const std = @import("std");
const builtin = @import("builtin");
const constants = @import("constants.zig");
const Config = @import("config.zig").Config;
const Context = @import("context.zig").Context;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Router = @import("router.zig").Router;
const Logger = @import("logger.zig").Logger;
const middleware_mod = @import("middleware.zig");
const TemplateEngine = @import("templates.zig").TemplateEngine;

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    router: *Router,
    logger: *Logger,
    template_engine: ?*TemplateEngine,
    listener: ?std.net.Server,
    running: bool,
    shutdown_requested: std.atomic.Value(bool),
    active_connections: std.atomic.Value(u32),
    global_middleware: std.ArrayList(middleware_mod.MiddlewareFn),
    request_count: std.atomic.Value(u64),
    error_count: std.atomic.Value(u64),

    pub fn init(allocator: std.mem.Allocator, config: *const Config, router: *Router, logger: *Logger, template_engine: ?*TemplateEngine) Server {
        return Server{
            .allocator = allocator,
            .config = config,
            .router = router,
            .logger = logger,
            .template_engine = template_engine,
            .listener = null,
            .running = false,
            .shutdown_requested = std.atomic.Value(bool).init(false),
            .active_connections = std.atomic.Value(u32).init(0),
            .global_middleware = .empty,
            .request_count = std.atomic.Value(u64).init(0),
            .error_count = std.atomic.Value(u64).init(0),
        };
    }

    pub fn deinit(self: *Server) void {
        self.stop();
        self.global_middleware.deinit(self.allocator);
    }

    pub fn use(self: *Server, mw: middleware_mod.MiddlewareFn) !void {
        try self.global_middleware.append(self.allocator, mw);
    }

    pub fn start(self: *Server) !void {
        const address = std.net.Address.parseIp4(self.config.address, self.config.port) catch {
            self.logger.err("Failed to parse address: {s}:{d}", .{ self.config.address, self.config.port });
            return error.BindFailed;
        };
        const listen_options = std.net.Address.ListenOptions{ .reuse_address = true };
        self.listener = address.listen(listen_options) catch {
            self.logger.err("Failed to bind to {s}:{d}", .{ self.config.address, self.config.port });
            return error.BindFailed;
        };
        self.running = true;
        self.shutdown_requested.store(false, .release);
        self.logger.serverStart(self.config.address, self.config.port);
        while (!self.shutdown_requested.load(.acquire)) {
            if (self.listener) |*listener| {
                const connection = listener.accept() catch |err| {
                    if (self.shutdown_requested.load(.acquire)) break;
                    self.logger.err("Accept error: {any}", .{err});
                    continue;
                };
                _ = self.active_connections.fetchAdd(1, .monotonic);
                const thread = std.Thread.spawn(.{}, handleConnectionWrapper, .{ self, connection }) catch |err| {
                    self.logger.err("Thread spawn error: {any}", .{err});
                    connection.stream.close();
                    _ = self.active_connections.fetchSub(1, .monotonic);
                    continue;
                };
                thread.detach();
            } else break;
        }
        self.running = false;
        self.logger.serverStop();
    }

    pub fn stop(self: *Server) void {
        self.shutdown_requested.store(true, .release);
        if (self.listener) |*listener| {
            listener.stream.close();
            self.listener = null;
        }
        const shutdown_start = std.time.milliTimestamp();
        const timeout = @as(i64, @intCast(self.config.shutdown_timeout_ms));
        while (self.active_connections.load(.acquire) > 0) {
            if (std.time.milliTimestamp() - shutdown_start > timeout) {
                self.logger.warn("Shutdown timeout", .{});
                break;
            }
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
        self.running = false;
    }

    pub fn isRunning(self: *const Server) bool {
        return self.running and !self.shutdown_requested.load(.acquire);
    }

    pub fn getStats(self: *const Server) ServerStats {
        return ServerStats{
            .requests = self.request_count.load(.acquire),
            .errors = self.error_count.load(.acquire),
            .active_connections = self.active_connections.load(.acquire),
        };
    }

    pub const ServerStats = struct {
        requests: u64,
        errors: u64,
        active_connections: u32,
    };

    fn handleConnectionWrapper(self: *Server, connection: std.net.Server.Connection) void {
        self.handleConnection(connection) catch |err| {
            self.logger.err("Connection error: {any}", .{err});
            _ = self.error_count.fetchAdd(1, .monotonic);
        };
    }

    fn handleConnection(self: *Server, connection: std.net.Server.Connection) !void {
        defer {
            connection.stream.close();
            _ = self.active_connections.fetchSub(1, .monotonic);
        }
        var read_buf: [constants.Defaults.buffer_size]u8 = undefined;
        while (!self.shutdown_requested.load(.acquire)) {
            const bytes_read = if (builtin.os.tag == .windows) blk: {
                const res = std.os.windows.ws2_32.recv(connection.stream.handle, &read_buf, @intCast(read_buf.len), 0);
                if (res == std.os.windows.ws2_32.SOCKET_ERROR) {
                    const err = std.os.windows.ws2_32.WSAGetLastError();
                    if (err == .WSAECONNRESET or err == .WSAECONNABORTED or err == .WSAETIMEDOUT) return;
                    return error.Unexpected;
                }
                break :blk @as(usize, @intCast(res));
            } else try connection.stream.read(&read_buf);
            if (bytes_read == 0) return;
            const raw_request = read_buf[0..bytes_read];
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();
            var request = Request.parse(allocator, self.config, raw_request) catch |err| {
                if (err != error.EndOfStream) {
                    self.logger.debug("Parse error: {any}", .{err});
                    self.sendErrorResponse(connection.stream, 400, "Bad Request") catch {};
                }
                return;
            };
            var response = Response.init(allocator, self.config);
            var ctx = Context.init(allocator, self.config, &request, &response, self.template_engine);
            self.processRequest(&ctx) catch |err| {
                self.logger.err("Request error: {any}", .{err});
                ctx.internalError() catch {};
                _ = self.error_count.fetchAdd(1, .monotonic);
            };
            const response_data = response.build() catch |err| {
                self.logger.err("Build error: {any}", .{err});
                self.sendErrorResponse(connection.stream, 500, "Internal Server Error") catch {};
                return;
            };
            _ = try connection.stream.writeAll(response_data);
            _ = self.request_count.fetchAdd(1, .monotonic);
            const duration = ctx.elapsed();
            self.logger.request(request.method.toString(), request.path, response.status_code, @intCast(duration));
            if (!request.is_keep_alive) break;
        }
    }

    fn processRequest(self: *Server, ctx: *Context) !void {
        for (self.global_middleware.items) |mw| {
            const noop: middleware_mod.NextFn = struct {
                fn n(_: *Context) !void {}
            }.n;
            try mw(ctx, noop);
            if (ctx.isAborted()) return;
        }
        for (self.router.global_middleware.items) |mw| {
            const noop: middleware_mod.NextFn = struct {
                fn n(_: *Context) !void {}
            }.n;
            try mw(ctx, noop);
            if (ctx.isAborted()) return;
        }
        const match_result = self.router.match(ctx.method(), ctx.path());
        if (match_result) |result| {
            ctx.route_data = result.route.data;
            for (result.params) |param| try ctx.setParam(param.name, param.value);
            for (result.route.middleware) |mw| {
                const noop: middleware_mod.NextFn = struct {
                    fn n(_: *Context) !void {}
                }.n;
                try mw(ctx, noop);
                if (ctx.isAborted()) return;
            }
            try result.route.handler(ctx);
        } else {
            if (self.router.hasMethodMatch(ctx.path())) {
                if (self.router.not_found_handler) |handler| try handler(ctx) else try ctx.methodNotAllowed();
            } else {
                if (self.config.spa_mode) {
                    const ext = std.fs.path.extension(ctx.path());
                    if (ext.len == 0) {
                        if (self.template_engine) |_| {
                            ctx.render(self.config.spa_index, .{}) catch |err| {
                                self.logger.debug("SPA fallback failed: {any}", .{err});
                                if (self.router.not_found_handler) |handler| try handler(ctx) else try ctx.notFound();
                            };
                            return;
                        }
                    }
                }
                if (self.router.not_found_handler) |handler| try handler(ctx) else try ctx.notFound();
            }
        }
    }

    fn sendErrorResponse(self: *Server, stream: std.net.Stream, status_code: u16, message: []const u8) !void {
        _ = self;
        const phrase = constants.HttpStatus.getPhrase(status_code);
        var buf: [512]u8 = undefined;
        const response = std.fmt.bufPrint(&buf, "HTTP/1.1 {d} {s}\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: {d}\r\n\r\n{s}", .{ status_code, phrase, message.len, message }) catch return;
        _ = stream.writeAll(response) catch return;
    }
};

pub fn createServer(allocator: std.mem.Allocator, config: *const Config, router: *Router, logger: *Logger) Server {
    return Server.init(allocator, config, router, logger, null);
}

pub const WsgiApp = struct {
    app: *const fn (environ: *std.StringHashMap([]const u8), startResponse: *const fn ([]const u8, []const Header) void) []const u8,

    pub const Header = struct {
        name: []const u8,
        value: []const u8,
    };

    pub fn call(self: *WsgiApp, environ: *std.StringHashMap([]const u8), startResponse: *const fn ([]const u8, []const Header) void) []const u8 {
        return self.app(environ, startResponse);
    }
};

test "Server.init creates server" {
    const allocator = std.testing.allocator;
    var config = Config{};
    var router = Router.init(allocator, &config);
    defer router.deinit();
    var logger = Logger.init(allocator, &config);
    defer logger.deinit();
    var server = Server.init(allocator, &config, &router, &logger, null);
    defer server.deinit();
    try std.testing.expect(!server.running);
}

test "Server.getStats returns stats" {
    const allocator = std.testing.allocator;
    var config = Config{};
    var router = Router.init(allocator, &config);
    defer router.deinit();
    var logger = Logger.init(allocator, &config);
    defer logger.deinit();
    var server = Server.init(allocator, &config, &router, &logger, null);
    defer server.deinit();
    const stats = server.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.requests);
}
