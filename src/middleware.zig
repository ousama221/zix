const std = @import("std");
const constants = @import("constants.zig");
const Config = @import("config.zig").Config;
const Context = @import("context.zig").Context;
const router_mod = @import("router.zig");
pub const NextFn = router_mod.NextFn;
const Logger = @import("logger.zig").Logger;
const utils = @import("utils.zig");
const security = @import("security.zig");

pub const MiddlewareFn = router_mod.MiddlewareFn;

pub fn logger(log: *Logger) MiddlewareFn {
    _ = log;
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            try next(ctx);
        }
    }.middleware;
}

pub fn createLogger() MiddlewareFn {
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            try next(ctx);
        }
    }.middleware;
}

pub fn securityHeaders() MiddlewareFn {
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            const sec_headers = security.SecurityHeaders.fromConfig(ctx.config);
            try sec_headers.apply(ctx);
            try next(ctx);
        }
    }.middleware;
}

pub fn cors() MiddlewareFn {
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            if (ctx.config.cors_enabled) {
                const cors_cfg = security.CorsConfig.fromConfig(ctx.config);
                try cors_cfg.apply(ctx);
                if (ctx.method() == .OPTIONS) {
                    try ctx.noContent();
                    return;
                }
            }
            try next(ctx);
        }
    }.middleware;
}

pub fn corsWithOptions(options: CorsOptions) MiddlewareFn {
    _ = options;
    return cors();
}

pub const CorsOptions = struct {
    origins: []const []const u8 = &.{"*"},
    methods: []const []const u8 = &.{ "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS" },
    allow_headers: []const []const u8 = &.{ "Content-Type", "Authorization" },
    expose_headers: []const []const u8 = &.{},
    supports_credentials: bool = false,
    max_age: u32 = 86400,
};

pub fn requestId() MiddlewareFn {
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            const id = ctx.header("X-Request-ID");
            if (id) |existing_id| {
                try ctx.setHeader("X-Request-ID", existing_id);
            } else {
                const random_id = try std.fmt.allocPrint(ctx.allocator, "{x}", .{std.crypto.random.int(u128)});
                defer ctx.allocator.free(random_id);
                try ctx.setHeader("X-Request-ID", random_id);
            }
            try next(ctx);
        }
    }.middleware;
}

pub fn recovery() MiddlewareFn {
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            next(ctx) catch |err| {
                if (ctx.config.debug_mode) {
                    const err_name = @errorName(err);
                    ctx.status(500).text(err_name) catch {};
                } else ctx.internalError() catch {};
            };
        }
    }.middleware;
}

pub fn noCache() MiddlewareFn {
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            try ctx.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
            try ctx.setHeader("Pragma", "no-cache");
            try ctx.setHeader("Expires", "0");
            try next(ctx);
        }
    }.middleware;
}

pub fn jsonMiddleware() MiddlewareFn {
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            try ctx.setHeader("Content-Type", constants.Response.json_content_type);
            try next(ctx);
        }
    }.middleware;
}

pub fn gzip() MiddlewareFn {
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            try next(ctx);
        }
    }.middleware;
}

pub fn rateLimit(requests_per_minute: u32) MiddlewareFn {
    _ = requests_per_minute;
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            try next(ctx);
        }
    }.middleware;
}

pub fn basicAuth(username: []const u8, password: []const u8) MiddlewareFn {
    _ = username;
    _ = password;
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            const auth = ctx.header("Authorization");
            if (auth == null) {
                try ctx.setHeader("WWW-Authenticate", "Basic realm=\"Restricted\"");
                try ctx.unauthorized();
                ctx.abort();
                return;
            }
            try next(ctx);
        }
    }.middleware;
}

pub fn bearerAuth() MiddlewareFn {
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            const auth = ctx.header("Authorization");
            if (auth == null) {
                try ctx.unauthorized();
                ctx.abort();
                return;
            }
            if (!std.mem.startsWith(u8, auth.?, "Bearer ")) {
                try ctx.unauthorized();
                ctx.abort();
                return;
            }
            try next(ctx);
        }
    }.middleware;
}

pub fn timeout(ms: u32) MiddlewareFn {
    _ = ms;
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            try next(ctx);
        }
    }.middleware;
}

pub fn csrf() MiddlewareFn {
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            if (ctx.config.csrf_enabled) {
                if (ctx.method() == .POST or ctx.method() == .PUT or ctx.method() == .DELETE) {
                    const token = ctx.header(ctx.config.csrf_header_name);
                    if (token == null) {
                        try ctx.forbidden();
                        ctx.abort();
                        return;
                    }
                }
            }
            try next(ctx);
        }
    }.middleware;
}

pub fn session() MiddlewareFn {
    return struct {
        fn middleware(ctx: *Context, next: NextFn) !void {
            if (ctx.config.session_enabled) {
                if (try ctx.request.cookie(ctx.config.session_cookie_name)) |cookie_val| {
                    if (ctx.config.secret_key) |secret| {
                        if (try utils.verify(ctx.allocator, cookie_val, secret)) |payload| {
                            defer ctx.allocator.free(payload);
                            const parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, payload, .{}) catch |err| blk: {
                                if (ctx.config.debug_mode) std.debug.print("Session parse error: {any}\n", .{err});
                                break :blk null;
                            };

                            if (parsed) |p| {
                                defer p.deinit();
                                if (p.value == .object) {
                                    var it = p.value.object.iterator();
                                    while (it.next()) |entry| {
                                        if (entry.value_ptr.* == .string) {
                                            const key = try ctx.allocator.dupe(u8, entry.key_ptr.*);
                                            const val = try ctx.allocator.dupe(u8, entry.value_ptr.string);
                                            try ctx.session.put(key, val);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            try next(ctx);

            if (ctx.config.session_enabled and ctx.session.count() > 0) {
                if (ctx.config.secret_key) |secret| {
                    var json_map = std.StringArrayHashMap([]const u8).init(ctx.allocator);
                    defer json_map.deinit();

                    var it = ctx.session.iterator();
                    while (it.next()) |entry| {
                        try json_map.put(entry.key_ptr.*, entry.value_ptr.*);
                    }

                    const json_str = try std.json.Stringify.valueAlloc(ctx.allocator, json_map, .{});
                    defer ctx.allocator.free(json_str);

                    const signed = try utils.sign(ctx.allocator, json_str, secret);
                    defer ctx.allocator.free(signed);

                    try ctx.response.setCookie(.{ .name = ctx.config.session_cookie_name, .value = signed, .max_age = ctx.config.session_max_age, .http_only = ctx.config.session_http_only, .secure = ctx.config.session_secure, .path = "/" });
                }
            }
        }
    }.middleware;
}

pub const MiddlewareChain = struct {
    middlewares: std.ArrayList(MiddlewareFn),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MiddlewareChain {
        return MiddlewareChain{ .middlewares = .empty, .allocator = allocator };
    }

    pub fn deinit(self: *MiddlewareChain) void {
        self.middlewares.deinit(self.allocator);
    }

    pub fn use(self: *MiddlewareChain, mw: MiddlewareFn) !void {
        try self.middlewares.append(self.allocator, mw);
    }

    pub fn execute(self: *const MiddlewareChain, ctx: *Context, handler: router_mod.HandlerFn) !void {
        if (self.middlewares.items.len == 0) {
            try handler(ctx);
            return;
        }
        const middlewares = self.middlewares.items;
        if (middlewares.len > 0) {
            const final_next: NextFn = struct {
                fn finalHandler(_: *Context) !void {}
            }.finalHandler;
            try middlewares[0](ctx, final_next);
        }
        if (!ctx.isAborted()) try handler(ctx);
    }
};

pub fn chain(allocator: std.mem.Allocator, middlewares: []const MiddlewareFn) !MiddlewareChain {
    var mw_chain = MiddlewareChain.init(allocator);
    for (middlewares) |mw| try mw_chain.use(mw);
    return mw_chain;
}

test "securityHeaders adds headers" {
    const allocator = std.testing.allocator;
    const Request = @import("request.zig").Request;
    const Response = @import("response.zig").Response;
    var config = Config{ .enable_security_headers = true };
    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();
    var response = Response.init(allocator, &config);
    defer response.deinit();
    var ctx = Context.init(allocator, &config, &request, &response, null);
    defer ctx.deinit();
    const mw = securityHeaders();
    const noop: NextFn = struct {
        fn n(_: *Context) !void {}
    }.n;
    try mw(&ctx, noop);
    var found = false;
    for (response.headers.items) |h| {
        if (std.mem.eql(u8, h.name, "X-Content-Type-Options")) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "cors handles OPTIONS" {
    const allocator = std.testing.allocator;
    const Request = @import("request.zig").Request;
    const Response = @import("response.zig").Response;
    var config = Config{ .cors_enabled = true };
    const raw = "OPTIONS /api HTTP/1.1\r\nHost: localhost\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();
    var response = Response.init(allocator, &config);
    defer response.deinit();
    var ctx = Context.init(allocator, &config, &request, &response, null);
    defer ctx.deinit();
    const mw = cors();
    const noop: NextFn = struct {
        fn n(_: *Context) !void {}
    }.n;
    try mw(&ctx, noop);
    try std.testing.expectEqual(@as(u16, 204), response.status_code);
}

test "noCache adds cache headers" {
    const allocator = std.testing.allocator;
    const Request = @import("request.zig").Request;
    const Response = @import("response.zig").Response;
    var config = Config{};
    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();
    var response = Response.init(allocator, &config);
    defer response.deinit();
    var ctx = Context.init(allocator, &config, &request, &response, null);
    defer ctx.deinit();
    const mw = noCache();
    const noop: NextFn = struct {
        fn n(_: *Context) !void {}
    }.n;
    try mw(&ctx, noop);
    var found = false;
    for (response.headers.items) |h| {
        if (std.mem.eql(u8, h.name, "Cache-Control")) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "recovery catches errors" {
    const allocator = std.testing.allocator;
    const Request = @import("request.zig").Request;
    const Response = @import("response.zig").Response;
    var config = Config{ .debug_mode = true };
    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();
    var response = Response.init(allocator, &config);
    defer response.deinit();
    var ctx = Context.init(allocator, &config, &request, &response, null);
    defer ctx.deinit();
    const mw = recovery();
    const failing: NextFn = struct {
        fn n(_: *Context) !void {
            return error.TestError;
        }
    }.n;
    try mw(&ctx, failing);
    try std.testing.expectEqual(@as(u16, 500), response.status_code);
}

test "MiddlewareChain executes" {
    const allocator = std.testing.allocator;
    var mw_chain = MiddlewareChain.init(allocator);
    defer mw_chain.deinit();
    const mw1: MiddlewareFn = struct {
        fn m(ctx: *Context, next: NextFn) !void {
            try ctx.set("step1", "done");
            try next(ctx);
        }
    }.m;
    try mw_chain.use(mw1);
    try std.testing.expectEqual(@as(usize, 1), mw_chain.middlewares.items.len);
}
