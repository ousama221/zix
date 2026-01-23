const std = @import("std");
const constants = @import("constants.zig");
const Config = @import("config.zig").Config;
const Request = @import("request.zig").Request;
const ResponseMod = @import("response.zig");
const Response = ResponseMod.Response;
const TemplateEngine = @import("templates.zig").TemplateEngine;
const utils = @import("utils.zig");
const Store = @import("state.zig").Store;

pub const Context = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    request: *Request,
    response: *Response,
    template_engine: ?*TemplateEngine,
    params: std.StringHashMap([]const u8),
    state: Store,
    session: std.StringHashMap([]const u8),
    start_time: i64,
    aborted: bool,
    route_data: ?*const anyopaque,

    pub fn init(allocator: std.mem.Allocator, config: *const Config, request: *Request, response: *Response, template_engine: ?*TemplateEngine) Context {
        return Context{
            .allocator = allocator,
            .config = config,
            .request = request,
            .response = response,
            .template_engine = template_engine,
            .params = std.StringHashMap([]const u8).init(allocator),
            .state = Store.init(allocator),
            .session = std.StringHashMap([]const u8).init(allocator),
            .start_time = std.time.milliTimestamp(),
            .aborted = false,
            .route_data = null,
        };
    }

    pub fn deinit(self: *Context) void {
        var param_it = self.params.iterator();
        while (param_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.params.deinit();

        self.state.deinit();

        var session_it = self.session.iterator();
        while (session_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.session.deinit();
    }

    pub fn method(self: *const Context) constants.HttpMethod {
        return self.request.method;
    }

    pub fn path(self: *const Context) []const u8 {
        return self.request.path;
    }

    pub fn uri(self: *const Context) []const u8 {
        return self.request.uri;
    }

    pub fn param(self: *const Context, name: []const u8) ?[]const u8 {
        return self.params.get(name);
    }

    pub fn query(self: *Context, key: []const u8) !?[]const u8 {
        return try self.request.query(key);
    }

    pub fn queryInt(self: *Context, key: []const u8, comptime T: type) !?T {
        const value = try self.query(key) orelse return null;
        return utils.parseInt(T, value);
    }

    pub fn header(self: *const Context, name: []const u8) ?[]const u8 {
        return self.request.header(name);
    }

    pub fn headers(self: *const Context) *const std.StringHashMap([]const u8) {
        return &self.request.headers;
    }

    pub fn flash(self: *Context, message: []const u8) !void {
        try self.session.put("_flash", try self.allocator.dupe(u8, message));
    }

    pub fn getFlashedMessage(self: *Context) ?[]const u8 {
        if (self.session.get("_flash")) |msg| {
            _ = self.session.remove("_flash");
            return msg;
        }
        return null;
    }

    pub fn g(self: *Context) *std.StringHashMap([]const u8) {
        return &self.state;
    }

    pub fn cookie(self: *Context, name: []const u8) !?[]const u8 {
        return try self.request.cookie(name);
    }

    pub fn form(self: *Context, key: []const u8) !?[]const u8 {
        _ = self;
        _ = key;
        return null;
    }

    pub fn bodyRaw(self: *const Context) ?[]const u8 {
        return self.request.body;
    }

    pub fn bodyJson(self: *Context, comptime T: type) !std.json.Parsed(T) {
        const body = self.request.body orelse return error.NoBody;
        return std.json.parseFromSlice(T, self.allocator, body, .{ .ignore_unknown_fields = true });
    }

    pub fn setParam(self: *Context, name: []const u8, value: []const u8) !void {
        const key = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(key);
        const val = try self.allocator.dupe(u8, value);
        try self.params.put(key, val);
    }

    pub fn set(self: *Context, key: []const u8, value: []const u8) !void {
        const k = try self.allocator.dupe(u8, key);
        const v = try self.allocator.dupe(u8, value);
        try self.state.set(k, v);
    }

    pub fn get(self: *const Context, key: []const u8) ?[]const u8 {
        if (self.state.get([]const u8, key)) |ptr| {
            return ptr.*;
        }
        return null;
    }

    pub fn status(self: *Context, code: u16) *Context {
        _ = self.response.status(code);
        return self;
    }

    pub fn text(self: *Context, content: []const u8) !void {
        try self.response.text(content);
    }

    pub fn html(self: *Context, content: []const u8) !void {
        try self.response.html(content);
    }

    pub fn json(self: *Context, data: anytype) !void {
        try self.response.json(data);
    }

    pub fn jsonRaw(self: *Context, json_string: []const u8) !void {
        try self.response.jsonRaw(json_string);
    }

    pub fn xml(self: *Context, content: []const u8) !void {
        try self.response.xml(content);
    }

    pub fn render(self: *Context, name: []const u8, data: anytype) !void {
        if (self.template_engine) |te| {
            const content = te.render(name, data) catch |err| {
                switch (err) {
                    error.TemplateNotFound => {
                        _ = self.status(404);
                        try self.html("<html><body><h1>404 - Template Not Found</h1><p>The requested template could not be found.</p></body></html>");
                        return;
                    },
                    error.TemplateSyntaxError => {
                        _ = self.status(500);
                        try self.html("<html><body><h1>500 - Template Error</h1><p>There was an error parsing the template.</p></body></html>");
                        return;
                    },
                    else => return err,
                }
            };
            defer self.allocator.free(content);
            try self.html(content);
        } else {
            return error.TemplatesNotEnabled;
        }
    }

    pub fn redirect(self: *Context, location: []const u8, status_code: ?u16) !void {
        try self.response.redirect(location, status_code);
    }

    pub fn redirectPermanent(self: *Context, location: []const u8) !void {
        try self.response.redirectPermanent(location);
    }

    pub fn file(self: *Context, file_path: []const u8) !void {
        try self.response.file(file_path);
    }

    pub fn sendFile(self: *Context, file_path: []const u8, filename: ?[]const u8) !void {
        try self.response.sendFile(file_path, filename);
    }

    pub fn setHeader(self: *Context, name: []const u8, value: []const u8) !void {
        try self.response.setHeader(name, value);
    }

    pub fn setCookie(self: *Context, opts: struct {
        name: []const u8,
        value: []const u8,
        max_age: ?i64 = null,
        expires: ?i64 = null,
        path: ?[]const u8 = null,
        domain: ?[]const u8 = null,
        secure: bool = false,
        http_only: bool = true,
        same_site: ?[]const u8 = null,
    }) !void {
        try self.response.setCookie(.{
            .name = opts.name,
            .value = opts.value,
            .max_age = opts.max_age,
            .expires = opts.expires,
            .path = opts.path,
            .domain = opts.domain,
            .secure = opts.secure,
            .http_only = opts.http_only,
            .same_site = opts.same_site,
        });
    }

    pub fn deleteCookie(self: *Context, name: []const u8) !void {
        try self.response.deleteCookie(name);
    }

    pub fn noContent(self: *Context) !void {
        try self.response.noContent();
    }

    pub fn notFound(self: *Context) !void {
        try self.response.notFound();
    }

    pub fn methodNotAllowed(self: *Context) !void {
        try self.response.methodNotAllowed();
    }

    pub fn internalError(self: *Context) !void {
        try self.response.internalError();
    }

    pub fn unauthorized(self: *Context) !void {
        try self.response.unauthorized();
    }

    pub fn forbidden(self: *Context) !void {
        try self.response.forbidden();
    }

    pub fn badRequest(self: *Context, message: ?[]const u8) !void {
        try self.response.badRequest(message);
    }

    pub fn abort(self: *Context) void {
        self.aborted = true;
    }

    pub fn contentType(self: *const Context) ?[]const u8 {
        return self.request.getContentType();
    }

    pub fn isAborted(self: *const Context) bool {
        return self.aborted;
    }

    pub fn elapsed(self: *const Context) i64 {
        return std.time.milliTimestamp() - self.start_time;
    }

    pub fn isAjax(self: *const Context) bool {
        return self.request.isAjax();
    }

    pub fn acceptsJson(self: *const Context) bool {
        return self.request.acceptsMimeType("application/json");
    }

    pub fn acceptsHtml(self: *const Context) bool {
        return self.request.acceptsMimeType("text/html");
    }

    pub fn isPost(self: *const Context) bool {
        return self.request.method == .POST;
    }

    pub fn isGet(self: *const Context) bool {
        return self.request.method == .GET;
    }

    pub fn isPut(self: *const Context) bool {
        return self.request.method == .PUT;
    }

    pub fn isDelete(self: *const Context) bool {
        return self.request.method == .DELETE;
    }

    pub fn isPatch(self: *const Context) bool {
        return self.request.method == .PATCH;
    }

    pub fn remoteAddr(self: *const Context) ?[]const u8 {
        return self.request.remote_addr;
    }
};

test "Context.init creates valid context" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    const raw = "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();

    var response = Response.init(allocator, &config);
    defer response.deinit();

    var ctx = Context.init(allocator, &config, &request, &response, null);
    defer ctx.deinit();

    try testing.expectEqualStrings("/test", ctx.path());
    try testing.expectEqual(constants.HttpMethod.GET, ctx.method());
}

test "Context.setParam and param work correctly" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    const raw = "GET /users/123 HTTP/1.1\r\nHost: localhost\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();

    var response = Response.init(allocator, &config);
    defer response.deinit();

    var ctx = Context.init(allocator, &config, &request, &response, null);
    defer ctx.deinit();

    try ctx.setParam("id", "123");
    try testing.expectEqualStrings("123", ctx.param("id").?);
    try testing.expect(ctx.param("missing") == null);
}

test "Context.set and get work correctly" {
    const testing = std.testing;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var config = Config{};
    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);

    var response = Response.init(allocator, &config);

    var ctx = Context.init(allocator, &config, &request, &response, null);

    try ctx.set("user_id", "42");
    try testing.expectEqualStrings("42", ctx.get("user_id").?);
}

test "Context.status sets response status" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();

    var response = Response.init(allocator, &config);
    defer response.deinit();

    var ctx = Context.init(allocator, &config, &request, &response, null);
    defer ctx.deinit();

    _ = ctx.status(201);
    try testing.expectEqual(@as(u16, 201), response.status_code);
}

test "Context.abort stops processing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();

    var response = Response.init(allocator, &config);
    defer response.deinit();

    var ctx = Context.init(allocator, &config, &request, &response, null);
    defer ctx.deinit();

    try testing.expect(!ctx.isAborted());
    ctx.abort();
    try testing.expect(ctx.isAborted());
}

test "Context.isGet and other method helpers" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    const raw = "POST /api/data HTTP/1.1\r\nHost: localhost\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();

    var response = Response.init(allocator, &config);
    defer response.deinit();

    var ctx = Context.init(allocator, &config, &request, &response, null);
    defer ctx.deinit();

    try testing.expect(!ctx.isGet());
    try testing.expect(ctx.isPost());
    try testing.expect(!ctx.isPut());
}
