const std = @import("std");
const constants = @import("constants.zig");
const Config = @import("config.zig").Config;
const Context = @import("context.zig").Context;

pub const HandlerFn = *const fn (*Context) anyerror!void;

pub const Route = struct {
    method: constants.HttpMethod,
    pattern: []const u8,
    handler: HandlerFn,
    middleware: []const MiddlewareFn,
    segments: []const Segment,
    param_count: usize,
    is_static: bool,
    data: ?*const anyopaque = null,

    pub const Segment = union(enum) {
        literal: []const u8,
        param: []const u8,
        wildcard: void,
        int: []const u8,
        float: []const u8,
        uuid: []const u8,
        path: []const u8,
    };
};

pub const MiddlewareFn = *const fn (*Context, NextFn) anyerror!void;
pub const NextFn = *const fn (*Context) anyerror!void;

pub const Router = struct {
    allocator: std.mem.Allocator,
    routes: std.ArrayListUnmanaged(Route),
    global_middleware: std.ArrayListUnmanaged(MiddlewareFn),
    not_found_handler: ?HandlerFn,
    error_handler: ?*const fn (*Context, anyerror) void,

    pub fn init(allocator: std.mem.Allocator, config: *const Config) Router {
        _ = config;
        return Router{
            .allocator = allocator,
            .routes = .empty,
            .global_middleware = .empty,
            .not_found_handler = null,
            .error_handler = null,
        };
    }

    pub fn deinit(self: *Router) void {
        for (self.routes.items) |route| {
            self.allocator.free(route.pattern);
            self.allocator.free(route.segments);
            if (route.middleware.len > 0) {
                self.allocator.free(route.middleware);
            }
        }
        self.routes.deinit(self.allocator);
        self.global_middleware.deinit(self.allocator);
    }

    pub fn addRoute(self: *Router, method: constants.HttpMethod, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRouteWithMiddleware(method, pattern, handler, &[_]MiddlewareFn{});
    }

    pub fn addRouteWithMiddleware(self: *Router, method: constants.HttpMethod, pattern: []const u8, handler: HandlerFn, middleware: []const MiddlewareFn) !void {
        try self.addRouteWithMiddlewareAndData(method, pattern, handler, middleware, null);
    }

    pub fn addRouteWithData(self: *Router, method: constants.HttpMethod, pattern: []const u8, handler: HandlerFn, data: *const anyopaque) !void {
        try self.addRouteWithMiddlewareAndData(method, pattern, handler, &[_]MiddlewareFn{}, data);
    }

    pub fn addRouteWithMiddlewareAndData(self: *Router, method: constants.HttpMethod, pattern: []const u8, handler: HandlerFn, middleware: []const MiddlewareFn, data: ?*const anyopaque) !void {
        for (self.routes.items) |route| {
            if (route.method == method and std.mem.eql(u8, route.pattern, pattern)) {
                return error.DuplicateRoute;
            }
        }

        const pattern_copy = try self.allocator.dupe(u8, pattern);
        errdefer self.allocator.free(pattern_copy);

        const segments = try self.parsePattern(pattern_copy);
        errdefer self.allocator.free(segments);

        const middleware_copy = if (middleware.len > 0)
            try self.allocator.dupe(MiddlewareFn, middleware)
        else
            &[_]MiddlewareFn{};
        errdefer if (middleware_copy.len > 0) self.allocator.free(middleware_copy);

        var param_count: usize = 0;
        var is_static = true;
        for (segments) |seg| {
            switch (seg) {
                .int, .float, .uuid, .path => |name| {
                    _ = name;
                    param_count += 1;
                    is_static = false;
                },
                .param => {
                    param_count += 1;
                    is_static = false;
                },
                .wildcard => {
                    is_static = false;
                },
                .literal => {},
            }
        }

        try self.routes.append(self.allocator, Route{
            .method = method,
            .pattern = pattern_copy,
            .handler = handler,
            .middleware = middleware_copy,
            .segments = segments,
            .param_count = param_count,
            .is_static = is_static,
            .data = data,
        });
    }

    fn parsePattern(self: *Router, pattern: []const u8) ![]Route.Segment {
        var segments = std.ArrayListUnmanaged(Route.Segment){};
        errdefer segments.deinit(self.allocator);

        const trimmed = std.mem.trim(u8, pattern, "/");
        if (trimmed.len == 0) {
            return segments.toOwnedSlice(self.allocator);
        }

        var it = std.mem.splitScalar(u8, trimmed, '/');
        while (it.next()) |part| {
            if (part.len == 0) continue;

            if (part[0] == constants.Router.param_prefix) {
                try segments.append(self.allocator, .{ .param = part[1..] });
            } else if (part[0] == constants.Router.wildcard) {
                try segments.append(self.allocator, .{ .wildcard = {} });
            } else if (part.len > 2 and part[0] == '<' and part[part.len - 1] == '>') {
                const inner = part[1 .. part.len - 1];
                if (std.mem.indexOf(u8, inner, ":")) |colon_pos| {
                    const type_str = inner[0..colon_pos];
                    const name = inner[colon_pos + 1 ..];
                    if (std.mem.eql(u8, type_str, "int")) {
                        try segments.append(self.allocator, .{ .int = name });
                    } else if (std.mem.eql(u8, type_str, "float")) {
                        try segments.append(self.allocator, .{ .float = name });
                    } else if (std.mem.eql(u8, type_str, "uuid")) {
                        try segments.append(self.allocator, .{ .uuid = name });
                    } else if (std.mem.eql(u8, type_str, "path")) {
                        try segments.append(self.allocator, .{ .path = name });
                    } else {
                        try segments.append(self.allocator, .{ .param = inner });
                    }
                } else {
                    try segments.append(self.allocator, .{ .param = inner });
                }
            } else {
                try segments.append(self.allocator, .{ .literal = part });
            }
        }

        return segments.toOwnedSlice(self.allocator);
    }

    pub fn get(self: *Router, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.GET, pattern, handler);
    }

    pub fn post(self: *Router, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.POST, pattern, handler);
    }

    pub fn put(self: *Router, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.PUT, pattern, handler);
    }

    pub fn patch(self: *Router, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.PATCH, pattern, handler);
    }

    pub fn delete(self: *Router, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.DELETE, pattern, handler);
    }

    pub fn head(self: *Router, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.HEAD, pattern, handler);
    }

    pub fn options(self: *Router, pattern: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.OPTIONS, pattern, handler);
    }

    pub fn any(self: *Router, pattern: []const u8, handler: HandlerFn) !void {
        const methods = [_]constants.HttpMethod{ .GET, .POST, .PUT, .PATCH, .DELETE, .HEAD, .OPTIONS };
        for (methods) |method| {
            try self.addRoute(method, pattern, handler);
        }
    }

    pub fn use(self: *Router, middleware: MiddlewareFn) !void {
        try self.global_middleware.append(self.allocator, middleware);
    }

    pub fn setNotFoundHandler(self: *Router, handler: HandlerFn) void {
        self.not_found_handler = handler;
    }

    pub fn setErrorHandler(self: *Router, handler: *const fn (*Context, anyerror) void) void {
        self.error_handler = handler;
    }

    pub fn match(self: *Router, method: constants.HttpMethod, path: []const u8) ?MatchResult {
        const trimmed_path = std.mem.trim(u8, path, "/");

        for (self.routes.items) |route| {
            if (route.method != method) continue;

            if (self.matchRoute(route, trimmed_path)) |params| {
                return MatchResult{
                    .route = route,
                    .params = params,
                };
            }
        }

        for (self.routes.items) |route| {
            if (route.method == method) continue;

            if (self.matchRoute(route, trimmed_path) != null) {
                return null;
            }
        }

        return null;
    }

    pub fn hasMethodMatch(self: *Router, path: []const u8) bool {
        const trimmed_path = std.mem.trim(u8, path, "/");

        for (self.routes.items) |route| {
            if (self.matchRoute(route, trimmed_path) != null) {
                return true;
            }
        }
        return false;
    }

    fn matchRoute(self: *Router, route: Route, path: []const u8) ?[]ParamPair {
        _ = self;
        var params: [constants.Router.max_params]ParamPair = undefined;
        var param_count: usize = 0;

        var path_it = std.mem.splitScalar(u8, path, '/');
        var segment_idx: usize = 0;

        while (path_it.next()) |path_part| {
            if (path_part.len == 0) continue;

            if (segment_idx >= route.segments.len) {
                return null;
            }

            const segment = route.segments[segment_idx];
            switch (segment) {
                .literal => |lit| {
                    if (!std.mem.eql(u8, path_part, lit)) {
                        return null;
                    }
                },
                .param => |name| {
                    if (param_count >= constants.Router.max_params) return null;
                    params[param_count] = ParamPair{ .name = name, .value = path_part };
                    param_count += 1;
                },
                .int => |name| {
                    if (std.fmt.parseInt(i64, path_part, 10)) |_| {
                        if (param_count >= constants.Router.max_params) return null;
                        params[param_count] = ParamPair{ .name = name, .value = path_part };
                        param_count += 1;
                    } else |_| return null;
                },
                .float => |name| {
                    if (std.fmt.parseFloat(f64, path_part)) |_| {
                        if (param_count >= constants.Router.max_params) return null;
                        params[param_count] = ParamPair{ .name = name, .value = path_part };
                        param_count += 1;
                    } else |_| return null;
                },
                .uuid => |name| {
                    if (path_part.len == 36 and std.mem.indexOf(u8, path_part, "-") != null) {
                        if (param_count >= constants.Router.max_params) return null;
                        params[param_count] = ParamPair{ .name = name, .value = path_part };
                        param_count += 1;
                    } else return null;
                },
                .path => |name| {
                    if (param_count >= constants.Router.max_params) return null;
                    const start = @intFromPtr(path_part.ptr) - @intFromPtr(path.ptr);
                    const rest = path[start..];
                    params[param_count] = ParamPair{ .name = name, .value = rest };
                    param_count += 1;
                    return params[0..param_count];
                },
                .wildcard => {
                    return params[0..param_count];
                },
            }
            segment_idx += 1;
        }

        if (segment_idx != route.segments.len) {
            return null;
        }

        return params[0..param_count];
    }

    pub const MatchResult = struct {
        route: Route,
        params: []ParamPair,
    };

    pub const ParamPair = struct {
        name: []const u8,
        value: []const u8,
    };

    pub fn group(self: *Router, prefix: []const u8) RouteGroup {
        return RouteGroup{ .router = self, .prefix = prefix };
    }

    pub fn notFound(self: *Router, handler: HandlerFn) void {
        self.not_found_handler = handler;
    }

    pub fn methodNotAllowed(self: *Router, handler: HandlerFn) void {
        self.not_found_handler = handler;
    }

    pub fn printRoutes(self: *Router) void {
        std.debug.print("Registered Routes (count={d}):\n", .{self.routes.items.len});
    }
};

pub const RouteGroup = struct {
    router: *Router,
    prefix: []const u8,

    pub fn get(self: *RouteGroup, pattern: []const u8, handler: HandlerFn) !void {
        var buf: [512]u8 = undefined;
        const full = std.fmt.bufPrint(&buf, "{s}{s}", .{ self.prefix, pattern }) catch return error.PathTooLong;
        try self.router.get(full, handler);
    }

    pub fn post(self: *RouteGroup, pattern: []const u8, handler: HandlerFn) !void {
        var buf: [512]u8 = undefined;
        const full = std.fmt.bufPrint(&buf, "{s}{s}", .{ self.prefix, pattern }) catch return error.PathTooLong;
        try self.router.post(full, handler);
    }

    pub fn put(self: *RouteGroup, pattern: []const u8, handler: HandlerFn) !void {
        var buf: [512]u8 = undefined;
        const full = std.fmt.bufPrint(&buf, "{s}{s}", .{ self.prefix, pattern }) catch return error.PathTooLong;
        try self.router.put(full, handler);
    }

    pub fn delete(self: *RouteGroup, pattern: []const u8, handler: HandlerFn) !void {
        var buf: [512]u8 = undefined;
        const full = std.fmt.bufPrint(&buf, "{s}{s}", .{ self.prefix, pattern }) catch return error.PathTooLong;
        try self.router.delete(full, handler);
    }
};

pub fn createRouter(allocator: std.mem.Allocator, config: *const Config) Router {
    return Router.init(allocator, config);
}

test "Router.init creates empty router" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var router = Router.init(allocator, &config);
    defer router.deinit();

    try testing.expectEqual(@as(usize, 0), router.routes.items.len);
}

test "Router.get adds GET route" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var router = Router.init(allocator, &config);
    defer router.deinit();

    const handler = struct {
        fn handle(_: *Context) !void {}
    }.handle;

    try router.get("/hello", handler);

    try testing.expectEqual(@as(usize, 1), router.routes.items.len);
    try testing.expectEqual(constants.HttpMethod.GET, router.routes.items[0].method);
}

test "Router.match finds exact routes" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var router = Router.init(allocator, &config);
    defer router.deinit();

    const handler = struct {
        fn handle(_: *Context) !void {}
    }.handle;

    try router.get("/hello", handler);
    try router.get("/world", handler);

    const result1 = router.match(.GET, "/hello");
    try testing.expect(result1 != null);
    try testing.expectEqualStrings("/hello", result1.?.route.pattern);

    const result2 = router.match(.GET, "/world");
    try testing.expect(result2 != null);

    const result3 = router.match(.GET, "/missing");
    try testing.expect(result3 == null);
}

test "Router.match handles parameterized routes" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var router = Router.init(allocator, &config);
    defer router.deinit();

    const handler = struct {
        fn handle(_: *Context) !void {}
    }.handle;

    try router.get("/users/:id", handler);
    try router.get("/users/:id/posts/:post_id", handler);

    const result1 = router.match(.GET, "/users/123");
    try testing.expect(result1 != null);
    try testing.expectEqual(@as(usize, 1), result1.?.params.len);
    try testing.expectEqualStrings("id", result1.?.params[0].name);
    try testing.expectEqualStrings("123", result1.?.params[0].value);

    const result2 = router.match(.GET, "/users/456/posts/789");
    try testing.expect(result2 != null);
    try testing.expectEqual(@as(usize, 2), result2.?.params.len);
}

test "Router.match respects method" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var router = Router.init(allocator, &config);
    defer router.deinit();

    const handler = struct {
        fn handle(_: *Context) !void {}
    }.handle;

    try router.get("/resource", handler);
    try router.post("/resource", handler);

    const get_result = router.match(.GET, "/resource");
    try testing.expect(get_result != null);
    try testing.expectEqual(constants.HttpMethod.GET, get_result.?.route.method);

    const post_result = router.match(.POST, "/resource");
    try testing.expect(post_result != null);
    try testing.expectEqual(constants.HttpMethod.POST, post_result.?.route.method);

    const put_result = router.match(.PUT, "/resource");
    try testing.expect(put_result == null);
}

test "Router.use adds global middleware" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var router = Router.init(allocator, &config);
    defer router.deinit();

    const mw = struct {
        fn middleware(_: *Context, _: NextFn) !void {}
    }.middleware;

    try router.use(mw);
    try testing.expectEqual(@as(usize, 1), router.global_middleware.items.len);
}

test "Router.any registers all methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var router = Router.init(allocator, &config);
    defer router.deinit();

    const handler = struct {
        fn handle(_: *Context) !void {}
    }.handle;

    try router.any("/api", handler);

    try testing.expectEqual(@as(usize, 7), router.routes.items.len);
}

test "Router.hasMethodMatch detects path existence" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var router = Router.init(allocator, &config);
    defer router.deinit();

    const handler = struct {
        fn handle(_: *Context) !void {}
    }.handle;

    try router.get("/exists", handler);

    try testing.expect(router.hasMethodMatch("/exists"));
    try testing.expect(!router.hasMethodMatch("/not-exists"));
}

test "Router matches typed params" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var router = Router.init(allocator, &config);
    defer router.deinit();

    const handler = struct {
        fn handle(_: *Context) !void {}
    }.handle;

    try router.get("/int/<int:id>", handler);
    try router.get("/float/<float:val>", handler);
    try router.get("/uuid/<uuid:uid>", handler);

    const r1 = router.match(.GET, "/int/123");
    try testing.expect(r1 != null);
    try testing.expectEqualStrings("123", r1.?.params[0].value);

    const r2 = router.match(.GET, "/int/abc");
    try testing.expect(r2 == null);

    const r3 = router.match(.GET, "/float/3.14");
    try testing.expect(r3 != null);

    const r4 = router.match(.GET, "/float/abc");
    try testing.expect(r4 == null);
}
