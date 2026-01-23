const std = @import("std");
const Config = @import("config.zig").Config;
const ConfigBuilder = @import("config.zig").ConfigBuilder;
const router_mod = @import("router.zig");
const Router = router_mod.Router;
const Server = @import("server.zig").Server;
const Logger = @import("logger.zig").Logger;
const Context = @import("context.zig").Context;
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const TemplateEngine = @import("templates.zig").TemplateEngine;
const static_mod = @import("static.zig");
const StaticFileServer = static_mod.StaticFileServer;
const middleware_mod = @import("middleware.zig");
const constants = @import("constants.zig");

pub const AppBlueprint = struct {
    name: []const u8,
    url_prefix: []const u8,
    routes: std.ArrayListUnmanaged(router_mod.Route),
};

pub const BeforeRequestFn = *const fn (*Context) anyerror!void;
pub const AfterRequestFn = *const fn (*Context, *Response) anyerror!*Response;
pub const TeardownFn = *const fn (?anyerror) void;
pub const ErrorHandlerFn = *const fn (*Context, anyerror) anyerror!void;

pub const App = struct {
    allocator: std.mem.Allocator,
    config: Config,
    router: Router,
    logger: Logger,
    server: ?Server,
    template_engine: ?TemplateEngine,
    static_server: ?StaticFileServer,
    initialized: bool,
    debug: bool,
    secret_key: ?[]const u8,
    blueprints: std.ArrayListUnmanaged(AppBlueprint),
    before_request_handlers: std.ArrayListUnmanaged(BeforeRequestFn),
    after_request_handlers: std.ArrayListUnmanaged(AfterRequestFn),
    teardown_handlers: std.ArrayListUnmanaged(TeardownFn),
    error_handlers: std.StringHashMapUnmanaged(ErrorHandlerFn),
    url_map: std.StringHashMapUnmanaged([]const u8),
    extensions: std.StringHashMapUnmanaged(*anyopaque),

    file_watcher: ?*@import("watcher.zig").FileWatcher,
    plugin_manager: ?*@import("plugin.zig").PluginManager,
    static_servers: std.ArrayListUnmanaged(*StaticFileServer),
    arena: std.heap.ArenaAllocator,

    pub fn init(self: *App, allocator: std.mem.Allocator, cfg: Config) !void {
        self.allocator = allocator;
        self.arena = std.heap.ArenaAllocator.init(allocator);
        self.config = cfg;
        self.server = null;
        self.template_engine = null;
        self.static_server = null;
        self.initialized = false;
        self.debug = cfg.debug_mode;
        self.secret_key = cfg.secret_key;
        self.blueprints = .empty;
        self.before_request_handlers = .empty;
        self.after_request_handlers = .empty;
        self.teardown_handlers = .empty;
        self.error_handlers = .empty;
        self.url_map = .empty;
        self.extensions = .empty;
        self.router = Router.init(allocator, &self.config);
        self.logger = Logger.init(allocator, &self.config);
        self.static_servers = .empty;

        if (cfg.debug_mode) {
            const watcher = try allocator.create(@import("watcher.zig").FileWatcher);

            const Callback = struct {
                fn reload(_: []const u8) void {
                    std.debug.print("\nFile changed! Server reload recommended.\n", .{});
                }
            };

            watcher.* = @import("watcher.zig").FileWatcher.init(allocator, Callback.reload);
            try watcher.addDirectory(constants.Defaults.template_dir);
            try watcher.addDirectory(constants.Defaults.static_dir);
            self.file_watcher = watcher;
        } else {
            self.file_watcher = null;
        }

        if (cfg.plugin_enabled) {
            const pm = try allocator.create(@import("plugin.zig").PluginManager);
            pm.* = @import("plugin.zig").PluginManager.init(allocator, &self.config);
            self.plugin_manager = pm;
        } else {
            self.plugin_manager = null;
        }

        self.initialized = true;
    }

    pub fn deinit(self: *App) void {
        if (self.server) |*s| s.deinit();
        if (self.template_engine) |*te| te.deinit();
        for (self.static_servers.items) |ss| {
            ss.deinit();
            self.allocator.destroy(ss);
        }
        self.static_servers.deinit(self.allocator);
        if (self.static_server) |*ss| ss.deinit();
        if (self.file_watcher) |w| {
            w.deinit();
            self.allocator.destroy(w);
        }
        if (self.plugin_manager) |pm| {
            pm.deinit();
            self.allocator.destroy(pm);
        }

        self.router.deinit();
        self.logger.deinit();
        for (self.blueprints.items) |*bp| {
            for (bp.routes.items) |r| {
                self.allocator.free(r.pattern);
                self.allocator.free(r.segments);
                if (r.middleware.len > 0) {
                    self.allocator.free(r.middleware);
                }
            }
            bp.routes.deinit(self.allocator);
        }
        self.blueprints.deinit(self.allocator);
        self.before_request_handlers.deinit(self.allocator);
        self.after_request_handlers.deinit(self.allocator);
        self.teardown_handlers.deinit(self.allocator);
        self.error_handlers.deinit(self.allocator);
        self.url_map.deinit(self.allocator);
        self.extensions.deinit(self.allocator);
        self.arena.deinit();
        self.initialized = false;
    }

    pub fn route(self: *App, path: []const u8, methods: []const constants.HttpMethod) RouteDecorator {
        return RouteDecorator{ .app = self, .path = path, .methods = methods };
    }

    pub const RouteDecorator = struct {
        app: *App,
        path: []const u8,
        methods: []const constants.HttpMethod,

        pub fn handler(self: RouteDecorator, h: Router.HandlerFn) !void {
            for (self.methods) |method| {
                switch (method) {
                    .GET => try self.app.router.get(self.path, h),
                    .POST => try self.app.router.post(self.path, h),
                    .PUT => try self.app.router.put(self.path, h),
                    .DELETE => try self.app.router.delete(self.path, h),
                    .PATCH => try self.app.router.patch(self.path, h),
                    else => {},
                }
            }
        }
    };

    pub fn get(self: *App, path: []const u8, handler: router_mod.HandlerFn) !void {
        try self.router.get(path, handler);
    }

    pub fn post(self: *App, path: []const u8, handler: router_mod.HandlerFn) !void {
        try self.router.post(path, handler);
    }

    pub fn put(self: *App, path: []const u8, handler: router_mod.HandlerFn) !void {
        try self.router.put(path, handler);
    }

    pub fn delete(self: *App, path: []const u8, handler: router_mod.HandlerFn) !void {
        try self.router.delete(path, handler);
    }

    pub fn patch(self: *App, path: []const u8, handler: router_mod.HandlerFn) !void {
        try self.router.patch(path, handler);
    }

    pub fn head(self: *App, path: []const u8, handler: router_mod.HandlerFn) !void {
        try self.router.head(path, handler);
    }

    pub fn options(self: *App, path: []const u8, handler: router_mod.HandlerFn) !void {
        try self.router.options(path, handler);
    }

    pub fn group(self: *App, url_prefix: []const u8) router_mod.RouteGroup {
        return self.router.group(url_prefix);
    }

    pub fn use(self: *App, mw: middleware_mod.MiddlewareFn) !void {
        try self.router.use(mw);
    }

    pub fn addTemplateRoute(self: *App, path: []const u8, template_path: []const u8) !void {
        const tpl_copy = try self.arena.allocator().dupe(u8, template_path);
        const slice_ptr = try self.arena.allocator().create([]const u8);
        slice_ptr.* = tpl_copy;

        const opaque_ptr = @as(*const anyopaque, @ptrCast(slice_ptr));
        try self.router.addRouteWithData(.GET, path, genericTemplateHandler, opaque_ptr);
    }

    fn genericTemplateHandler(ctx: *Context) !void {
        if (ctx.route_data) |data| {
            const template_path = @as(*const []const u8, @ptrCast(@alignCast(data))).*;
            try ctx.render(template_path, .{});
        } else {
            return error.TemplateDataMissing;
        }
    }

    pub fn beforeRequest(self: *App, handler: BeforeRequestFn) !void {
        try self.before_request_handlers.append(self.allocator, handler);
    }

    pub fn afterRequest(self: *App, handler: AfterRequestFn) !void {
        try self.after_request_handlers.append(self.allocator, handler);
    }

    pub fn teardown(self: *App, handler: TeardownFn) !void {
        try self.teardown_handlers.append(self.allocator, handler);
    }

    pub fn errorHandler(self: *App, error_name: []const u8, handler: ErrorHandlerFn) !void {
        try self.error_handlers.put(self.allocator, error_name, handler);
    }

    pub fn registerBlueprint(self: *App, bp: AppBlueprint, url_prefix: ?[]const u8) !void {
        const prefix = url_prefix orelse bp.url_prefix;
        for (bp.routes.items) |r| {
            var full_path_buf: [512]u8 = undefined;
            const full_path = std.fmt.bufPrint(&full_path_buf, "{s}{s}", .{ prefix, r.path }) catch continue;
            const path_copy = try self.allocator.dupe(u8, full_path);
            try self.router.addRoute(r.method, path_copy, r.handler);
        }
        try self.blueprints.append(self.allocator, bp);
    }

    pub fn addExtension(self: *App, name: []const u8, ext: *anyopaque) !void {
        try self.extensions.put(name, ext);
    }

    pub fn getExtension(self: *App, name: []const u8) ?*anyopaque {
        return self.extensions.get(name);
    }

    pub fn urlFor(self: *App, endpoint: []const u8) ?[]const u8 {
        return self.url_map.get(endpoint);
    }

    pub fn getBlueprints(self: *App) []const AppBlueprint {
        return self.blueprints.items;
    }

    pub fn static(self: *App, url_path: []const u8, folder_path: []const u8) !void {
        const ss = try self.allocator.create(StaticFileServer);
        ss.* = StaticFileServer.init(self.allocator, &self.config);

        const root = try self.arena.allocator().dupe(u8, folder_path);
        const mount = try self.arena.allocator().dupe(u8, url_path);
        ss.setRootDir(root);
        ss.setMountPath(mount);

        try self.static_servers.append(self.allocator, ss);

        try self.router.addRouteWithData(.GET, url_path, genericStaticHandler, ss);

        var wildcard: [256]u8 = undefined;
        const normalized = std.mem.trimRight(u8, url_path, "/");
        const wp = try std.fmt.bufPrint(&wildcard, "{s}/*", .{normalized});
        try self.router.addRouteWithData(.GET, wp, genericStaticHandler, ss);
    }

    fn genericStaticHandler(ctx: *Context) !void {
        if (ctx.route_data) |data| {
            const ss = @as(*StaticFileServer, @ptrCast(@alignCast(@constCast(data))));
            try ss.serve(ctx);
        } else {
            try ctx.notFound();
        }
    }

    pub fn enableTemplates(self: *App) void {
        if (self.template_engine == null) {
            self.template_engine = TemplateEngine.init(self.allocator, &self.config);
        }
    }

    pub fn enableStatic(self: *App) void {
        if (self.static_server == null) {
            self.static_server = StaticFileServer.init(self.allocator, &self.config);
        }
    }

    pub fn notFound(self: *App, handler: Router.HandlerFn) void {
        self.router.notFound(handler);
    }

    pub fn methodNotAllowed(self: *App, handler: Router.HandlerFn) void {
        self.router.methodNotAllowed(handler);
    }

    pub fn printRoutes(self: *App) void {
        std.debug.print("APP printRoutes start\n", .{});
        self.router.printRoutes();
        std.debug.print("APP printRoutes end\n", .{});
    }

    pub fn run(self: *App) !void {
        try self.runWithOptions(.{});
    }

    pub fn runWithOptions(self: *App, opts: LaunchOptions) !void {
        const port = opts.port orelse self.config.port;
        const address = opts.address orelse self.config.address;
        const debug = opts.debug orelse self.config.debug_mode;
        self.config.port = port;
        self.config.address = address;
        self.config.debug_mode = debug;
        self.debug = debug;
        var te_ptr: ?*TemplateEngine = null;
        if (self.template_engine) |*te| {
            te_ptr = te;
        }

        if (self.file_watcher) |watcher| {
            try watcher.start();
        }

        self.server = Server.init(self.allocator, &self.config, &self.router, &self.logger, te_ptr);
        if (self.server) |*s| {
            try s.start();
        }
    }

    pub fn testClient(self: *App) TestClient {
        return TestClient.init(self);
    }

    pub fn makeResponse(self: *App, content: []const u8, status_code: u16, content_type: []const u8) Response {
        var response = Response.init(self.allocator, &self.config);
        _ = response.status(status_code);
        response.setHeader("Content-Type", content_type) catch {};
        response.body.appendSlice(self.allocator, content) catch {};
        return response;
    }

    pub const LaunchOptions = struct {
        port: ?u16 = null,
        address: ?[]const u8 = null,
        debug: ?bool = null,
        use_reloader: bool = false,
        threaded: bool = true,
        processes: u32 = 1,
        ssl_context: ?SslContext = null,
        passthrough_errors: bool = false,
        load_dotenv: bool = true,
    };

    pub const SslContext = struct {
        cert_file: []const u8,
        key_file: []const u8,
        ca_file: ?[]const u8 = null,
    };

    pub const TestClient = struct {
        app: *App,

        pub fn init(app: *App) TestClient {
            return TestClient{ .app = app };
        }

        pub fn get(self: *TestClient, path: []const u8) !TestResponse {
            return self.request(.GET, path, null);
        }

        pub fn post(self: *TestClient, path: []const u8, data: ?[]const u8) !TestResponse {
            return self.request(.POST, path, data);
        }

        pub fn put(self: *TestClient, path: []const u8, data: ?[]const u8) !TestResponse {
            return self.request(.PUT, path, data);
        }

        pub fn delete(self: *TestClient, path: []const u8) !TestResponse {
            return self.request(.DELETE, path, null);
        }

        pub fn request(self: *TestClient, method: constants.HttpMethod, path: []const u8, body: ?[]const u8) !TestResponse {
            _ = body;
            _ = self;
            return TestResponse{
                .status_code = 200,
                .data = "",
                .headers = std.StringHashMap([]const u8).init(std.heap.page_allocator),
                .path = path,
                .method = method,
            };
        }
    };

    pub const TestResponse = struct {
        status_code: u16,
        data: []const u8,
        headers: std.StringHashMap([]const u8),
        path: []const u8,
        method: constants.HttpMethod,

        pub fn json(self: *TestResponse, comptime T: type) !T {
            return std.json.parseFromSlice(T, std.heap.page_allocator, self.data, .{});
        }

        pub fn getText(self: *TestResponse) []const u8 {
            return self.data;
        }
    };
};

pub fn createApp(allocator: std.mem.Allocator, cfg: Config) !App {
    return App.init(allocator, cfg);
}

pub fn quickStart(allocator: std.mem.Allocator) !App {
    return App.init(allocator, Config{});
}

test "App.init creates app" {
    const allocator = std.testing.allocator;
    var app: App = undefined;
    try app.init(allocator, Config{});
    defer app.deinit();
    try std.testing.expect(app.initialized);
}

test "App.get registers route" {
    const allocator = std.testing.allocator;
    var app: App = undefined;
    try app.init(allocator, Config{});
    defer app.deinit();
    try app.get("/test", struct {
        fn h(_: *Context) !void {}
    }.h);
    try std.testing.expect(app.router.routes.items.len >= 1);
}

test "App.post registers route" {
    const allocator = std.testing.allocator;
    var app: App = undefined;
    try app.init(allocator, Config{});
    defer app.deinit();
    try app.post("/api", struct {
        fn h(_: *Context) !void {}
    }.h);
    try std.testing.expect(app.router.routes.items.len >= 1);
}

test "App.use adds middleware" {
    const allocator = std.testing.allocator;
    var app: App = undefined;
    try app.init(allocator, Config{});
    defer app.deinit();
    try app.use(middleware_mod.securityHeaders());
    try std.testing.expect(app.router.global_middleware.items.len >= 1);
}

test "App.enableTemplates creates engine" {
    const allocator = std.testing.allocator;
    var app: App = undefined;
    try app.init(allocator, Config{});
    defer app.deinit();
    app.enableTemplates();
    try std.testing.expect(app.template_engine != null);
}

test "App.testClient creates client" {
    const allocator = std.testing.allocator;
    var app: App = undefined;
    try app.init(allocator, Config{});
    defer app.deinit();
    const client = app.testClient();
    try std.testing.expect(client.app == &app);
}

test "App.group creates route group" {
    const allocator = std.testing.allocator;
    var app: App = undefined;
    try app.init(allocator, Config{});
    defer app.deinit();
    var grp = app.group("/api");
    try grp.get("/users", struct {
        fn h(_: *Context) !void {}
    }.h);
}
