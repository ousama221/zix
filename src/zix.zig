const std = @import("std");

pub const constants = @import("constants.zig");
pub const config = @import("config.zig");
pub const errors = @import("errors.zig");
pub const utils = @import("utils.zig");
pub const logger = @import("logger.zig");
pub const request = @import("request.zig");
pub const response = @import("response.zig");
pub const context = @import("context.zig");
pub const router = @import("router.zig");
pub const middleware = @import("middleware.zig");
pub const templates = @import("templates.zig");
pub const static = @import("static.zig");
pub const security = @import("security.zig");
pub const server = @import("server.zig");
pub const async_utils = @import("async.zig");
pub const app = @import("app.zig");
pub const session = @import("session.zig");
pub const auth = @import("auth.zig");
pub const plugin = @import("plugin.zig");
pub const state = @import("state.zig");
pub const watcher = @import("watcher.zig");
pub const navigation = @import("navigation.zig");

pub const App = app.App;
pub const Config = config.Config;
pub const ConfigBuilder = config.ConfigBuilder;
pub const Context = context.Context;
pub const Request = request.Request;
pub const Response = response.Response;
pub const Router = router.Router;
pub const Server = server.Server;
pub const Logger = logger.Logger;
pub const Level = logger.Level;
pub const TemplateEngine = templates.TemplateEngine;
pub const Template = templates.Template;
pub const StaticFileServer = static.StaticFileServer;
pub const SecurityHeaders = security.SecurityHeaders;
pub const CorsConfig = security.CorsConfig;
pub const RateLimiter = security.RateLimiter;
pub const CsrfProtection = security.CsrfProtection;
pub const Session = session.Session;
pub const SessionManager = session.SessionManager;
pub const CookieSession = session.CookieSession;
pub const FlashMessage = session.FlashMessage;
pub const User = auth.User;
pub const Token = auth.Token;
pub const LoginManager = auth.LoginManager;
pub const PasswordHasher = auth.PasswordHasher;
pub const TokenManager = auth.TokenManager;
pub const Plugin = plugin.Plugin;
pub const PluginManager = plugin.PluginManager;
pub const ExternalLogger = plugin.ExternalLogger;
pub const LoggerRegistry = plugin.LoggerRegistry;
pub const AppState = state.AppState;
pub const Store = state.Store;
pub const FileWatcher = watcher.FileWatcher;
pub const Navigation = navigation.Navigation;

pub const HandlerFn = router.HandlerFn;
pub const MiddlewareFn = router.MiddlewareFn;
pub const NextFn = router.NextFn;

pub const HttpMethod = constants.HttpMethod;
pub const HttpStatus = constants.HttpStatus;
pub const MimeTypes = constants.MimeTypes;

pub const ZixError = errors.ZixError;
pub const ErrorInfo = errors.ErrorInfo;

pub const Timer = async_utils.Timer;
pub const TaskQueue = async_utils.TaskQueue;
pub const Task = async_utils.Task;
pub const Debouncer = async_utils.Debouncer;
pub const Throttler = async_utils.Throttler;

pub const VERSION = constants.Version.string;
pub const VERSION_MAJOR = constants.Version.major;
pub const VERSION_MINOR = constants.Version.minor;
pub const VERSION_PATCH = constants.Version.patch;
pub const FRAMEWORK_NAME = constants.Framework.name;

pub fn init(allocator: std.mem.Allocator, cfg: config.Config) !*app.App {
    const self = try allocator.create(app.App);
    @memset(std.mem.asBytes(self), 0);
    try self.init(allocator, cfg);
    return self;
}

pub fn quickStart(allocator: std.mem.Allocator) !*app.App {
    return init(allocator, config.Config{});
}

pub fn createApp(allocator: std.mem.Allocator, cfg: config.Config) !*app.App {
    return init(allocator, cfg);
}

pub fn createRouter(allocator: std.mem.Allocator, cfg: *const Config) Router {
    return Router.init(allocator, cfg);
}

pub fn createLogger(allocator: std.mem.Allocator, cfg: *const Config) Logger {
    return Logger.init(allocator, cfg);
}

pub fn createTemplateEngine(allocator: std.mem.Allocator, cfg: *const Config) TemplateEngine {
    return TemplateEngine.init(allocator, cfg);
}

pub fn createStaticServer(allocator: std.mem.Allocator, cfg: *const Config) StaticFileServer {
    return StaticFileServer.init(allocator, cfg);
}

pub fn urlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    return utils.urlEncode(allocator, input);
}

pub fn urlDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    return utils.urlDecode(allocator, input);
}

pub fn htmlEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    return utils.htmlEscape(allocator, input);
}

pub fn jsonEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    return utils.jsonEscape(allocator, input);
}

pub fn getMimeType(path_str: []const u8) []const u8 {
    return static.getMimeType(path_str);
}

pub fn isValidPath(path_str: []const u8) bool {
    return security.isValidPath(path_str);
}

pub fn validateInput(input: []const u8) bool {
    return security.validateInput(input);
}

pub fn sanitizeInput(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    return security.sanitizeInput(allocator, input);
}

pub fn timestamp() i64 {
    return async_utils.timestamp();
}

pub fn milliTimestamp() i64 {
    return async_utils.milliTimestamp();
}

pub fn sleep(ms: u64) void {
    async_utils.sleep(ms);
}

pub fn redirect(ctx: *Context, location: []const u8, status_code: ?u16) !void {
    try ctx.redirect(location, status_code);
}

pub fn redirectPermanent(ctx: *Context, location: []const u8) !void {
    try ctx.redirectPermanent(location);
}

pub fn abort(ctx: *Context, status_code: u16) !void {
    _ = ctx.status(status_code);
    ctx.abort();
}

pub fn jsonify(ctx: *Context, data: anytype) !void {
    try ctx.json(data);
}

pub fn renderTemplate(ctx: *Context, name: []const u8, data: anytype) !void {
    try ctx.render(name, data);
}

pub fn sendFromDirectory(ctx: *Context, directory: []const u8, filename: []const u8) !void {
    var path_buf: [1024]u8 = undefined;
    const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ directory, filename }) catch return error.PathTooLong;
    try ctx.file(full_path);
}

pub fn makeResponseWithStatus(allocator: std.mem.Allocator, cfg: *const Config, content: []const u8, status_code: u16) !Response {
    return response.makeResponse(allocator, cfg, content, status_code);
}

pub const Environment = config.Environment;
pub const LaunchOptions = app.App.LaunchOptions;
pub const SslContext = app.App.SslContext;
pub const RouteGroup = router.RouteGroup;
pub const Route = router.Route;

test "zix module exports are accessible" {
    const testing = std.testing;

    try testing.expectEqualStrings("Zix", FRAMEWORK_NAME);
    try testing.expectEqualStrings("0.0.1", VERSION);
    try testing.expectEqual(@as(u32, 0), VERSION_MAJOR);
    try testing.expectEqual(@as(u32, 0), VERSION_MINOR);
    try testing.expectEqual(@as(u32, 1), VERSION_PATCH);
}

test "zix.init creates app" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var zix_app = try init(allocator, Config{});
    defer allocator.destroy(zix_app);
    defer zix_app.deinit();

    try testing.expect(zix_app.initialized);
}

test "zix.quickStart creates app with defaults" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var zix_app = try quickStart(allocator);
    defer allocator.destroy(zix_app);
    defer zix_app.deinit();

    try testing.expectEqual(@as(u16, 3000), zix_app.config.port);
}

test "zix.createRouter creates router" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cfg = Config{};
    var rtr = createRouter(allocator, &cfg);
    defer rtr.deinit();

    try testing.expectEqual(@as(usize, 0), rtr.routes.items.len);
}

test "zix.urlEncode and urlDecode are inverses" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const original = "hello world!";
    const encoded = try urlEncode(allocator, original);
    defer allocator.free(encoded);

    const decoded = try urlDecode(allocator, encoded);
    defer allocator.free(decoded);

    try testing.expectEqualStrings(original, decoded);
}

test "zix.htmlEscape escapes HTML" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const escaped = try htmlEscape(allocator, "<script>alert('xss')</script>");
    defer allocator.free(escaped);

    try testing.expect(std.mem.indexOf(u8, escaped, "&lt;script&gt;") != null);
}

test "zix.getMimeType returns correct type" {
    const testing = std.testing;
    try testing.expectEqualStrings("text/html; charset=utf-8", getMimeType("index.html"));
    try testing.expectEqualStrings("application/json; charset=utf-8", getMimeType("data.json"));
}

test "zix.isValidPath rejects traversal" {
    const testing = std.testing;
    try testing.expect(!isValidPath("../etc/passwd"));
    try testing.expect(isValidPath("/valid/path/file.txt"));
}

test "zix.validateInput checks for null bytes" {
    const testing = std.testing;
    try testing.expect(!validateInput("hello\x00world"));
    try testing.expect(validateInput("hello world"));
}

test "zix.timestamp returns current time" {
    const testing = std.testing;
    const ts = timestamp();
    try testing.expect(ts > 0);
}

test "exported types are correct" {
    const testing = std.testing;
    try testing.expect(@TypeOf(App) == type);
    try testing.expect(@TypeOf(Config) == type);
    try testing.expect(@TypeOf(Context) == type);
    try testing.expect(@TypeOf(Router) == type);
    try testing.expect(@TypeOf(Logger) == type);
}

comptime {
    _ = constants;
    _ = config;
    _ = errors;
    _ = utils;
    _ = logger;
    _ = request;
    _ = response;
    _ = context;
    _ = router;
    _ = middleware;
    _ = templates;
    _ = static;
    _ = security;
    _ = server;
    _ = async_utils;
    _ = app;
}
