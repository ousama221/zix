const std = @import("std");
const constants = @import("constants.zig");

pub const Config = struct {
    port: u16 = constants.Defaults.port,
    address: []const u8 = constants.Defaults.address,
    debug_mode: bool = false,
    enable_logging: bool = true,
    shutdown_timeout_ms: u32 = 5000,
    max_body_size: usize = constants.Defaults.max_body_size,
    max_header_size: usize = constants.Defaults.max_header_size,
    max_uri_size: usize = constants.Defaults.max_uri_size,
    max_connections: u32 = constants.Defaults.max_connections,
    buffer_size: usize = constants.Defaults.buffer_size,
    read_timeout_ms: u32 = constants.Defaults.read_timeout_ms,
    write_timeout_ms: u32 = constants.Defaults.write_timeout_ms,
    keep_alive_timeout_ms: u32 = constants.Defaults.keep_alive_timeout_ms,
    server_name: []const u8 = constants.Defaults.server_name,
    static_dir: []const u8 = constants.Defaults.static_dir,
    static_mount_path: []const u8 = constants.Defaults.static_mount_path,
    static_cache_max_age: u32 = constants.Static.default_cache_max_age,
    serve_static: bool = true,
    template_dir: []const u8 = constants.Defaults.template_dir,
    auto_escape: bool = true,
    template_cache: bool = true,
    enable_security_headers: bool = true,
    x_content_type_options: []const u8 = constants.Security.default_x_content_type_options,
    x_frame_options: []const u8 = constants.Security.default_x_frame_options,
    x_xss_protection: []const u8 = constants.Security.default_x_xss_protection,
    referrer_policy: []const u8 = constants.Security.default_referrer_policy,
    content_security_policy: ?[]const u8 = null,
    strict_transport_security: ?[]const u8 = null,
    permissions_policy: ?[]const u8 = "unload=()",
    cors_enabled: bool = false,
    cors_allow_origin: []const u8 = "*",
    cors_allow_methods: []const u8 = "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    cors_allow_headers: []const u8 = "Content-Type, Authorization, X-Requested-With",
    cors_expose_headers: ?[]const u8 = null,
    cors_max_age: u32 = 86400,
    cors_allow_credentials: bool = false,
    session_enabled: bool = false,
    session_cookie_name: []const u8 = constants.Session.cookie_name,
    session_max_age: i64 = constants.Session.default_max_age,
    session_secure: bool = constants.Session.secure_cookie,
    session_http_only: bool = constants.Session.http_only,
    session_same_site: []const u8 = constants.Session.same_site,
    secret_key: ?[]const u8 = null,
    rate_limit_enabled: bool = false,
    rate_limit_requests: u32 = 100,
    rate_limit_window_ms: u32 = 60_000,
    csrf_enabled: bool = false,
    csrf_cookie_name: []const u8 = "zix_csrf",
    csrf_header_name: []const u8 = "X-CSRF-Token",
    compression_enabled: bool = false,
    compression_min_size: usize = 1024,
    json_pretty_print: bool = false,
    json_escape_html: bool = true,
    threaded: bool = true,
    processes: u32 = 1,
    use_reloader: bool = false,
    use_debugger: bool = false,
    use_evalex: bool = true,
    passthrough_errors: bool = false,
    load_dotenv: bool = true,
    propagate_exceptions: bool = false,
    preserve_context_on_exception: bool = false,
    trap_http_exceptions: bool = false,
    explain_template_loading: bool = false,
    preferred_url_scheme: []const u8 = "http",
    max_content_length: ?usize = null,
    send_file_max_age_default: u32 = 43200,
    wsgi_enabled: bool = false,
    wsgi_app: ?[]const u8 = null,
    plugin_enabled: bool = constants.Plugin.enabled_default,
    plugin_auto_discover: bool = constants.Plugin.auto_discover,
    plugin_directory: []const u8 = constants.Plugin.default_directory,
    auth_enabled: bool = false,
    auth_login_view: []const u8 = constants.Auth.default_login_view,
    auth_token_lifetime: i64 = constants.Auth.default_token_lifetime,
    auth_refresh_token_lifetime: i64 = constants.Auth.refresh_token_lifetime,
    error_page_template: ?[]const u8 = null,
    custom_error_handler: bool = false,
    api_prefix: []const u8 = "/api",
    api_version: []const u8 = "v1",
    cookie_secure: bool = false,
    spa_mode: bool = false,
    spa_index: []const u8 = "index.html",
    cookie_http_only: bool = true,
    cookie_same_site: []const u8 = "Lax",
    cookie_domain: ?[]const u8 = null,
    cookie_path: []const u8 = "/",

    pub fn validate(self: *Config) !void {
        if (self.port == 0) return error.InvalidPort;
        if (self.max_body_size == 0) return error.InvalidBodySize;
        if (self.buffer_size == 0) return error.InvalidBufferSize;
        if (self.max_connections == 0) return error.InvalidMaxConnections;
    }

    pub fn withOverrides(self: Config, overrides: ConfigOverrides) Config {
        var result = self;
        if (overrides.port) |p| result.port = p;
        if (overrides.address) |a| result.address = a;
        if (overrides.debug_mode) |d| result.debug_mode = d;
        if (overrides.enable_logging) |l| result.enable_logging = l;
        return result;
    }

    pub fn isDebug(self: *const Config) bool {
        return self.debug_mode;
    }

    pub fn isCorsEnabled(self: *const Config) bool {
        return self.cors_enabled;
    }

    pub fn getServerUrl(self: *const Config, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "http://{s}:{d}", .{ self.address, self.port });
    }

    pub fn fromEnvironment(self: *Config) void {
        if (std.process.getEnvVarOwned(std.heap.page_allocator, "ZIX_DEBUG")) |val| {
            self.debug_mode = std.mem.eql(u8, val, "1") or std.mem.eql(u8, val, "true");
            std.heap.page_allocator.free(val);
        } else |_| {}
        if (std.process.getEnvVarOwned(std.heap.page_allocator, "ZIX_PORT")) |val| {
            self.port = std.fmt.parseInt(u16, val, 10) catch self.port;
            std.heap.page_allocator.free(val);
        } else |_| {}
    }
};

pub const ConfigOverrides = struct {
    port: ?u16 = null,
    address: ?[]const u8 = null,
    debug_mode: ?bool = null,
    enable_logging: ?bool = null,
};

pub const ConfigBuilder = struct {
    config: Config,

    pub fn init() ConfigBuilder {
        return ConfigBuilder{ .config = Config{} };
    }

    pub fn port(self: *ConfigBuilder, p: u16) *ConfigBuilder {
        self.config.port = p;
        return self;
    }

    pub fn address(self: *ConfigBuilder, addr: []const u8) *ConfigBuilder {
        self.config.address = addr;
        return self;
    }

    pub fn debugMode(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.debug_mode = enabled;
        return self;
    }

    pub fn logging(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.enable_logging = enabled;
        return self;
    }

    pub fn maxBodySize(self: *ConfigBuilder, size: usize) *ConfigBuilder {
        self.config.max_body_size = size;
        return self;
    }

    pub fn maxConnections(self: *ConfigBuilder, max: u32) *ConfigBuilder {
        self.config.max_connections = max;
        return self;
    }

    pub fn templateDir(self: *ConfigBuilder, dir: []const u8) *ConfigBuilder {
        self.config.template_dir = dir;
        return self;
    }

    pub fn staticDir(self: *ConfigBuilder, dir: []const u8) *ConfigBuilder {
        self.config.static_dir = dir;
        return self;
    }

    pub fn staticMountPath(self: *ConfigBuilder, path: []const u8) *ConfigBuilder {
        self.config.static_mount_path = path;
        return self;
    }

    pub fn staticCacheMaxAge(self: *ConfigBuilder, max_age: u32) *ConfigBuilder {
        self.config.static_cache_max_age = max_age;
        return self;
    }

    pub fn serveStatic(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.serve_static = enabled;
        return self;
    }

    pub fn securityHeaders(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.enable_security_headers = enabled;
        return self;
    }

    pub fn cors(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.cors_enabled = enabled;
        return self;
    }

    pub fn corsAllowOrigin(self: *ConfigBuilder, origin: []const u8) *ConfigBuilder {
        self.config.cors_allow_origin = origin;
        return self;
    }

    pub fn corsAllowMethods(self: *ConfigBuilder, methods: []const u8) *ConfigBuilder {
        self.config.cors_allow_methods = methods;
        return self;
    }

    pub fn corsAllowHeaders(self: *ConfigBuilder, headers: []const u8) *ConfigBuilder {
        self.config.cors_allow_headers = headers;
        return self;
    }

    pub fn corsAllowCredentials(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.cors_allow_credentials = enabled;
        return self;
    }

    pub fn corsMaxAge(self: *ConfigBuilder, max_age: u32) *ConfigBuilder {
        self.config.cors_max_age = max_age;
        return self;
    }

    pub fn secretKey(self: *ConfigBuilder, key: []const u8) *ConfigBuilder {
        self.config.secret_key = key;
        return self;
    }

    pub fn serverName(self: *ConfigBuilder, name: []const u8) *ConfigBuilder {
        self.config.server_name = name;
        return self;
    }

    pub fn session(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.session_enabled = enabled;
        return self;
    }

    pub fn sessionCookieName(self: *ConfigBuilder, name: []const u8) *ConfigBuilder {
        self.config.session_cookie_name = name;
        return self;
    }

    pub fn sessionMaxAge(self: *ConfigBuilder, max_age: i64) *ConfigBuilder {
        self.config.session_max_age = max_age;
        return self;
    }

    pub fn rateLimit(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.rate_limit_enabled = enabled;
        return self;
    }

    pub fn rateLimitRequests(self: *ConfigBuilder, requests: u32) *ConfigBuilder {
        self.config.rate_limit_requests = requests;
        return self;
    }

    pub fn rateLimitWindow(self: *ConfigBuilder, window_ms: u32) *ConfigBuilder {
        self.config.rate_limit_window_ms = window_ms;
        return self;
    }

    pub fn csrfProtection(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.csrf_enabled = enabled;
        return self;
    }

    pub fn compression(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.compression_enabled = enabled;
        return self;
    }

    pub fn compressionMinSize(self: *ConfigBuilder, size: usize) *ConfigBuilder {
        self.config.compression_min_size = size;
        return self;
    }

    pub fn jsonPrettyPrint(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.json_pretty_print = enabled;
        return self;
    }

    pub fn autoEscape(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.auto_escape = enabled;
        return self;
    }

    pub fn templateCache(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.template_cache = enabled;
        return self;
    }

    pub fn readTimeout(self: *ConfigBuilder, timeout_ms: u32) *ConfigBuilder {
        self.config.read_timeout_ms = timeout_ms;
        return self;
    }

    pub fn writeTimeout(self: *ConfigBuilder, timeout_ms: u32) *ConfigBuilder {
        self.config.write_timeout_ms = timeout_ms;
        return self;
    }

    pub fn keepAliveTimeout(self: *ConfigBuilder, timeout_ms: u32) *ConfigBuilder {
        self.config.keep_alive_timeout_ms = timeout_ms;
        return self;
    }

    pub fn shutdownTimeout(self: *ConfigBuilder, timeout_ms: u32) *ConfigBuilder {
        self.config.shutdown_timeout_ms = timeout_ms;
        return self;
    }

    pub fn threaded(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.threaded = enabled;
        return self;
    }

    pub fn processes(self: *ConfigBuilder, num: u32) *ConfigBuilder {
        self.config.processes = num;
        return self;
    }

    pub fn useReloader(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.use_reloader = enabled;
        return self;
    }

    pub fn useDebugger(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.use_debugger = enabled;
        return self;
    }

    pub fn wsgi(self: *ConfigBuilder, enabled: bool) *ConfigBuilder {
        self.config.wsgi_enabled = enabled;
        return self;
    }

    pub fn build(self: *ConfigBuilder) !Config {
        try self.config.validate();
        return self.config;
    }

    pub fn buildUnchecked(self: *ConfigBuilder) Config {
        return self.config;
    }
};

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

pub const Environment = enum {
    development,
    testing,
    staging,
    production,

    pub fn getConfig(self: Environment) Config {
        return switch (self) {
            .development => Config{
                .debug_mode = true,
                .enable_logging = true,
                .cors_enabled = true,
                .cors_allow_origin = "*",
                .json_pretty_print = true,
                .template_cache = false,
                .use_reloader = true,
                .use_debugger = true,
            },
            .testing => Config{
                .debug_mode = true,
                .enable_logging = false,
                .session_secure = false,
                .propagate_exceptions = true,
                .preserve_context_on_exception = true,
            },
            .staging => Config{
                .debug_mode = false,
                .enable_logging = true,
                .enable_security_headers = true,
            },
            .production => Config{
                .debug_mode = false,
                .enable_logging = true,
                .enable_security_headers = true,
                .session_secure = true,
                .cors_enabled = false,
                .template_cache = true,
                .compression_enabled = true,
                .threaded = true,
            },
        };
    }
};

test "Config default values" {
    const cfg = Config{};
    try std.testing.expectEqual(@as(u16, 3000), cfg.port);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.address);
    try std.testing.expect(!cfg.debug_mode);
}

test "Config validation" {
    var valid_cfg = Config{};
    try valid_cfg.validate();
    var invalid_cfg = Config{ .port = 0 };
    try std.testing.expectError(error.InvalidPort, invalid_cfg.validate());
}

test "ConfigBuilder creates config" {
    var builder = ConfigBuilder.init();
    const cfg = try builder.port(8080).address("0.0.0.0").debugMode(true).cors(true).build();
    try std.testing.expectEqual(@as(u16, 8080), cfg.port);
    try std.testing.expect(cfg.debug_mode);
    try std.testing.expect(cfg.cors_enabled);
}

test "Config withOverrides" {
    const base = Config{};
    const overrides = ConfigOverrides{ .port = 9000, .debug_mode = true };
    const cfg = base.withOverrides(overrides);
    try std.testing.expectEqual(@as(u16, 9000), cfg.port);
    try std.testing.expect(cfg.debug_mode);
}

test "Environment presets" {
    const dev = Environment.development.getConfig();
    try std.testing.expect(dev.debug_mode);
    try std.testing.expect(dev.cors_enabled);
    const prod = Environment.production.getConfig();
    try std.testing.expect(!prod.debug_mode);
    try std.testing.expect(prod.enable_security_headers);
}
