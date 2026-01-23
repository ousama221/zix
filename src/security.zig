const std = @import("std");
const constants = @import("constants.zig");
const Config = @import("config.zig").Config;
const Context = @import("context.zig").Context;
const utils = @import("utils.zig");

pub const SecurityHeaders = struct {
    content_security_policy: ?[]const u8,
    x_content_type_options: ?[]const u8,
    x_frame_options: ?[]const u8,
    x_xss_protection: ?[]const u8,
    strict_transport_security: ?[]const u8,
    referrer_policy: ?[]const u8,
    permissions_policy: ?[]const u8,

    pub fn fromConfig(config: *const Config) SecurityHeaders {
        if (!config.enable_security_headers) {
            return SecurityHeaders{
                .content_security_policy = null,
                .x_content_type_options = null,
                .x_frame_options = null,
                .x_xss_protection = null,
                .strict_transport_security = null,
                .referrer_policy = null,
                .permissions_policy = null,
            };
        }

        return SecurityHeaders{
            .content_security_policy = config.content_security_policy,
            .x_content_type_options = config.x_content_type_options,
            .x_frame_options = config.x_frame_options,
            .x_xss_protection = config.x_xss_protection,
            .strict_transport_security = config.strict_transport_security,
            .referrer_policy = config.referrer_policy,
            .permissions_policy = config.permissions_policy,
        };
    }

    pub fn apply(self: *const SecurityHeaders, ctx: *Context) !void {
        if (self.content_security_policy) |csp| {
            try ctx.setHeader("Content-Security-Policy", csp);
        }
        if (self.x_content_type_options) |xcto| {
            try ctx.setHeader("X-Content-Type-Options", xcto);
        }
        if (self.x_frame_options) |xfo| {
            try ctx.setHeader("X-Frame-Options", xfo);
        }
        if (self.x_xss_protection) |xxp| {
            try ctx.setHeader("X-XSS-Protection", xxp);
        }
        if (self.strict_transport_security) |sts| {
            try ctx.setHeader("Strict-Transport-Security", sts);
        }
        if (self.referrer_policy) |rp| {
            try ctx.setHeader("Referrer-Policy", rp);
        }
        if (self.permissions_policy) |pp| {
            try ctx.setHeader("Permissions-Policy", pp);
        }
    }
};

pub const CorsConfig = struct {
    allow_origin: []const u8 = "*",
    allow_methods: []const u8 = "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    allow_headers: []const u8 = "Content-Type, Authorization, X-Requested-With",
    expose_headers: ?[]const u8 = null,
    max_age: u32 = 86400,
    allow_credentials: bool = false,

    pub fn fromConfig(config: *const Config) CorsConfig {
        return CorsConfig{
            .allow_origin = config.cors_allow_origin,
            .allow_methods = config.cors_allow_methods,
            .allow_headers = config.cors_allow_headers,
            .max_age = config.cors_max_age,
            .allow_credentials = config.cors_allow_credentials,
        };
    }

    pub fn apply(self: *const CorsConfig, ctx: *Context) !void {
        try ctx.setHeader("Access-Control-Allow-Origin", self.allow_origin);
        try ctx.setHeader("Access-Control-Allow-Methods", self.allow_methods);
        try ctx.setHeader("Access-Control-Allow-Headers", self.allow_headers);

        if (self.expose_headers) |eh| {
            try ctx.setHeader("Access-Control-Expose-Headers", eh);
        }

        var buf: [16]u8 = undefined;
        const max_age_str = std.fmt.bufPrint(&buf, "{d}", .{self.max_age}) catch "86400";
        try ctx.setHeader("Access-Control-Max-Age", max_age_str);

        if (self.allow_credentials) {
            try ctx.setHeader("Access-Control-Allow-Credentials", "true");
        }
    }
};

pub fn validateInput(input: []const u8) bool {
    for (input) |c| {
        if (c == 0) return false;
    }
    return true;
}

pub fn sanitizeInput(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    for (input) |c| {
        if (c == 0) continue;
        if (c < 32 and c != '\n' and c != '\r' and c != '\t') continue;
        try result.append(allocator, c);
    }

    return result.toOwnedSlice(allocator);
}

pub fn isValidPath(path: []const u8) bool {
    if (utils.isPathTraversal(path)) {
        return false;
    }

    if (std.mem.indexOf(u8, path, "\x00") != null) {
        return false;
    }

    return true;
}

pub fn sanitizePath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    var prev_was_slash = false;
    for (path) |c| {
        if (c == 0) continue;

        if (c == '/' or c == '\\') {
            if (!prev_was_slash) {
                try result.append(allocator, '/');
                prev_was_slash = true;
            }
        } else {
            try result.append(allocator, c);
            prev_was_slash = false;
        }
    }

    return result.toOwnedSlice(allocator);
}

pub fn validateContentLength(content_length: ?usize, max_size: usize) bool {
    if (content_length) |len| {
        return len <= max_size;
    }
    return true;
}

pub fn sanitizeHeader(allocator: std.mem.Allocator, header_value: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    for (header_value) |c| {
        if (c == '\r' or c == '\n' or c == 0) continue;
        try result.append(allocator, c);
    }

    return result.toOwnedSlice(allocator);
}

pub fn validateHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;

    for (name) |c| {
        if (c == ':' or c == '\r' or c == '\n' or c == 0) return false;
        if (c < 33 or c > 126) return false;
    }

    return true;
}

pub fn validateHeaderValue(value: []const u8) bool {
    for (value) |c| {
        if (c == '\r' or c == '\n' or c == 0) return false;
    }
    return true;
}

pub const CsrfProtection = struct {
    allocator: std.mem.Allocator,
    token_name: []const u8,
    header_name: []const u8,

    pub fn init(allocator: std.mem.Allocator) CsrfProtection {
        return CsrfProtection{
            .allocator = allocator,
            .token_name = "csrf_token",
            .header_name = "X-CSRF-Token",
        };
    }

    pub fn generateToken(self: *CsrfProtection) ![]u8 {
        return utils.generateRandomId(self.allocator, constants.Session.id_length);
    }

    pub fn validateToken(self: *CsrfProtection, ctx: *Context, expected: []const u8) !bool {
        _ = self;
        const header_token = ctx.header("X-CSRF-Token");
        if (header_token) |token| {
            return std.mem.eql(u8, token, expected);
        }

        const form_token = try ctx.form("csrf_token");
        if (form_token) |token| {
            return std.mem.eql(u8, token, expected);
        }

        return false;
    }
};

pub const RateLimiter = struct {
    allocator: std.mem.Allocator,
    max_requests: u32,
    window_ms: u64,
    requests: std.StringHashMap(RequestCount),

    pub const RequestCount = struct {
        count: u32,
        window_start: i64,
    };

    pub fn init(allocator: std.mem.Allocator, max_requests: u32, window_ms: u64) RateLimiter {
        return RateLimiter{
            .allocator = allocator,
            .max_requests = max_requests,
            .window_ms = window_ms,
            .requests = std.StringHashMap(RequestCount).init(allocator),
        };
    }

    pub fn deinit(self: *RateLimiter) void {
        var it = self.requests.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.requests.deinit();
    }

    pub fn isAllowed(self: *RateLimiter, identifier: []const u8) !bool {
        const now = std.time.milliTimestamp();

        if (self.requests.get(identifier)) |entry| {
            const window_end = entry.window_start + @as(i64, @intCast(self.window_ms));

            if (now > window_end) {
                const mutable_entry = self.requests.getPtr(identifier).?;
                mutable_entry.count = 1;
                mutable_entry.window_start = now;
                return true;
            }

            if (entry.count >= self.max_requests) {
                return false;
            }

            const mutable_entry = self.requests.getPtr(identifier).?;
            mutable_entry.count += 1;
            return true;
        }

        const key = try self.allocator.dupe(u8, identifier);
        try self.requests.put(key, RequestCount{
            .count = 1,
            .window_start = now,
        });
        return true;
    }

    pub fn reset(self: *RateLimiter, identifier: []const u8) void {
        if (self.requests.fetchRemove(identifier)) |removed| {
            self.allocator.free(removed.key);
        }
    }

    pub fn clear(self: *RateLimiter) void {
        var it = self.requests.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.requests.clearRetainingCapacity();
    }
};

test "SecurityHeaders.fromConfig creates headers" {
    const testing = std.testing;
    var config = Config{ .enable_security_headers = true };
    const headers = SecurityHeaders.fromConfig(&config);

    try testing.expect(headers.x_content_type_options != null);
    try testing.expect(headers.x_frame_options != null);
}

test "SecurityHeaders.fromConfig returns null when disabled" {
    const testing = std.testing;
    var config = Config{ .enable_security_headers = false };
    const headers = SecurityHeaders.fromConfig(&config);

    try testing.expect(headers.x_content_type_options == null);
    try testing.expect(headers.x_frame_options == null);
}

test "CorsConfig.fromConfig creates config" {
    const testing = std.testing;
    var config = Config{ .cors_enabled = true, .cors_allow_origin = "http://example.com" };
    const cors_cfg = CorsConfig.fromConfig(&config);

    try testing.expectEqualStrings("http://example.com", cors_cfg.allow_origin);
}

test "validateInput rejects null bytes" {
    const testing = std.testing;
    try testing.expect(!validateInput("hello\x00world"));
    try testing.expect(validateInput("hello world"));
}

test "sanitizeInput removes null bytes" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const result = try sanitizeInput(allocator, "hello\x00world");
    defer allocator.free(result);

    try testing.expectEqualStrings("helloworld", result);
}

test "isValidPath rejects traversal" {
    const testing = std.testing;
    try testing.expect(!isValidPath("../etc/passwd"));
    try testing.expect(!isValidPath("foo/../../bar"));
    try testing.expect(isValidPath("/valid/path"));
}

test "sanitizePath normalizes paths" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const result = try sanitizePath(allocator, "foo//bar\\baz");
    defer allocator.free(result);

    try testing.expectEqualStrings("foo/bar/baz", result);
}

test "validateHeaderName rejects invalid names" {
    const testing = std.testing;
    try testing.expect(!validateHeaderName(""));
    try testing.expect(!validateHeaderName("Header:Name"));
    try testing.expect(!validateHeaderName("Header\nName"));
    try testing.expect(validateHeaderName("Content-Type"));
    try testing.expect(validateHeaderName("X-Custom-Header"));
}

test "validateHeaderValue rejects newlines" {
    const testing = std.testing;
    try testing.expect(!validateHeaderValue("value\r\nHeader: injection"));
    try testing.expect(validateHeaderValue("normal value"));
}

test "sanitizeHeader removes dangerous characters" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const result = try sanitizeHeader(allocator, "value\r\nInjected: header");
    defer allocator.free(result);

    try testing.expect(std.mem.indexOf(u8, result, "\r\n") == null);
}

test "RateLimiter.init creates limiter" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var limiter = RateLimiter.init(allocator, 100, 60000);
    defer limiter.deinit();

    try testing.expectEqual(@as(u32, 100), limiter.max_requests);
    try testing.expectEqual(@as(u64, 60000), limiter.window_ms);
}

test "RateLimiter.isAllowed allows requests within limit" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var limiter = RateLimiter.init(allocator, 3, 60000);
    defer limiter.deinit();

    try testing.expect(try limiter.isAllowed("user1"));
    try testing.expect(try limiter.isAllowed("user1"));
    try testing.expect(try limiter.isAllowed("user1"));
    try testing.expect(!try limiter.isAllowed("user1"));
}

test "RateLimiter.reset clears user limit" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var limiter = RateLimiter.init(allocator, 2, 60000);
    defer limiter.deinit();

    _ = try limiter.isAllowed("user1");
    _ = try limiter.isAllowed("user1");
    try testing.expect(!try limiter.isAllowed("user1"));

    limiter.reset("user1");
    try testing.expect(try limiter.isAllowed("user1"));
}
