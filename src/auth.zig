const std = @import("std");
const constants = @import("constants.zig");
const Config = @import("config.zig").Config;
const Context = @import("context.zig").Context;
const utils = @import("utils.zig");
const router_mod = @import("router.zig");

pub const AuthError = error{
    InvalidCredentials,
    TokenExpired,
    TokenInvalid,
    UserNotFound,
    PasswordMismatch,
    Unauthorized,
    SessionExpired,
    OutOfMemory,
};

pub const User = struct {
    id: []const u8,
    username: []const u8,
    email: ?[]const u8,
    password_hash: []const u8,
    is_active: bool,
    is_authenticated: bool,
    roles: []const []const u8,
    created_at: i64,
    last_login: ?i64,

    pub fn init(id: []const u8, username: []const u8) User {
        return User{
            .id = id,
            .username = username,
            .email = null,
            .password_hash = "",
            .is_active = true,
            .is_authenticated = false,
            .roles = &[_][]const u8{},
            .created_at = utils.timestamp(),
            .last_login = null,
        };
    }

    pub fn hasRole(self: *const User, role: []const u8) bool {
        for (self.roles) |r| {
            if (std.mem.eql(u8, r, role)) return true;
        }
        return false;
    }

    pub fn isAdmin(self: *const User) bool {
        return self.hasRole("admin");
    }
};

pub const Token = struct {
    value: []const u8,
    user_id: []const u8,
    expires_at: i64,
    created_at: i64,
    token_type: TokenType,

    pub const TokenType = enum {
        access,
        refresh,
        api_key,
    };

    pub fn isExpired(self: *const Token) bool {
        return std.time.timestamp() > self.expires_at;
    }
};

pub const PasswordHasher = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PasswordHasher {
        return PasswordHasher{ .allocator = allocator };
    }

    pub fn hash(self: *PasswordHasher, password: []const u8, salt: []const u8) ![]u8 {
        var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(salt);
        hmac.update(password);
        var result: [32]u8 = undefined;
        hmac.final(&result);
        const encoder = std.base64.url_safe_no_pad.Encoder;
        const encoded_len = encoder.calcSize(result.len);
        const out = try self.allocator.alloc(u8, encoded_len);
        _ = encoder.encode(out, &result);
        return out;
    }

    pub fn verify(self: *PasswordHasher, password: []const u8, salt: []const u8, hashed: []const u8) !bool {
        const computed = try self.hash(password, salt);
        defer self.allocator.free(computed);
        return std.mem.eql(u8, computed, hashed);
    }

    pub fn generateSalt(self: *PasswordHasher) ![]u8 {
        var buf: [16]u8 = undefined;
        std.crypto.random.bytes(&buf);
        const encoder = std.base64.url_safe_no_pad.Encoder;
        const encoded_len = encoder.calcSize(buf.len);
        const out = try self.allocator.alloc(u8, encoded_len);
        _ = encoder.encode(out, &buf);
        return out;
    }
};

pub const TokenManager = struct {
    allocator: std.mem.Allocator,
    secret_key: []const u8,
    access_token_lifetime: i64,
    refresh_token_lifetime: i64,

    pub fn init(allocator: std.mem.Allocator, secret_key: []const u8) TokenManager {
        return TokenManager{
            .allocator = allocator,
            .secret_key = secret_key,
            .access_token_lifetime = constants.Auth.default_token_lifetime,
            .refresh_token_lifetime = constants.Auth.refresh_token_lifetime,
        };
    }

    pub fn createAccessToken(self: *TokenManager, user_id: []const u8) ![]u8 {
        return self.createToken(user_id, self.access_token_lifetime, .access);
    }

    pub fn createRefreshToken(self: *TokenManager, user_id: []const u8) ![]u8 {
        return self.createToken(user_id, self.refresh_token_lifetime, .refresh);
    }

    fn createToken(self: *TokenManager, user_id: []const u8, lifetime: i64, token_type: Token.TokenType) ![]u8 {
        _ = token_type;
        const now = std.time.timestamp();
        const expires = now + lifetime;
        var random_bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        const payload = try std.fmt.allocPrint(self.allocator, "{s}|{d}|{d}|{x}", .{ user_id, now, expires, std.fmt.fmtSliceHexLower(&random_bytes) });
        defer self.allocator.free(payload);
        return utils.sign(self.allocator, payload, self.secret_key);
    }

    pub fn verifyToken(self: *TokenManager, token: []const u8) !?Token {
        const payload = try utils.verify(self.allocator, token, self.secret_key) orelse return null;
        defer self.allocator.free(payload);
        var it = std.mem.splitScalar(u8, payload, '|');
        const user_id = it.next() orelse return null;
        const created_str = it.next() orelse return null;
        const expires_str = it.next() orelse return null;
        const created = std.fmt.parseInt(i64, created_str, 10) catch return null;
        const expires = std.fmt.parseInt(i64, expires_str, 10) catch return null;
        if (std.time.timestamp() > expires) return null;
        return Token{
            .value = token,
            .user_id = try self.allocator.dupe(u8, user_id),
            .expires_at = expires,
            .created_at = created,
            .token_type = .access,
        };
    }
};

pub const LoginManager = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    token_manager: TokenManager,
    password_hasher: PasswordHasher,
    login_view: ?[]const u8,
    login_message: []const u8,
    session_protection: SessionProtection,

    pub const SessionProtection = enum {
        none,
        basic,
        strong,
    };

    pub fn init(allocator: std.mem.Allocator, config: *const Config) LoginManager {
        const secret = config.secret_key orelse "default-secret";
        return LoginManager{
            .allocator = allocator,
            .config = config,
            .token_manager = TokenManager.init(allocator, secret),
            .password_hasher = PasswordHasher.init(allocator),
            .login_view = constants.Auth.default_login_view,
            .login_message = "Please log in to access this page.",
            .session_protection = .basic,
        };
    }

    pub fn setLoginView(self: *LoginManager, view: []const u8) void {
        self.login_view = view;
    }

    pub fn loginUser(self: *LoginManager, ctx: *Context, user_id: []const u8, remember: bool) !void {
        const key = try self.allocator.dupe(u8, constants.Auth.session_key_user_id);
        const val = try self.allocator.dupe(u8, user_id);
        try ctx.session.put(key, val);
        const auth_key = try self.allocator.dupe(u8, constants.Auth.session_key_authenticated);
        const auth_val = try self.allocator.dupe(u8, "true");
        try ctx.session.put(auth_key, auth_val);
        if (remember) {
            const rem_key = try self.allocator.dupe(u8, constants.Auth.session_key_remember);
            const rem_val = try self.allocator.dupe(u8, "true");
            try ctx.session.put(rem_key, rem_val);
        }
    }

    pub fn logoutUser(self: *LoginManager, ctx: *Context) void {
        _ = self;
        _ = ctx.session.remove(constants.Auth.session_key_user_id);
        _ = ctx.session.remove(constants.Auth.session_key_authenticated);
        _ = ctx.session.remove(constants.Auth.session_key_remember);
    }

    pub fn getCurrentUserId(self: *LoginManager, ctx: *Context) ?[]const u8 {
        _ = self;
        return ctx.session.get(constants.Auth.session_key_user_id);
    }

    pub fn isAuthenticated(self: *LoginManager, ctx: *Context) bool {
        _ = self;
        if (ctx.session.get(constants.Auth.session_key_authenticated)) |val| {
            return std.mem.eql(u8, val, "true");
        }
        return false;
    }

    pub fn hashPassword(self: *LoginManager, password: []const u8) !struct { hash: []u8, salt: []u8 } {
        const salt = try self.password_hasher.generateSalt();
        const hash = try self.password_hasher.hash(password, salt);
        return .{ .hash = hash, .salt = salt };
    }

    pub fn checkPassword(self: *LoginManager, password: []const u8, salt: []const u8, hashed: []const u8) !bool {
        return self.password_hasher.verify(password, salt, hashed);
    }

    pub fn createToken(self: *LoginManager, user_id: []const u8) ![]u8 {
        return self.token_manager.createAccessToken(user_id);
    }

    pub fn verifyToken(self: *LoginManager, token: []const u8) !?Token {
        return self.token_manager.verifyToken(token);
    }

    pub fn unauthorized(self: *LoginManager, ctx: *Context) !void {
        if (self.login_view) |view| {
            try ctx.redirect(view);
        } else {
            try ctx.unauthorized();
        }
    }
};

pub fn loginRequired() router_mod.MiddlewareFn {
    return struct {
        fn middleware(ctx: *Context, next: router_mod.NextFn) !void {
            if (ctx.session.get(constants.Auth.session_key_authenticated)) |val| {
                if (std.mem.eql(u8, val, "true")) {
                    try next(ctx);
                    return;
                }
            }
            if (ctx.header("Authorization")) |auth_header| {
                if (std.mem.startsWith(u8, auth_header, constants.Auth.bearer_prefix)) {
                    try next(ctx);
                    return;
                }
            }
            try ctx.unauthorized();
        }
    }.middleware;
}

pub fn adminRequired() router_mod.MiddlewareFn {
    return struct {
        fn middleware(ctx: *Context, next: router_mod.NextFn) !void {
            if (ctx.session.get(constants.Auth.session_key_role)) |role| {
                if (std.mem.eql(u8, role, "admin")) {
                    try next(ctx);
                    return;
                }
            }
            try ctx.forbidden();
        }
    }.middleware;
}

pub fn roleRequired(required_role: []const u8) router_mod.MiddlewareFn {
    _ = required_role;
    return struct {
        fn middleware(ctx: *Context, next: router_mod.NextFn) !void {
            if (ctx.session.get(constants.Auth.session_key_role)) |_| {
                try next(ctx);
                return;
            }
            try ctx.forbidden();
        }
    }.middleware;
}

pub fn basicAuth(realm: []const u8) router_mod.MiddlewareFn {
    _ = realm;
    return struct {
        fn middleware(ctx: *Context, next: router_mod.NextFn) !void {
            if (ctx.header("Authorization")) |auth_header| {
                if (std.mem.startsWith(u8, auth_header, constants.Auth.basic_prefix)) {
                    try next(ctx);
                    return;
                }
            }
            try ctx.setHeader("WWW-Authenticate", "Basic realm=\"Protected\"");
            try ctx.unauthorized();
        }
    }.middleware;
}

pub fn apiKeyAuth(header_name: []const u8) router_mod.MiddlewareFn {
    _ = header_name;
    return struct {
        fn middleware(ctx: *Context, next: router_mod.NextFn) !void {
            if (ctx.header(constants.Auth.api_key_header)) |_| {
                try next(ctx);
                return;
            }
            try ctx.unauthorized();
        }
    }.middleware;
}

test "PasswordHasher.hash produces consistent results" {
    const allocator = std.testing.allocator;
    var hasher = PasswordHasher.init(allocator);
    const hash1 = try hasher.hash("password123", "salt123");
    defer allocator.free(hash1);
    const hash2 = try hasher.hash("password123", "salt123");
    defer allocator.free(hash2);
    try std.testing.expectEqualStrings(hash1, hash2);
}

test "PasswordHasher.verify validates correct password" {
    const allocator = std.testing.allocator;
    var hasher = PasswordHasher.init(allocator);
    const hash = try hasher.hash("mypassword", "mysalt");
    defer allocator.free(hash);
    try std.testing.expect(try hasher.verify("mypassword", "mysalt", hash));
    try std.testing.expect(!try hasher.verify("wrongpassword", "mysalt", hash));
}

test "PasswordHasher.generateSalt produces unique salts" {
    const allocator = std.testing.allocator;
    var hasher = PasswordHasher.init(allocator);
    const salt1 = try hasher.generateSalt();
    defer allocator.free(salt1);
    const salt2 = try hasher.generateSalt();
    defer allocator.free(salt2);
    try std.testing.expect(!std.mem.eql(u8, salt1, salt2));
}

test "TokenManager.createAccessToken creates valid token" {
    const allocator = std.testing.allocator;
    var manager = TokenManager.init(allocator, "test-secret");
    const token = try manager.createAccessToken("user123");
    defer allocator.free(token);
    try std.testing.expect(token.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, token, ".") != null);
}

test "TokenManager.verifyToken validates token" {
    const allocator = std.testing.allocator;
    var manager = TokenManager.init(allocator, "test-secret");
    const token = try manager.createAccessToken("user123");
    defer allocator.free(token);
    const verified = try manager.verifyToken(token);
    try std.testing.expect(verified != null);
    if (verified) |v| {
        defer allocator.free(v.user_id);
        try std.testing.expectEqualStrings("user123", v.user_id);
    }
}

test "User.init creates user" {
    const user = User.init("1", "testuser");
    try std.testing.expectEqualStrings("1", user.id);
    try std.testing.expectEqualStrings("testuser", user.username);
    try std.testing.expect(user.is_active);
    try std.testing.expect(!user.is_authenticated);
}

test "User.hasRole checks roles" {
    var roles = [_][]const u8{ "user", "admin" };
    var user = User.init("1", "testuser");
    user.roles = &roles;
    try std.testing.expect(user.hasRole("admin"));
    try std.testing.expect(user.hasRole("user"));
    try std.testing.expect(!user.hasRole("superadmin"));
}

test "LoginManager.init creates manager" {
    const allocator = std.testing.allocator;
    var config = Config{ .secret_key = "test-secret" };
    const manager = LoginManager.init(allocator, &config);
    try std.testing.expectEqualStrings("/login", manager.login_view.?);
}
