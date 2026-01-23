const std = @import("std");
const constants = @import("constants.zig");
const Config = @import("config.zig").Config;
const Context = @import("context.zig").Context;
const utils = @import("utils.zig");

pub const SessionError = error{
    SessionNotFound,
    SessionExpired,
    SessionInvalid,
    SessionFull,
    SignatureInvalid,
    SerializationError,
    DeserializationError,
    OutOfMemory,
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    id: []const u8,
    data: std.StringHashMap([]const u8),
    created_at: i64,
    accessed_at: i64,
    expires_at: i64,
    modified: bool,
    permanent: bool,

    pub fn init(allocator: std.mem.Allocator) Session {
        const now = std.time.timestamp();
        return Session{
            .allocator = allocator,
            .id = "",
            .data = std.StringHashMap([]const u8).init(allocator),
            .created_at = now,
            .accessed_at = now,
            .expires_at = now + constants.Session.default_max_age,
            .modified = false,
            .permanent = false,
        };
    }

    pub fn deinit(self: *Session) void {
        if (self.id.len > 0) {
            self.allocator.free(self.id);
        }
        var it = self.data.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.data.deinit();
    }

    pub fn get(self: *const Session, key: []const u8) ?[]const u8 {
        return self.data.get(key);
    }

    pub fn put(self: *Session, key: []const u8, value: []const u8) !void {
        const k = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(k);
        const v = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(v);
        if (self.data.fetchRemove(k)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value);
        }
        try self.data.put(k, v);
        self.modified = true;
    }

    pub fn remove(self: *Session, key: []const u8) bool {
        if (self.data.fetchRemove(key)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value);
            self.modified = true;
            return true;
        }
        return false;
    }

    pub fn clear(self: *Session) void {
        var it = self.data.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.data.clearRetainingCapacity();
        self.modified = true;
    }

    pub fn contains(self: *const Session, key: []const u8) bool {
        return self.data.contains(key);
    }

    pub fn count(self: *const Session) usize {
        return self.data.count();
    }

    pub fn isExpired(self: *const Session) bool {
        return std.time.timestamp() > self.expires_at;
    }

    pub fn touch(self: *Session) void {
        self.accessed_at = std.time.timestamp();
    }

    pub fn extend(self: *Session, seconds: i64) void {
        self.expires_at = std.time.timestamp() + seconds;
        self.modified = true;
    }

    pub fn setId(self: *Session, id: []const u8) !void {
        if (self.id.len > 0) {
            self.allocator.free(self.id);
        }
        self.id = try self.allocator.dupe(u8, id);
    }

    pub fn serialize(self: *const Session, allocator: std.mem.Allocator) ![]u8 {
        var json_obj = std.StringArrayHashMap([]const u8).init(allocator);
        defer json_obj.deinit();
        var it = self.data.iterator();
        while (it.next()) |entry| {
            try json_obj.put(entry.key_ptr.*, entry.value_ptr.*);
        }
        return std.json.Stringify.valueAlloc(allocator, json_obj, .{});
    }

    pub fn deserialize(self: *Session, data: []const u8) !void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, data, .{}) catch return error.DeserializationError;
        defer parsed.deinit();
        if (parsed.value != .object) return error.DeserializationError;
        var it = parsed.value.object.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == .string) {
                try self.put(entry.key_ptr.*, entry.value_ptr.string);
            }
        }
    }
};

pub const SessionManager = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    sessions: std.StringHashMap(*Session),
    secret_key: []const u8,

    pub fn init(allocator: std.mem.Allocator, config: *const Config) SessionManager {
        return SessionManager{
            .allocator = allocator,
            .config = config,
            .sessions = std.StringHashMap(*Session).init(allocator),
            .secret_key = config.secret_key orelse "default-secret-key",
        };
    }

    pub fn deinit(self: *SessionManager) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.sessions.deinit();
    }

    pub fn create(self: *SessionManager) !*Session {
        const session = try self.allocator.create(Session);
        session.* = Session.init(self.allocator);
        const id = try self.generateId();
        try session.setId(id);
        self.allocator.free(id);
        const stored_id = try self.allocator.dupe(u8, session.id);
        try self.sessions.put(stored_id, session);
        return session;
    }

    pub fn get(self: *SessionManager, id: []const u8) ?*Session {
        if (self.sessions.get(id)) |session| {
            if (!session.isExpired()) {
                session.touch();
                return session;
            }
            self.destroy(id);
        }
        return null;
    }

    pub fn destroy(self: *SessionManager, id: []const u8) void {
        if (self.sessions.fetchRemove(id)) |entry| {
            self.allocator.free(entry.key);
            entry.value.deinit();
            self.allocator.destroy(entry.value);
        }
    }

    pub fn cleanup(self: *SessionManager) void {
        var to_remove: std.ArrayList([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.isExpired()) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }
        for (to_remove.items) |id| {
            self.destroy(id);
        }
    }

    fn generateId(self: *SessionManager) ![]u8 {
        var buf: [32]u8 = undefined;
        std.crypto.random.bytes(&buf);
        var result: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&result, "{x}", .{std.fmt.fmtSliceHexLower(&buf)}) catch return error.OutOfMemory;
        return self.allocator.dupe(u8, &result);
    }

    pub fn count(self: *const SessionManager) usize {
        return self.sessions.count();
    }
};

pub const CookieSession = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    secret_key: []const u8,

    pub fn init(allocator: std.mem.Allocator, config: *const Config) CookieSession {
        return CookieSession{
            .allocator = allocator,
            .config = config,
            .secret_key = config.secret_key orelse "default-secret-key",
        };
    }

    pub fn load(self: *CookieSession, ctx: *Context) !void {
        const cookie_val = try ctx.request.cookie(self.config.session_cookie_name) orelse return;
        const payload = try utils.verify(self.allocator, cookie_val, self.secret_key) orelse return;
        defer self.allocator.free(payload);
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value == .object) {
            var it = parsed.value.object.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.* == .string) {
                    const key = try self.allocator.dupe(u8, entry.key_ptr.*);
                    const val = try self.allocator.dupe(u8, entry.value_ptr.string);
                    try ctx.session.put(key, val);
                }
            }
        }
    }

    pub fn save(self: *CookieSession, ctx: *Context) !void {
        if (ctx.session.count() == 0) return;
        var json_map = std.StringArrayHashMap([]const u8).init(self.allocator);
        defer json_map.deinit();
        var it = ctx.session.iterator();
        while (it.next()) |entry| {
            try json_map.put(entry.key_ptr.*, entry.value_ptr.*);
        }
        const json_str = try std.json.Stringify.valueAlloc(self.allocator, json_map, .{});
        defer self.allocator.free(json_str);
        const signed = try utils.sign(self.allocator, json_str, self.secret_key);
        defer self.allocator.free(signed);
        try ctx.response.setCookie(.{
            .name = self.config.session_cookie_name,
            .value = signed,
            .max_age = self.config.session_max_age,
            .http_only = self.config.session_http_only,
            .secure = self.config.session_secure,
            .path = "/",
        });
    }
};

pub const FlashMessage = struct {
    category: []const u8,
    message: []const u8,
};

pub fn flash(ctx: *Context, message: []const u8, category: []const u8) !void {
    const key = try std.fmt.allocPrint(ctx.allocator, "_flash_{s}", .{category});
    defer ctx.allocator.free(key);
    try ctx.session.put(key, try ctx.allocator.dupe(u8, message));
}

pub fn getFlashedMessages(ctx: *Context, allocator: std.mem.Allocator) ![]FlashMessage {
    var messages: std.ArrayList(FlashMessage) = .empty;
    var to_remove: std.ArrayList([]const u8) = .empty;
    defer to_remove.deinit(allocator);
    var it = ctx.session.iterator();
    while (it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "_flash_")) {
            const category = entry.key_ptr.*[7..];
            try messages.append(allocator, .{
                .category = try allocator.dupe(u8, category),
                .message = try allocator.dupe(u8, entry.value_ptr.*),
            });
            try to_remove.append(allocator, entry.key_ptr.*);
        }
    }
    for (to_remove.items) |key| {
        _ = ctx.session.remove(key);
    }
    return messages.toOwnedSlice(allocator);
}

test "Session.init creates session" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();
    try std.testing.expect(session.count() == 0);
    try std.testing.expect(!session.isExpired());
}

test "Session.put and get work" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();
    try session.put("key1", "value1");
    try std.testing.expectEqualStrings("value1", session.get("key1").?);
}

test "Session.remove works" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();
    try session.put("key1", "value1");
    try std.testing.expect(session.remove("key1"));
    try std.testing.expect(session.get("key1") == null);
}

test "Session.clear works" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();
    try session.put("key1", "value1");
    try session.put("key2", "value2");
    session.clear();
    try std.testing.expect(session.count() == 0);
}

test "Session.serialize works" {
    const allocator = std.testing.allocator;
    var session = Session.init(allocator);
    defer session.deinit();
    try session.put("name", "test");
    const json = try session.serialize(allocator);
    defer allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "name") != null);
}

test "SessionManager.create creates session" {
    const allocator = std.testing.allocator;
    var config = Config{};
    var manager = SessionManager.init(allocator, &config);
    defer manager.deinit();
    const session = try manager.create();
    try std.testing.expect(session.id.len > 0);
    try std.testing.expect(manager.count() == 1);
}

test "CookieSession.init creates handler" {
    const allocator = std.testing.allocator;
    var config = Config{ .secret_key = "test-secret" };
    const cookie_session = CookieSession.init(allocator, &config);
    try std.testing.expectEqualStrings("test-secret", cookie_session.secret_key);
}
