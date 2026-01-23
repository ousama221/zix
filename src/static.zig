const std = @import("std");
const constants = @import("constants.zig");
const Config = @import("config.zig").Config;
const Context = @import("context.zig").Context;
const utils = @import("utils.zig");

pub const StaticError = error{
    FileNotFound,
    DirectoryTraversal,
    FileTooLarge,
    ReadError,
    InvalidPath,
    OutOfMemory,
};

pub const StaticFileServer = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    root_dir: []const u8,
    mount_path: []const u8,
    cache: std.StringHashMap(CachedFile),
    cache_enabled: bool,
    cache_max_size: usize,
    current_cache_size: usize,

    pub const CachedFile = struct {
        content: []const u8,
        mime_type: []const u8,
        last_modified: i64,
        size: usize,
    };

    pub fn init(allocator: std.mem.Allocator, config: *const Config) StaticFileServer {
        return StaticFileServer{
            .allocator = allocator,
            .config = config,
            .root_dir = config.static_dir,
            .mount_path = config.static_mount_path,
            .cache = std.StringHashMap(CachedFile).init(allocator),
            .cache_enabled = true,
            .cache_max_size = 50 * 1024 * 1024,
            .current_cache_size = 0,
        };
    }

    pub fn deinit(self: *StaticFileServer) void {
        var it = self.cache.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.content);
        }
        self.cache.deinit();
    }

    pub fn setRootDir(self: *StaticFileServer, dir: []const u8) void {
        self.root_dir = dir;
    }

    pub fn setMountPath(self: *StaticFileServer, path: []const u8) void {
        self.mount_path = path;
    }

    pub fn setCacheEnabled(self: *StaticFileServer, enabled: bool) void {
        self.cache_enabled = enabled;
    }

    pub fn clearCache(self: *StaticFileServer) void {
        var it = self.cache.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.content);
        }
        self.cache.clearRetainingCapacity();
        self.current_cache_size = 0;
    }

    pub fn serve(self: *StaticFileServer, ctx: *Context) !void {
        const request_path = ctx.path();

        if (!std.mem.startsWith(u8, request_path, self.mount_path)) {
            try ctx.notFound();
            return;
        }

        const relative_path = request_path[self.mount_path.len..];
        const trimmed_path = std.mem.trimLeft(u8, relative_path, "/");

        if (utils.isPathTraversal(trimmed_path)) {
            _ = ctx.status(403);
            try ctx.text("Forbidden");
            return;
        }

        if (trimmed_path.len == 0) {
            for (constants.Static.index_files) |index_file| {
                if (self.serveFile(ctx, index_file)) {
                    return;
                } else |_| {}
            }
            try ctx.notFound();
            return;
        }

        self.serveFile(ctx, trimmed_path) catch |err| {
            switch (err) {
                StaticError.FileNotFound => try ctx.notFound(),
                StaticError.DirectoryTraversal => {
                    _ = ctx.status(403);
                    try ctx.text("Forbidden");
                },
                else => try ctx.internalError(),
            }
        };
    }

    fn serveFile(self: *StaticFileServer, ctx: *Context, relative_path: []const u8) !void {
        if (self.cache_enabled) {
            if (self.cache.get(relative_path)) |cached| {
                try self.sendCachedFile(ctx, &cached);
                return;
            }
        }

        const full_path = try utils.joinPaths(self.allocator, self.root_dir, relative_path);
        defer self.allocator.free(full_path);

        const file = std.fs.cwd().openFile(full_path, .{}) catch {
            return StaticError.FileNotFound;
        };
        defer file.close();

        const stat = file.stat() catch {
            return StaticError.ReadError;
        };

        if (stat.size > self.config.max_body_size) {
            return StaticError.FileTooLarge;
        }

        const content = file.readToEndAlloc(self.allocator, self.config.max_body_size) catch {
            return StaticError.ReadError;
        };

        const mime_type = constants.MimeTypes.fromPath(relative_path);

        if (self.cache_enabled and content.len < 1024 * 1024) {
            const key = try self.allocator.dupe(u8, relative_path);
            try self.cache.put(key, CachedFile{
                .content = content,
                .mime_type = mime_type,
                .last_modified = @intCast(stat.mtime),
                .size = content.len,
            });
            self.current_cache_size += content.len;
        }

        try self.sendFile(ctx, content, mime_type);

        if (!self.cache_enabled or content.len >= 1024 * 1024) {
            self.allocator.free(content);
        }
    }

    fn sendFile(self: *StaticFileServer, ctx: *Context, content: []const u8, mime_type: []const u8) !void {
        _ = self;

        _ = ctx.status(200);
        try ctx.setHeader("Content-Type", mime_type);

        var cache_buf: [64]u8 = undefined;
        const cache_control = std.fmt.bufPrint(&cache_buf, "public, max-age={d}", .{ctx.config.static_cache_max_age}) catch "public, max-age=86400";
        try ctx.setHeader("Cache-Control", cache_control);

        try ctx.setHeader("Accept-Ranges", "bytes");

        ctx.response.body.clearRetainingCapacity();
        try ctx.response.body.appendSlice(ctx.allocator, content);
    }

    fn sendCachedFile(self: *StaticFileServer, ctx: *Context, cached: *const CachedFile) !void {
        _ = self;

        const if_modified = ctx.header("If-Modified-Since");
        if (if_modified != null) {
            _ = ctx.status(304);
            return;
        }

        _ = ctx.status(200);
        try ctx.setHeader("Content-Type", cached.mime_type);

        var cache_buf: [64]u8 = undefined;
        const cache_control = std.fmt.bufPrint(&cache_buf, "public, max-age={d}", .{ctx.config.static_cache_max_age}) catch "public, max-age=86400";
        try ctx.setHeader("Cache-Control", cache_control);

        ctx.response.body.clearRetainingCapacity();
        try ctx.response.body.appendSlice(ctx.allocator, cached.content);
    }
};

pub fn serveStatic(allocator: std.mem.Allocator, config: *const Config, root_dir: []const u8, mount_path: []const u8) StaticFileServer {
    var server = StaticFileServer.init(allocator, config);
    server.setRootDir(root_dir);
    server.setMountPath(mount_path);
    return server;
}

pub fn getMimeType(path: []const u8) []const u8 {
    return constants.MimeTypes.fromPath(path);
}

pub fn isValidStaticPath(path: []const u8) bool {
    if (utils.isPathTraversal(path)) {
        return false;
    }

    if (std.mem.indexOf(u8, path, "\x00") != null) {
        return false;
    }

    if (std.mem.indexOf(u8, path, "..") != null) {
        return false;
    }

    return true;
}

test "StaticFileServer.init creates server" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var server = StaticFileServer.init(allocator, &config);
    defer server.deinit();

    try testing.expectEqualStrings(config.static_dir, server.root_dir);
    try testing.expectEqualStrings(config.static_mount_path, server.mount_path);
}

test "StaticFileServer.setRootDir changes directory" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var server = StaticFileServer.init(allocator, &config);
    defer server.deinit();

    server.setRootDir("assets");
    try testing.expectEqualStrings("assets", server.root_dir);
}

test "StaticFileServer.setMountPath changes path" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var server = StaticFileServer.init(allocator, &config);
    defer server.deinit();

    server.setMountPath("/assets");
    try testing.expectEqualStrings("/assets", server.mount_path);
}

test "getMimeType returns correct types" {
    const testing = std.testing;
    try testing.expectEqualStrings("text/html; charset=utf-8", getMimeType("index.html"));
    try testing.expectEqualStrings("text/css; charset=utf-8", getMimeType("style.css"));
    try testing.expectEqualStrings("application/javascript; charset=utf-8", getMimeType("app.js"));
    try testing.expectEqualStrings("image/png", getMimeType("image.png"));
    try testing.expectEqualStrings("application/json; charset=utf-8", getMimeType("data.json"));
}

test "isValidStaticPath rejects traversal attempts" {
    const testing = std.testing;
    try testing.expect(!isValidStaticPath("../etc/passwd"));
    try testing.expect(!isValidStaticPath("..\\windows\\system32"));
    try testing.expect(!isValidStaticPath("foo/../../bar"));
    try testing.expect(isValidStaticPath("images/logo.png"));
    try testing.expect(isValidStaticPath("css/style.css"));
}

test "isValidStaticPath rejects null bytes" {
    const testing = std.testing;
    try testing.expect(!isValidStaticPath("file\x00.txt"));
    try testing.expect(isValidStaticPath("normal-file.txt"));
}

test "StaticFileServer.clearCache empties cache" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var server = StaticFileServer.init(allocator, &config);
    defer server.deinit();

    server.clearCache();
    try testing.expectEqual(@as(usize, 0), server.cache.count());
    try testing.expectEqual(@as(usize, 0), server.current_cache_size);
}

test "StaticFileServer.setCacheEnabled toggles caching" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var config = Config{};
    var server = StaticFileServer.init(allocator, &config);
    defer server.deinit();

    try testing.expect(server.cache_enabled);
    server.setCacheEnabled(false);
    try testing.expect(!server.cache_enabled);
}
