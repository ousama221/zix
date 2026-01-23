const std = @import("std");
const builtin = @import("builtin");
const logger = @import("logger.zig");

pub const WatchCallback = *const fn (path: []const u8) void;

pub const FileWatcher = struct {
    allocator: std.mem.Allocator,
    directories: std.ArrayList([]const u8),
    callback: WatchCallback,
    running: bool,
    interval_ms: u64,
    thread: ?std.Thread,
    snapshots: std.StringHashMap(i128),

    pub fn init(allocator: std.mem.Allocator, callback: WatchCallback) FileWatcher {
        return FileWatcher{
            .allocator = allocator,
            .directories = .empty,
            .callback = callback,
            .running = false,
            .interval_ms = 1000,
            .thread = null,
            .snapshots = std.StringHashMap(i128).init(allocator),
        };
    }

    pub fn deinit(self: *FileWatcher) void {
        self.stop();
        for (self.directories.items) |dir| {
            self.allocator.free(dir);
        }
        self.directories.deinit(self.allocator);
        var it = self.snapshots.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.snapshots.deinit();
    }

    pub fn addDirectory(self: *FileWatcher, path: []const u8) !void {
        const duped = try self.allocator.dupe(u8, path);
        try self.directories.append(self.allocator, duped);
    }

    pub fn start(self: *FileWatcher) !void {
        if (self.running) return;
        self.running = true;

        try self.scan(false);

        self.thread = try std.Thread.spawn(.{}, runLoop, .{self});
    }

    pub fn stop(self: *FileWatcher) void {
        self.running = false;
        if (self.thread) |handle| {
            handle.join();
            self.thread = null;
        }
    }

    fn runLoop(self: *FileWatcher) void {
        while (self.running) {
            if (builtin.os.tag == .windows) {
                std.os.windows.kernel32.Sleep(@intCast(self.interval_ms));
            } else {
                std.time.sleep(self.interval_ms * std.time.ns_per_ms);
            }
            self.scan(true) catch |err| {
                std.debug.print("Watcher error: {any}\n", .{err});
            };
        }
    }

    fn scan(self: *FileWatcher, trigger_events: bool) !void {
        for (self.directories.items) |dir_path| {
            var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch continue;
            defer dir.close();

            var walker = try dir.walk(self.allocator);
            defer walker.deinit();

            while (try walker.next()) |entry| {
                if (entry.kind != .file) continue;

                const full_path = try std.fs.path.join(self.allocator, &[_][]const u8{ dir_path, entry.path });
                defer self.allocator.free(full_path);

                const stat = dir.statFile(entry.path) catch continue;
                const mtime = stat.mtime;

                const result = try self.snapshots.getOrPut(full_path);
                if (!result.found_existing) {
                    result.key_ptr.* = try self.allocator.dupe(u8, full_path);
                    result.value_ptr.* = mtime;
                    if (trigger_events) {
                        self.callback(full_path);
                    }
                } else {
                    if (result.value_ptr.* != mtime) {
                        result.value_ptr.* = mtime;
                        if (trigger_events) {
                            self.callback(full_path);
                        }
                    }
                }
            }
        }
    }
};

test "FileWatcher initializes" {
    const allocator = std.testing.allocator;
    const Callback = struct {
        fn noop(_: []const u8) void {}
    };
    var watcher = FileWatcher.init(allocator, Callback.noop);
    defer watcher.deinit();
    try std.testing.expect(!watcher.running);
}
