const std = @import("std");
const config = @import("config.zig");
const constants = @import("constants.zig");
const utils = @import("utils.zig");

pub const LoggerFn = *const fn (level: Level, message: []const u8, timestamp: i64) void;

pub const Level = enum(u8) {
    trace = 0,
    debug = 1,
    info = 2,
    warn = 3,
    err = 4,
    fatal = 5,
    off = 6,

    pub fn toString(self: Level) []const u8 {
        return switch (self) {
            .trace => "TRACE",
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
            .fatal => "FATAL",
            .off => "OFF",
        };
    }

    pub fn toShort(self: Level) []const u8 {
        return switch (self) {
            .trace => "TRC",
            .debug => "DBG",
            .info => "INF",
            .warn => "WRN",
            .err => "ERR",
            .fatal => "FTL",
            .off => "OFF",
        };
    }

    pub fn fromString(s: []const u8) ?Level {
        return level_map.get(s);
    }

    const level_map = std.StaticStringMap(Level).initComptime(.{
        .{ "trace", .trace },
        .{ "TRACE", .trace },
        .{ "debug", .debug },
        .{ "DEBUG", .debug },
        .{ "info", .info },
        .{ "INFO", .info },
        .{ "warn", .warn },
        .{ "WARN", .warn },
        .{ "warning", .warn },
        .{ "WARNING", .warn },
        .{ "error", .err },
        .{ "ERROR", .err },
        .{ "err", .err },
        .{ "ERR", .err },
        .{ "fatal", .fatal },
        .{ "FATAL", .fatal },
        .{ "off", .off },
        .{ "OFF", .off },
    });
};

pub const Logger = struct {
    allocator: std.mem.Allocator,
    level: Level,
    enabled: bool,
    external_logger: ?LoggerFn,
    use_colors: bool,
    show_timestamp: bool,
    show_level: bool,
    show_source: bool,
    prefix: ?[]const u8,
    format: Format,
    request_count: u64,
    error_count: u64,

    pub const Format = enum {
        text,
        json,
        compact,
    };

    pub fn init(allocator: std.mem.Allocator, cfg: *const config.Config) Logger {
        return Logger{
            .allocator = allocator,
            .level = if (cfg.debug_mode) .debug else .info,
            .enabled = cfg.enable_logging,
            .external_logger = null,
            .use_colors = true,
            .show_timestamp = true,
            .show_level = true,
            .show_source = cfg.debug_mode,
            .prefix = null,
            .format = .text,
            .request_count = 0,
            .error_count = 0,
        };
    }

    pub fn initSimple(allocator: std.mem.Allocator, enabled: bool) Logger {
        return Logger{
            .allocator = allocator,
            .level = .info,
            .enabled = enabled,
            .external_logger = null,
            .use_colors = true,
            .show_timestamp = true,
            .show_level = true,
            .show_source = false,
            .prefix = null,
            .format = .text,
            .request_count = 0,
            .error_count = 0,
        };
    }

    pub fn deinit(self: *Logger) void {
        if (self.prefix) |p| {
            self.allocator.free(p);
        }
    }

    pub fn setExternalLogger(self: *Logger, logger_fn: LoggerFn) void {
        self.external_logger = logger_fn;
    }

    pub fn clearExternalLogger(self: *Logger) void {
        self.external_logger = null;
    }

    pub fn setLevel(self: *Logger, level: Level) void {
        self.level = level;
    }

    pub fn setEnabled(self: *Logger, enabled: bool) void {
        self.enabled = enabled;
    }

    pub fn setColors(self: *Logger, use_colors: bool) void {
        self.use_colors = use_colors;
    }

    pub fn setTimestamp(self: *Logger, show_timestamp: bool) void {
        self.show_timestamp = show_timestamp;
    }

    pub fn setFormat(self: *Logger, format: Format) void {
        self.format = format;
    }

    pub fn setPrefix(self: *Logger, prefix: []const u8) !void {
        if (self.prefix) |p| {
            self.allocator.free(p);
        }
        self.prefix = try self.allocator.dupe(u8, prefix);
    }

    pub fn shouldLog(self: *const Logger, level: Level) bool {
        if (!self.enabled) return false;
        return @intFromEnum(level) >= @intFromEnum(self.level);
    }

    fn getLevelColor(level: Level) []const u8 {
        return switch (level) {
            .trace => constants.Logger.color_trace,
            .debug => constants.Logger.color_debug,
            .info => constants.Logger.color_info,
            .warn => constants.Logger.color_warn,
            .err => constants.Logger.color_err,
            .fatal => constants.Logger.color_fatal,
            .off => "",
        };
    }

    fn log(self: *Logger, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (!self.shouldLog(level)) return;

        const ts = utils.timestamp();

        if (level == .err or level == .fatal) {
            self.error_count += 1;
        }

        if (self.external_logger) |ext_logger| {
            var buf: [4096]u8 = undefined;
            const message = std.fmt.bufPrint(&buf, fmt, args) catch return;
            ext_logger(level, message, ts);
            return;
        }

        const reset = constants.Logger.color_reset;
        const dim = constants.Logger.color_dim;

        switch (self.format) {
            .json => {
                std.debug.print("{{\"timestamp\":{d},\"level\":\"{s}\",\"message\":\"", .{ ts, level.toString() });
                std.debug.print(fmt, args);
                std.debug.print("\"}}\n", .{});
            },
            .compact => {
                if (self.use_colors) {
                    std.debug.print("{s}[{s}]{s} ", .{ getLevelColor(level), level.toShort(), reset });
                } else {
                    std.debug.print("[{s}] ", .{level.toShort()});
                }
                std.debug.print(fmt ++ "\n", args);
            },
            .text => {
                if (self.use_colors) {
                    const color = getLevelColor(level);

                    if (self.show_timestamp) {
                        std.debug.print("{s}{d}{s} ", .{ dim, ts, reset });
                    }

                    std.debug.print("{s}[{s}]{s} ", .{ color, level.toString(), reset });
                } else {
                    if (self.show_timestamp) {
                        std.debug.print("{d} ", .{ts});
                    }
                    std.debug.print("[{s}] ", .{level.toString()});
                }

                if (self.prefix) |p| {
                    std.debug.print("{s}: ", .{p});
                }

                std.debug.print(fmt ++ "\n", args);
            },
        }
    }

    pub fn trace(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.trace, fmt, args);
    }

    pub fn debug(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.debug, fmt, args);
    }

    pub fn info(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.info, fmt, args);
    }

    pub fn warn(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.warn, fmt, args);
    }

    pub fn err(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.err, fmt, args);
    }

    pub fn fatal(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.fatal, fmt, args);
    }

    pub fn request(self: *Logger, method: []const u8, path: []const u8, status: u16, duration_ms: u64) void {
        if (!self.shouldLog(.info)) return;

        self.request_count += 1;

        const status_color = if (self.use_colors) blk: {
            if (status < 300) break :blk constants.Logger.color_info;
            if (status < 400) break :blk constants.Logger.color_debug;
            if (status < 500) break :blk constants.Logger.color_warn;
            break :blk constants.Logger.color_err;
        } else "";

        const reset = if (self.use_colors) constants.Logger.color_reset else "";
        const bold = if (self.use_colors) constants.Logger.color_bold else "";
        const dim = if (self.use_colors) constants.Logger.color_dim else "";

        std.debug.print("{s}{s}{s} {s} {s}->{s} {s}{d}{s} {s}({d}ms){s}\n", .{
            bold,         method,      reset,
            path,         dim,         reset,
            status_color, status,      reset,
            dim,          duration_ms, reset,
        });
    }

    pub fn serverStart(self: *Logger, addr: []const u8, port: u16) void {
        if (!self.shouldLog(.info)) return;

        std.debug.print("\nServing the site on http://{s}:{d}\n\n", .{ addr, port });
    }

    pub fn serverStop(self: *Logger) void {
        if (!self.shouldLog(.info)) return;

        std.debug.print("\nServer shutting down...\n", .{});
        std.debug.print("   Requests handled: {d}\n", .{self.request_count});
        std.debug.print("   Errors logged: {d}\n\n", .{self.error_count});
    }

    pub fn routeRegistered(self: *Logger, method: []const u8, path: []const u8) void {
        if (!self.shouldLog(.debug)) return;
        std.debug.print("  -> {s} {s}\n", .{ method, path });
    }

    pub fn middlewareAdded(self: *Logger, name: []const u8) void {
        if (!self.shouldLog(.debug)) return;
        std.debug.print("  <> Middleware: {s}\n", .{name});
    }

    pub fn getStats(self: *const Logger) LogStats {
        return LogStats{
            .request_count = self.request_count,
            .error_count = self.error_count,
        };
    }

    pub fn resetStats(self: *Logger) void {
        self.request_count = 0;
        self.error_count = 0;
    }
};

pub const LogStats = struct {
    request_count: u64,
    error_count: u64,
};

test "Level.fromString" {
    const testing = std.testing;
    try testing.expectEqual(Level.info, Level.fromString("info").?);
    try testing.expectEqual(Level.info, Level.fromString("INFO").?);
    try testing.expectEqual(Level.err, Level.fromString("error").?);
    try testing.expectEqual(Level.warn, Level.fromString("warning").?);
    try testing.expect(Level.fromString("invalid") == null);
}

test "Level.toString" {
    const testing = std.testing;
    try testing.expectEqualStrings("INFO", Level.info.toString());
    try testing.expectEqualStrings("ERROR", Level.err.toString());
    try testing.expectEqualStrings("DEBUG", Level.debug.toString());
}

test "Logger.shouldLog" {
    const testing = std.testing;
    const cfg = config.Config{};

    var logger = Logger.init(testing.allocator, &cfg);
    defer logger.deinit();

    logger.setLevel(.info);
    try testing.expect(logger.shouldLog(.info));
    try testing.expect(logger.shouldLog(.warn));
    try testing.expect(logger.shouldLog(.err));
    try testing.expect(!logger.shouldLog(.debug));
    try testing.expect(!logger.shouldLog(.trace));
}

test "Logger.setEnabled" {
    const testing = std.testing;

    var logger = Logger.initSimple(testing.allocator, true);
    defer logger.deinit();

    try testing.expect(logger.shouldLog(.info));

    logger.setEnabled(false);
    try testing.expect(!logger.shouldLog(.info));
}

test "Logger statistics" {
    const testing = std.testing;

    var logger = Logger.initSimple(testing.allocator, false);
    defer logger.deinit();

    const stats = logger.getStats();
    try testing.expectEqual(@as(u64, 0), stats.request_count);
    try testing.expectEqual(@as(u64, 0), stats.error_count);
}
