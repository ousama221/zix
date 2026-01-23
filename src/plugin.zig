const std = @import("std");
const constants = @import("constants.zig");
const Config = @import("config.zig").Config;
const Context = @import("context.zig").Context;
const router_mod = @import("router.zig");
const utils = @import("utils.zig");

pub const PluginError = error{
    PluginNotFound,
    PluginAlreadyRegistered,
    PluginInitFailed,
    PluginDisabled,
    HookNotFound,
    InvalidCallback,
    OutOfMemory,
};

pub const PluginState = enum {
    uninitialized,
    initialized,
    enabled,
    disabled,
    error_state,
};

pub const HookType = enum {
    before_request,
    after_request,
    before_response,
    after_response,
    on_error,
    on_startup,
    on_shutdown,
    on_route_match,
    on_template_render,
    on_static_serve,
    custom,
};

pub const HookFn = *const fn (*Context, ?*anyopaque) anyerror!void;
pub const InitFn = *const fn (*PluginManager, *const Config) anyerror!void;
pub const CleanupFn = *const fn (*PluginManager) void;

pub const Plugin = struct {
    name: []const u8,
    version: []const u8,
    description: []const u8,
    author: []const u8,
    state: PluginState,
    priority: i32,
    config: ?*anyopaque,
    init_fn: ?InitFn,
    cleanup_fn: ?CleanupFn,
    hooks: std.StringHashMap(HookFn),

    pub fn init(allocator: std.mem.Allocator, name: []const u8) Plugin {
        return Plugin{
            .name = name,
            .version = "1.0.0",
            .description = "",
            .author = "",
            .state = .uninitialized,
            .priority = 0,
            .config = null,
            .init_fn = null,
            .cleanup_fn = null,
            .hooks = std.StringHashMap(HookFn).init(allocator),
        };
    }

    pub fn deinit(self: *Plugin) void {
        self.hooks.deinit();
    }

    pub fn setVersion(self: *Plugin, version: []const u8) *Plugin {
        self.version = version;
        return self;
    }

    pub fn setDescription(self: *Plugin, description: []const u8) *Plugin {
        self.description = description;
        return self;
    }

    pub fn setAuthor(self: *Plugin, author: []const u8) *Plugin {
        self.author = author;
        return self;
    }

    pub fn setPriority(self: *Plugin, priority: i32) *Plugin {
        self.priority = priority;
        return self;
    }

    pub fn setInitFn(self: *Plugin, init_fn: InitFn) *Plugin {
        self.init_fn = init_fn;
        return self;
    }

    pub fn setCleanupFn(self: *Plugin, cleanup_fn: CleanupFn) *Plugin {
        self.cleanup_fn = cleanup_fn;
        return self;
    }

    pub fn registerHook(self: *Plugin, hook_name: []const u8, callback: HookFn) !void {
        try self.hooks.put(hook_name, callback);
    }

    pub fn unregisterHook(self: *Plugin, hook_name: []const u8) void {
        _ = self.hooks.remove(hook_name);
    }

    pub fn hasHook(self: *const Plugin, hook_name: []const u8) bool {
        return self.hooks.contains(hook_name);
    }

    pub fn enable(self: *Plugin) void {
        self.state = .enabled;
    }

    pub fn disable(self: *Plugin) void {
        self.state = .disabled;
    }

    pub fn isEnabled(self: *const Plugin) bool {
        return self.state == .enabled;
    }
};

pub const PluginManager = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    plugins: std.StringHashMap(*Plugin),
    hook_registry: std.StringHashMap(std.ArrayList(HookEntry)),
    enabled: bool,

    const HookEntry = struct {
        plugin_name: []const u8,
        callback: HookFn,
        priority: i32,
    };

    pub fn init(allocator: std.mem.Allocator, config: *const Config) PluginManager {
        return PluginManager{
            .allocator = allocator,
            .config = config,
            .plugins = std.StringHashMap(*Plugin).init(allocator),
            .hook_registry = std.StringHashMap(std.ArrayList(HookEntry)).init(allocator),
            .enabled = true,
        };
    }

    pub fn deinit(self: *PluginManager) void {
        var plugin_it = self.plugins.iterator();
        while (plugin_it.next()) |entry| {
            if (entry.value_ptr.*.cleanup_fn) |cleanup| {
                cleanup(self);
            }
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.plugins.deinit();
        var hook_it = self.hook_registry.iterator();
        while (hook_it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.hook_registry.deinit();
    }

    pub fn register(self: *PluginManager, plugin: *Plugin) !void {
        if (self.plugins.contains(plugin.name)) {
            return PluginError.PluginAlreadyRegistered;
        }
        try self.plugins.put(plugin.name, plugin);
        if (plugin.init_fn) |init_fn| {
            init_fn(self, self.config) catch {
                plugin.state = .error_state;
                return PluginError.PluginInitFailed;
            };
        }
        plugin.state = .initialized;
    }

    pub fn unregister(self: *PluginManager, name: []const u8) !void {
        if (self.plugins.fetchRemove(name)) |entry| {
            if (entry.value.cleanup_fn) |cleanup| {
                cleanup(self);
            }
            entry.value.deinit();
            self.allocator.destroy(entry.value);
        } else {
            return PluginError.PluginNotFound;
        }
    }

    pub fn get(self: *PluginManager, name: []const u8) ?*Plugin {
        return self.plugins.get(name);
    }

    pub fn enable(self: *PluginManager, name: []const u8) !void {
        if (self.plugins.get(name)) |plugin| {
            plugin.enable();
        } else {
            return PluginError.PluginNotFound;
        }
    }

    pub fn disable(self: *PluginManager, name: []const u8) !void {
        if (self.plugins.get(name)) |plugin| {
            plugin.disable();
        } else {
            return PluginError.PluginNotFound;
        }
    }

    pub fn registerHook(self: *PluginManager, hook_name: []const u8, plugin_name: []const u8, callback: HookFn, priority: i32) !void {
        const hook_list_ptr = try self.hook_registry.getOrPut(hook_name);
        if (!hook_list_ptr.found_existing) {
            hook_list_ptr.value_ptr.* = .empty;
        }
        try hook_list_ptr.value_ptr.append(self.allocator, .{
            .plugin_name = plugin_name,
            .callback = callback,
            .priority = priority,
        });
    }

    pub fn executeHook(self: *PluginManager, hook_name: []const u8, ctx: *Context, data: ?*anyopaque) !void {
        if (!self.enabled) return;
        if (self.hook_registry.get(hook_name)) |entries| {
            for (entries.items) |entry| {
                if (self.plugins.get(entry.plugin_name)) |plugin| {
                    if (plugin.isEnabled()) {
                        try entry.callback(ctx, data);
                    }
                }
            }
        }
    }

    pub fn count(self: *const PluginManager) usize {
        return self.plugins.count();
    }

    pub fn list(self: *PluginManager, allocator: std.mem.Allocator) ![][]const u8 {
        var names = std.ArrayList([]const u8){};
        defer names.deinit(allocator);
        var it = self.plugins.iterator();
        while (it.next()) |entry| {
            try names.append(allocator, entry.key_ptr.*);
        }
        return names.toOwnedSlice(allocator);
    }
};

pub const ExternalLogger = struct {
    name: []const u8,
    log_fn: *const fn (level: LogLevel, message: []const u8, context: ?*anyopaque) void,
    context: ?*anyopaque,

    pub const LogLevel = enum {
        trace,
        debug,
        info,
        warn,
        err,
        fatal,
    };

    pub fn log(self: *const ExternalLogger, level: LogLevel, message: []const u8) void {
        self.log_fn(level, message, self.context);
    }
};

pub const LoggerRegistry = struct {
    allocator: std.mem.Allocator,
    loggers: std.ArrayList(ExternalLogger),

    pub fn init(allocator: std.mem.Allocator) LoggerRegistry {
        return LoggerRegistry{
            .allocator = allocator,
            .loggers = .empty,
        };
    }

    pub fn deinit(self: *LoggerRegistry) void {
        self.loggers.deinit(self.allocator);
    }

    pub fn register(self: *LoggerRegistry, logger: ExternalLogger) !void {
        try self.loggers.append(self.allocator, logger);
    }

    pub fn broadcast(self: *LoggerRegistry, level: ExternalLogger.LogLevel, message: []const u8) void {
        for (self.loggers.items) |logger| {
            logger.log(level, message);
        }
    }
};

pub fn createPlugin(allocator: std.mem.Allocator, name: []const u8) !*Plugin {
    const plugin = try allocator.create(Plugin);
    plugin.* = Plugin.init(allocator, name);
    return plugin;
}

pub fn pluginMiddleware(plugin_manager: *PluginManager, hook_name: []const u8) router_mod.MiddlewareFn {
    _ = plugin_manager;
    _ = hook_name;
    return struct {
        fn middleware(ctx: *Context, next: router_mod.NextFn) !void {
            try next(ctx);
        }
    }.middleware;
}

test "Plugin.init creates plugin" {
    const allocator = std.testing.allocator;
    var plugin = Plugin.init(allocator, "test-plugin");
    defer plugin.deinit();
    try std.testing.expectEqualStrings("test-plugin", plugin.name);
    try std.testing.expect(plugin.state == .uninitialized);
}

test "Plugin.setVersion sets version" {
    const allocator = std.testing.allocator;
    var plugin = Plugin.init(allocator, "test");
    defer plugin.deinit();
    _ = plugin.setVersion("2.0.0");
    try std.testing.expectEqualStrings("2.0.0", plugin.version);
}

test "Plugin.enable and disable work" {
    const allocator = std.testing.allocator;
    var plugin = Plugin.init(allocator, "test");
    defer plugin.deinit();
    plugin.enable();
    try std.testing.expect(plugin.isEnabled());
    plugin.disable();
    try std.testing.expect(!plugin.isEnabled());
}

test "PluginManager.init creates manager" {
    const allocator = std.testing.allocator;
    var config = Config{};
    var manager = PluginManager.init(allocator, &config);
    defer manager.deinit();
    try std.testing.expect(manager.enabled);
    try std.testing.expectEqual(@as(usize, 0), manager.count());
}

test "PluginManager.register adds plugin" {
    const allocator = std.testing.allocator;
    var config = Config{};
    var manager = PluginManager.init(allocator, &config);
    defer manager.deinit();
    const plugin = try createPlugin(allocator, "my-plugin");
    try manager.register(plugin);
    try std.testing.expectEqual(@as(usize, 1), manager.count());
}

test "LoggerRegistry.init creates registry" {
    const allocator = std.testing.allocator;
    var registry = LoggerRegistry.init(allocator);
    defer registry.deinit();
    try std.testing.expectEqual(@as(usize, 0), registry.loggers.items.len);
}
