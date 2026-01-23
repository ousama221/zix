const std = @import("std");

pub const StateError = error{
    KeyNotFound,
    TypeMismatch,
    OutOfMemory,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    data: std.StringHashMap(*anyopaque),
    destructors: std.StringHashMap(*const fn (*anyopaque, std.mem.Allocator) void),

    pub fn init(allocator: std.mem.Allocator) Store {
        return Store{
            .allocator = allocator,
            .data = std.StringHashMap(*anyopaque).init(allocator),
            .destructors = std.StringHashMap(*const fn (*anyopaque, std.mem.Allocator) void).init(allocator),
        };
    }

    pub fn deinit(self: *Store) void {
        var it = self.data.iterator();
        while (it.next()) |entry| {
            if (self.destructors.get(entry.key_ptr.*)) |destructor| {
                destructor(entry.value_ptr.*, self.allocator);
            }
        }
        self.data.deinit();
        self.destructors.deinit();
    }

    pub fn set(self: *Store, key: []const u8, value: anytype) !void {
        const T = @TypeOf(value);
        const ptr = try self.allocator.create(T);
        ptr.* = value;
        try self.data.put(key, @as(*anyopaque, @ptrCast(ptr)));

        const DestructorWrapper = struct {
            fn destroy(ptr_void: *anyopaque, alloc: std.mem.Allocator) void {
                const typed_ptr = @as(*T, @ptrCast(@alignCast(ptr_void)));
                alloc.destroy(typed_ptr);
            }
        };
        try self.destructors.put(key, DestructorWrapper.destroy);
    }

    pub fn get(self: *const Store, comptime T: type, key: []const u8) ?*T {
        const ptr = self.data.get(key) orelse return null;
        return @as(*T, @ptrCast(@alignCast(ptr)));
    }

    pub fn remove(self: *Store, key: []const u8) void {
        if (self.data.fetchRemove(key)) |entry| {
            if (self.destructors.fetchRemove(key)) |destructor_entry| {
                destructor_entry.value(entry.value, self.allocator);
            }
        }
    }

    pub fn has(self: *const Store, key: []const u8) bool {
        return self.data.contains(key);
    }
};

pub const AppState = struct {
    allocator: std.mem.Allocator,
    globals: Store,

    pub fn init(allocator: std.mem.Allocator) AppState {
        return AppState{
            .allocator = allocator,
            .globals = Store.init(allocator),
        };
    }

    pub fn deinit(self: *AppState) void {
        self.globals.deinit();
    }
};

test "Store handles different types" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var store = Store.init(allocator);
    defer store.deinit();

    try store.set("int_val", @as(i32, 42));
    try store.set("float_val", @as(f64, 3.14));
    try store.set("string_val", @as([]const u8, "hello"));

    const i = store.get(i32, "int_val").?;
    try testing.expectEqual(@as(i32, 42), i.*);

    const f = store.get(f64, "float_val").?;
    try testing.expectEqual(@as(f64, 3.14), f.*);

    const s = store.get([]const u8, "string_val").?;
    try testing.expectEqualStrings("hello", s.*);
}
