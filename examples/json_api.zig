const std = @import("std");
const zix = @import("zix");

const User = struct {
    id: u32,
    name: []const u8,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var app = try zix.createApp(allocator, .{ .port = 8081 });
    defer {
        app.deinit();
        allocator.destroy(app);
    }

    try app.post("/users", createUser);
    try app.get("/users/:id", getUser);

    try app.run();
}

fn createUser(ctx: *zix.Context) !void {
    const parsed = try ctx.bodyJson(User);
    defer parsed.deinit();
    const user = parsed.value;
    try ctx.status(201).json(.{ .message = "Created", .user = user });
}

fn getUser(ctx: *zix.Context) !void {
    const id = ctx.param("id") orelse return ctx.badRequest("Missing ID");
    try ctx.json(.{ .id = id, .name = "Example User" });
}
