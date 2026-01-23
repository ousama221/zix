const std = @import("std");
const zix = @import("zix");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var app = try zix.createApp(allocator, .{
        .debug_mode = true,
        .address = "127.0.0.1",
        .port = 8080,
    });
    defer {
        app.deinit();
        allocator.destroy(app);
    }

    try app.get("/", h1);
    try app.get("/hello", h2);

    app.printRoutes();

    try app.run();
}

fn h1(ctx: *zix.Context) !void {
    try ctx.text("Hello Zix!");
}

fn h2(ctx: *zix.Context) !void {
    try ctx.json(.{ .message = "Hello World" });
}
