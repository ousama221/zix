const std = @import("std");
const zix = @import("zix");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var app = try zix.createApp(allocator, .{
        .port = 8083,
        .spa_mode = true,
        .spa_index = "index.html",
    });
    defer {
        app.deinit();
        allocator.destroy(app);
    }

    app.enableTemplates();
    app.enableStatic();

    try app.static("/assets", "static");

    try app.run();
}
