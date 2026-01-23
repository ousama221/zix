const std = @import("std");
const zix = @import("zix");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var app = try zix.createApp(allocator, .{
        .port = 8084,
        .debug_mode = true,
        .template_dir = "examples/templates",
    });
    defer {
        app.deinit();
        allocator.destroy(app);
    }

    app.enableTemplates();

    try app.get("/", indexHandler);
    try app.get("/about", aboutHandler);

    try app.run();
}

fn indexHandler(ctx: *zix.Context) !void {
    const items = [_]struct { name: []const u8, price: []const u8 }{
        .{ .name = "Wireless Mouse", .price = "$25.99" },
        .{ .name = "Mechanical Keyboard", .price = "$89.50" },
        .{ .name = "27-inch Monitor", .price = "$249.00" },
    };

    try ctx.render("index.html", .{
        .title = "Zix Templates Demo",
        .message = "Welcome to Zix - a powerful web framework for Zig!",
        .items = &items,
        .show_footer = "true",
    });
}

fn aboutHandler(ctx: *zix.Context) !void {
    try ctx.render("about.html", .{
        .title = "About Zix",
        .description = "Zix is a lightweight web framework for Zig.",
    });
}
