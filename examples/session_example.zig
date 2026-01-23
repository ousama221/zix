const std = @import("std");
const zix = @import("zix");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var app = try zix.createApp(allocator, .{
        .port = 8082,
        .secret_key = "super-secret-key",
    });
    defer app.deinit();

    try app.get("/login", login);
    try app.get("/dashboard", dashboard);
    try app.get("/logout", logout);

    try app.run();
}

fn login(ctx: *zix.Context) !void {
    try ctx.session.put("user_id", "123");
    try zix.session.flash(ctx, "Welcome back!", "info");
    try ctx.redirect("/dashboard", 302);
}

fn dashboard(ctx: *zix.Context) !void {
    if (ctx.session.get("user_id")) |uid| {
        const flashes = try zix.session.getFlashedMessages(ctx, ctx.allocator);
        try ctx.json(.{ .user_id = uid, .messages = flashes });
    } else {
        try ctx.unauthorized();
    }
}

fn logout(ctx: *zix.Context) !void {
    ctx.session.clearRetainingCapacity();
    try ctx.text("Logged out");
}
