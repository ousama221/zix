const std = @import("std");
const zix = @import("zix");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var app = try zix.createApp(allocator, .{ .port = 8085 });
    defer app.deinit();

    try app.use(loggingMiddleware);

    var api = app.group("/api/v1");
    try api.get("/resource", getResource);
    try api.get("/redirect", doRedirect);

    try app.run();
}

fn loggingMiddleware(ctx: *zix.Context, next: zix.NextFn) anyerror!void {
    std.debug.print("Request: {s}\n", .{ctx.request.path});
    try next(ctx);
    std.debug.print("Status: {d}\n", .{ctx.response.status_code});
}

fn getResource(ctx: *zix.Context) !void {
    try ctx.state.set("timestamp", @as([]const u8, "2023-01-01"));
    const ts = ctx.state.get([]const u8, "timestamp");
    if (ts) |t| {
        try ctx.json(.{ .data = "Resource", .time = t.* });
    } else {
        try ctx.json(.{ .data = "Resource", .time = "unknown" });
    }
}

fn doRedirect(ctx: *zix.Context) !void {
    try zix.navigation.push(ctx, "/api/v1/resource");
}
