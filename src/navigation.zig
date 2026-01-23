const std = @import("std");
const Context = @import("context.zig").Context;
const utils = @import("utils.zig");
const constants = @import("constants.zig");
const HttpStatus = constants.HttpStatus;

pub const Navigation = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Navigation {
        return Navigation{ .allocator = allocator };
    }

    pub fn urlFor(self: *Navigation, endpoint: []const u8, params: anytype) ![]u8 {
        var result: std.ArrayList(u8) = .empty;
        defer result.deinit(self.allocator);

        var it = utils.splitPath(endpoint);
        while (it.next()) |segment| {
            try result.append(self.allocator, '/');

            if (segment.len > 1 and segment[0] == ':') {
                const param_name = segment[1..];
                const value = try self.getParamValue(params, param_name);
                if (value) |v| {
                    try result.appendSlice(self.allocator, v);
                } else {
                    try result.appendSlice(self.allocator, segment);
                }
            } else if (segment.len > 2 and segment[0] == '<' and segment[segment.len - 1] == '>') {
                const inner = segment[1 .. segment.len - 1];
                var param_name = inner;
                if (std.mem.indexOf(u8, inner, ":")) |colon| {
                    param_name = inner[colon + 1 ..];
                }
                const value = try self.getParamValue(params, param_name);
                if (value) |v| {
                    try result.appendSlice(self.allocator, v);
                } else {
                    try result.appendSlice(self.allocator, segment);
                }
            } else if (std.mem.eql(u8, segment, "*")) {
                const value = try self.getParamValue(params, "wildcard");
                if (value) |v| {
                    try result.appendSlice(self.allocator, v);
                } else {
                    try result.appendSlice(self.allocator, segment);
                }
            } else {
                try result.appendSlice(self.allocator, segment);
            }
        }

        if (result.items.len == 0) {
            try result.append(self.allocator, '/');
        }

        return result.toOwnedSlice(self.allocator);
    }

    fn getParamValue(self: *Navigation, params: anytype, name: []const u8) !?[]const u8 {
        _ = self;
        inline for (std.meta.fields(@TypeOf(params))) |field| {
            if (std.mem.eql(u8, field.name, name)) {
                const val = @field(params, field.name);
                switch (@TypeOf(val)) {
                    []const u8 => return val,
                    []u8 => return val,
                    else => return null,
                }
            }
        }
        return null;
    }
};

pub fn redirect(ctx: *Context, location: []const u8, status: u16) !void {
    try ctx.redirect(location, status);
}

pub fn push(ctx: *Context, location: []const u8) !void {
    try ctx.redirect(location, HttpStatus.Found);
}

pub fn replace(ctx: *Context, location: []const u8) !void {
    try ctx.redirect(location, HttpStatus.SeeOther);
}

pub fn back(ctx: *Context) !void {
    const referrer = ctx.header("Referer") orelse "/";
    try ctx.redirect(referrer, HttpStatus.Found);
}

test "Navigation constructs basics" {
    const allocator = std.testing.allocator;
    const nav = Navigation.init(allocator);
    _ = nav;
}
