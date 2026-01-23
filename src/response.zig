const std = @import("std");
const constants = @import("constants.zig");
const Config = @import("config.zig").Config;
const utils = @import("utils.zig");

pub const Response = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    status_code: u16,
    headers: std.ArrayList(Header),
    body: std.ArrayList(u8),
    sent: bool,
    cookies: std.ArrayList(Cookie),
    charset: []const u8,
    mimetype: []const u8,
    direct_passthrough: bool,

    pub const Header = struct {
        name: []const u8,
        value: []const u8,
    };

    pub const Cookie = struct {
        name: []const u8,
        value: []const u8,
        max_age: ?i64 = null,
        expires: ?i64 = null,
        path: ?[]const u8 = null,
        domain: ?[]const u8 = null,
        secure: bool = false,
        http_only: bool = true,
        same_site: ?[]const u8 = null,

        pub fn format(self: *const Cookie, allocator: std.mem.Allocator) ![]u8 {
            var result: std.ArrayList(u8) = .empty;
            errdefer result.deinit(allocator);
            try result.appendSlice(allocator, self.name);
            try result.append(allocator, '=');
            try result.appendSlice(allocator, self.value);
            if (self.max_age) |ma| {
                var buf: [32]u8 = undefined;
                const age_str = std.fmt.bufPrint(&buf, "; Max-Age={d}", .{ma}) catch return error.OutOfMemory;
                try result.appendSlice(allocator, age_str);
            }
            if (self.expires) |exp| {
                try result.appendSlice(allocator, "; Expires=");
                var date_buf: [29]u8 = undefined;
                const date_str = utils.formatHttpDate(&date_buf, exp);
                try result.appendSlice(allocator, date_str);
            }
            if (self.path) |p| {
                try result.appendSlice(allocator, "; Path=");
                try result.appendSlice(allocator, p);
            }
            if (self.domain) |d| {
                try result.appendSlice(allocator, "; Domain=");
                try result.appendSlice(allocator, d);
            }
            if (self.secure) try result.appendSlice(allocator, "; Secure");
            if (self.http_only) try result.appendSlice(allocator, "; HttpOnly");
            if (self.same_site) |ss| {
                try result.appendSlice(allocator, "; SameSite=");
                try result.appendSlice(allocator, ss);
            }
            return result.toOwnedSlice(allocator);
        }
    };

    pub fn init(allocator: std.mem.Allocator, config: *const Config) Response {
        return Response{
            .allocator = allocator,
            .config = config,
            .status_code = 200,
            .headers = .empty,
            .body = .empty,
            .sent = false,
            .cookies = .empty,
            .charset = "utf-8",
            .mimetype = "text/html",
            .direct_passthrough = false,
        };
    }

    pub fn deinit(self: *Response) void {
        for (self.headers.items) |h| {
            self.allocator.free(h.name);
            self.allocator.free(h.value);
        }
        self.headers.deinit(self.allocator);
        self.body.deinit(self.allocator);
        for (self.cookies.items) |c| {
            self.allocator.free(c.name);
            self.allocator.free(c.value);
            if (c.path) |p| self.allocator.free(p);
            if (c.domain) |d| self.allocator.free(d);
            if (c.same_site) |ss| self.allocator.free(ss);
        }
        self.cookies.deinit(self.allocator);
    }

    pub fn status(self: *Response, code: u16) *Response {
        self.status_code = code;
        return self;
    }

    pub fn setHeader(self: *Response, name: []const u8, value: []const u8) !void {
        for (self.headers.items, 0..) |h, i| {
            if (utils.eqlIgnoreCase(h.name, name)) {
                self.allocator.free(self.headers.items[i].value);
                self.headers.items[i].value = try self.allocator.dupe(u8, value);
                return;
            }
        }
        try self.headers.append(self.allocator, Header{
            .name = try self.allocator.dupe(u8, name),
            .value = try self.allocator.dupe(u8, value),
        });
    }

    pub fn addHeader(self: *Response, name: []const u8, value: []const u8) !void {
        try self.headers.append(self.allocator, Header{
            .name = try self.allocator.dupe(u8, name),
            .value = try self.allocator.dupe(u8, value),
        });
    }

    pub fn deleteHeader(self: *Response, name: []const u8) void {
        var i: usize = 0;
        while (i < self.headers.items.len) {
            if (utils.eqlIgnoreCase(self.headers.items[i].name, name)) {
                self.allocator.free(self.headers.items[i].name);
                self.allocator.free(self.headers.items[i].value);
                _ = self.headers.orderedRemove(i);
            } else i += 1;
        }
    }

    pub fn getHeader(self: *const Response, name: []const u8) ?[]const u8 {
        for (self.headers.items) |h| {
            if (utils.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    pub fn setCookie(self: *Response, cookie_opts: struct {
        name: []const u8,
        value: []const u8,
        max_age: ?i64 = null,
        expires: ?i64 = null,
        path: ?[]const u8 = null,
        domain: ?[]const u8 = null,
        secure: bool = false,
        http_only: bool = true,
        same_site: ?[]const u8 = null,
    }) !void {
        const cookie = Cookie{
            .name = try self.allocator.dupe(u8, cookie_opts.name),
            .value = try self.allocator.dupe(u8, cookie_opts.value),
            .max_age = cookie_opts.max_age,
            .expires = cookie_opts.expires,
            .path = if (cookie_opts.path) |p| try self.allocator.dupe(u8, p) else null,
            .domain = if (cookie_opts.domain) |d| try self.allocator.dupe(u8, d) else null,
            .secure = cookie_opts.secure,
            .http_only = cookie_opts.http_only,
            .same_site = if (cookie_opts.same_site) |ss| try self.allocator.dupe(u8, ss) else null,
        };
        try self.cookies.append(self.allocator, cookie);
    }

    pub fn deleteCookie(self: *Response, name: []const u8) !void {
        try self.setCookie(.{ .name = name, .value = "", .max_age = 0, .path = "/" });
    }

    pub fn text(self: *Response, content: []const u8) !void {
        self.body.clearRetainingCapacity();
        try self.body.appendSlice(self.allocator, content);
        try self.setHeader("Content-Type", constants.Response.default_content_type);
    }

    pub fn html(self: *Response, content: []const u8) !void {
        self.body.clearRetainingCapacity();
        try self.body.appendSlice(self.allocator, content);
        try self.setHeader("Content-Type", constants.Response.html_content_type);
    }

    pub fn json(self: *Response, data: anytype) !void {
        self.body.clearRetainingCapacity();
        const json_str = try std.json.Stringify.valueAlloc(self.allocator, data, .{});
        defer self.allocator.free(json_str);
        try self.body.appendSlice(self.allocator, json_str);
        try self.setHeader("Content-Type", constants.Response.json_content_type);
    }

    pub fn jsonRaw(self: *Response, json_string: []const u8) !void {
        self.body.clearRetainingCapacity();
        try self.body.appendSlice(self.allocator, json_string);
        try self.setHeader("Content-Type", constants.Response.json_content_type);
    }

    pub fn xml(self: *Response, content: []const u8) !void {
        self.body.clearRetainingCapacity();
        try self.body.appendSlice(self.allocator, content);
        try self.setHeader("Content-Type", constants.Response.xml_content_type);
    }

    pub fn setData(self: *Response, data: []const u8) !void {
        self.body.clearRetainingCapacity();
        try self.body.appendSlice(self.allocator, data);
    }

    pub fn getData(self: *const Response) []const u8 {
        return self.body.items;
    }

    pub fn setContentType(self: *Response, content_type: []const u8) !void {
        try self.setHeader("Content-Type", content_type);
    }

    pub fn redirect(self: *Response, location: []const u8, status_code: ?u16) !void {
        self.status_code = status_code orelse 302;
        try self.setHeader("Location", location);
    }

    pub fn redirectPermanent(self: *Response, location: []const u8) !void {
        self.status_code = 301;
        try self.setHeader("Location", location);
    }

    pub fn file(self: *Response, file_path: []const u8) !void {
        const f = std.fs.cwd().openFile(file_path, .{}) catch return error.StaticFileNotFound;
        defer f.close();
        const stat = f.stat() catch return error.StaticFileReadError;
        if (stat.size > self.config.max_body_size) return error.StaticFileTooLarge;
        self.body.clearRetainingCapacity();
        const content = f.readToEndAlloc(self.allocator, self.config.max_body_size) catch return error.StaticFileReadError;
        defer self.allocator.free(content);
        try self.body.appendSlice(self.allocator, content);
        const mime_type = constants.MimeTypes.fromPath(file_path);
        try self.setHeader("Content-Type", mime_type);
    }

    pub fn sendFile(self: *Response, file_path: []const u8, filename: ?[]const u8) !void {
        try self.file(file_path);
        const name = filename orelse std.fs.path.basename(file_path);
        var disposition_buf: [512]u8 = undefined;
        const disposition = std.fmt.bufPrint(&disposition_buf, "attachment; filename=\"{s}\"", .{name}) catch return error.OutOfMemory;
        try self.setHeader("Content-Disposition", disposition);
    }

    pub fn noContent(self: *Response) !void {
        self.status_code = 204;
        self.body.clearRetainingCapacity();
    }

    pub fn notFound(self: *Response) !void {
        self.status_code = 404;
        try self.html(constants.ErrorPages.getPage(404));
    }

    pub fn methodNotAllowed(self: *Response) !void {
        self.status_code = 405;
        try self.html(constants.ErrorPages.getPage(405));
    }

    pub fn internalError(self: *Response) !void {
        self.status_code = 500;
        try self.html(constants.ErrorPages.getPage(500));
    }

    pub fn unauthorized(self: *Response) !void {
        self.status_code = 401;
        try self.text("Unauthorized");
    }

    pub fn forbidden(self: *Response) !void {
        self.status_code = 403;
        try self.text("Forbidden");
    }

    pub fn badRequest(self: *Response, message: ?[]const u8) !void {
        self.status_code = 400;
        try self.text(message orelse "Bad Request");
    }

    pub fn created(self: *Response, location: ?[]const u8) !void {
        self.status_code = 201;
        if (location) |loc| try self.setHeader("Location", loc);
    }

    pub fn accepted(self: *Response) !void {
        self.status_code = 202;
    }

    pub fn setMimetype(self: *Response, mimetype: []const u8) void {
        self.mimetype = mimetype;
    }

    pub fn setCharset(self: *Response, charset: []const u8) void {
        self.charset = charset;
    }

    pub fn makeConditional(self: *Response, request_headers: anytype) void {
        _ = request_headers;
        _ = self;
    }

    pub fn addEtag(self: *Response, etag: []const u8) !void {
        try self.setHeader("ETag", etag);
    }

    pub fn cacheControl(self: *Response, directives: []const u8) !void {
        try self.setHeader("Cache-Control", directives);
    }

    pub fn expires(self: *Response, timestamp: i64) !void {
        var date_buf: [29]u8 = undefined;
        const date_str = utils.formatHttpDate(&date_buf, timestamp);
        try self.setHeader("Expires", date_str);
    }

    pub fn lastModified(self: *Response, timestamp: i64) !void {
        var date_buf: [29]u8 = undefined;
        const date_str = utils.formatHttpDate(&date_buf, timestamp);
        try self.setHeader("Last-Modified", date_str);
    }

    fn addSecurityHeaders(self: *Response) !void {
        if (self.config.enable_security_headers) {
            try self.setHeader("X-Content-Type-Options", self.config.x_content_type_options);
            try self.setHeader("X-Frame-Options", self.config.x_frame_options);
            try self.setHeader("X-XSS-Protection", self.config.x_xss_protection);
            try self.setHeader("Referrer-Policy", self.config.referrer_policy);
            if (self.config.content_security_policy) |csp| try self.setHeader("Content-Security-Policy", csp);
            if (self.config.strict_transport_security) |hsts| try self.setHeader("Strict-Transport-Security", hsts);
            if (self.config.permissions_policy) |pp| try self.setHeader("Permissions-Policy", pp);
        }
    }

    fn addCorsHeaders(self: *Response) !void {
        if (self.config.cors_enabled) {
            try self.setHeader("Access-Control-Allow-Origin", self.config.cors_allow_origin);
            try self.setHeader("Access-Control-Allow-Methods", self.config.cors_allow_methods);
            try self.setHeader("Access-Control-Allow-Headers", self.config.cors_allow_headers);
            if (self.config.cors_allow_credentials) try self.setHeader("Access-Control-Allow-Credentials", "true");
            if (self.config.cors_expose_headers) |eh| try self.setHeader("Access-Control-Expose-Headers", eh);
        }
    }

    pub fn build(self: *Response) ![]u8 {
        try self.addSecurityHeaders();
        try self.addCorsHeaders();
        var len_buf: [32]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{self.body.items.len}) catch return error.OutOfMemory;
        try self.setHeader("Content-Length", len_str);
        try self.setHeader("Server", self.config.server_name);
        var date_buf: [29]u8 = undefined;
        const date_str = utils.formatHttpDate(&date_buf, std.time.timestamp());
        try self.setHeader("Date", date_str);
        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(self.allocator);
        const status_message = constants.HttpStatus.getPhrase(self.status_code);
        var status_line_buf: [64]u8 = undefined;
        const status_line = std.fmt.bufPrint(&status_line_buf, "HTTP/1.1 {d} {s}\r\n", .{ self.status_code, status_message }) catch return error.OutOfMemory;
        try result.appendSlice(self.allocator, status_line);
        for (self.headers.items) |h| {
            try result.appendSlice(self.allocator, h.name);
            try result.appendSlice(self.allocator, ": ");
            try result.appendSlice(self.allocator, h.value);
            try result.appendSlice(self.allocator, "\r\n");
        }
        for (self.cookies.items) |c| {
            try result.appendSlice(self.allocator, "Set-Cookie: ");
            const cookie_str = try c.format(self.allocator);
            defer self.allocator.free(cookie_str);
            try result.appendSlice(self.allocator, cookie_str);
            try result.appendSlice(self.allocator, "\r\n");
        }
        try result.appendSlice(self.allocator, "\r\n");
        if (self.body.items.len > 0) try result.appendSlice(self.allocator, self.body.items);
        self.sent = true;
        return result.toOwnedSlice(self.allocator);
    }
};

pub fn makeResponse(allocator: std.mem.Allocator, config: *const Config, content: []const u8, status_code: u16) !Response {
    var response = Response.init(allocator, config);
    _ = response.status(status_code);
    try response.setData(content);
    return response;
}

pub fn jsonify(allocator: std.mem.Allocator, config: *const Config, data: anytype) !Response {
    var response = Response.init(allocator, config);
    try response.json(data);
    return response;
}

test "Response.init creates response" {
    const allocator = std.testing.allocator;
    var config = Config{};
    var response = Response.init(allocator, &config);
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
}

test "Response.status sets code" {
    const allocator = std.testing.allocator;
    var config = Config{};
    var response = Response.init(allocator, &config);
    defer response.deinit();
    _ = response.status(404);
    try std.testing.expectEqual(@as(u16, 404), response.status_code);
}

test "Response.text sets body" {
    const allocator = std.testing.allocator;
    var config = Config{};
    var response = Response.init(allocator, &config);
    defer response.deinit();
    try response.text("Hello");
    try std.testing.expectEqualStrings("Hello", response.body.items);
}

test "Response.json serializes data" {
    const allocator = std.testing.allocator;
    var config = Config{};
    var response = Response.init(allocator, &config);
    defer response.deinit();
    try response.json(.{ .message = "hello" });
    try std.testing.expect(std.mem.indexOf(u8, response.body.items, "message") != null);
}

test "Response.redirect sets location" {
    const allocator = std.testing.allocator;
    var config = Config{};
    var response = Response.init(allocator, &config);
    defer response.deinit();
    try response.redirect("/login", null);
    try std.testing.expectEqual(@as(u16, 302), response.status_code);
}

test "Response.setCookie adds cookie" {
    const allocator = std.testing.allocator;
    var config = Config{};
    var response = Response.init(allocator, &config);
    defer response.deinit();
    try response.setCookie(.{ .name = "session", .value = "abc", .max_age = 3600 });
    try std.testing.expectEqual(@as(usize, 1), response.cookies.items.len);
}

test "Response.build creates HTTP response" {
    const allocator = std.testing.allocator;
    var config = Config{ .enable_security_headers = false };
    var response = Response.init(allocator, &config);
    defer response.deinit();
    try response.text("Test");
    const built = try response.build();
    defer allocator.free(built);
    try std.testing.expect(std.mem.indexOf(u8, built, "HTTP/1.1 200") != null);
}
