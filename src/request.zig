const std = @import("std");
const constants = @import("constants.zig");
const Config = @import("config.zig").Config;
const utils = @import("utils.zig");

pub const Request = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    method: constants.HttpMethod,
    uri: []const u8,
    path: []const u8,
    query_string: ?[]const u8,
    http_version: []const u8,
    headers: std.StringHashMap([]const u8),
    body: ?[]const u8,
    raw_request: []const u8,
    query_params: ?std.StringHashMap([]const u8),
    form_data: ?std.StringHashMap([]const u8),
    cookies: ?std.StringHashMap([]const u8),
    content_type: ?[]const u8,
    content_length: ?usize,
    is_keep_alive: bool,
    remote_addr: ?[]const u8,
    files: ?std.StringHashMap(UploadedFile),
    json_data: ?[]const u8,
    is_json: bool,
    is_form: bool,
    is_multipart: bool,
    scheme: []const u8,
    host: ?[]const u8,
    port: ?u16,
    base_url: ?[]const u8,
    url: ?[]const u8,
    endpoint: ?[]const u8,
    view_args: std.StringHashMap([]const u8),
    environ: std.StringHashMap([]const u8),

    pub const UploadedFile = struct {
        filename: []const u8,
        content_type: []const u8,
        data: []const u8,
        size: usize,
    };

    pub fn init(allocator: std.mem.Allocator, config: *const Config) !Request {
        const uri = try allocator.dupe(u8, "/");
        errdefer allocator.free(uri);
        const path = try allocator.dupe(u8, "/");
        errdefer allocator.free(path);
        const http_version = try allocator.dupe(u8, "HTTP/1.1");
        errdefer allocator.free(http_version);
        return Request{
            .allocator = allocator,
            .config = config,
            .method = .GET,
            .uri = uri,
            .path = path,
            .query_string = null,
            .http_version = http_version,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = null,
            .raw_request = "",
            .query_params = null,
            .form_data = null,
            .cookies = null,
            .content_type = null,
            .content_length = null,
            .is_keep_alive = true,
            .remote_addr = null,
            .files = null,
            .json_data = null,
            .is_json = false,
            .is_form = false,
            .is_multipart = false,
            .scheme = "http",
            .host = null,
            .port = null,
            .base_url = null,
            .url = null,
            .endpoint = null,
            .view_args = std.StringHashMap([]const u8).init(allocator),
            .environ = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Request) void {
        var header_it = self.headers.iterator();
        while (header_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        if (self.query_params) |*qp| utils.freeQueryMap(self.allocator, qp);
        if (self.form_data) |*fd| utils.freeQueryMap(self.allocator, fd);
        if (self.cookies) |*c| utils.freeQueryMap(self.allocator, c);
        if (self.body) |b| self.allocator.free(b);
        if (self.query_string) |qs| self.allocator.free(qs);
        self.allocator.free(self.uri);
        self.allocator.free(self.path);
        self.allocator.free(self.http_version);
        if (self.remote_addr) |addr| self.allocator.free(addr);
        self.view_args.deinit();
        self.environ.deinit();
    }

    pub fn parse(allocator: std.mem.Allocator, config: *const Config, raw: []const u8) !Request {
        var request = try Request.init(allocator, config);
        errdefer request.deinit();
        request.raw_request = raw;
        const header_end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse
            return if (raw.len > 0) error.InvalidHeader else error.EndOfStream;
        const header_section = raw[0..header_end];
        const body_start = header_end + 4;
        var lines = std.mem.splitSequence(u8, header_section, "\r\n");
        const request_line = lines.next() orelse return error.InvalidUri;
        try request.parseRequestLine(request_line);
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            try request.parseHeaderLine(line);
        }
        request.content_type = request.header("content-type");
        if (request.header("content-length")) |cl| {
            request.content_length = std.fmt.parseInt(usize, cl, 10) catch null;
        }
        if (request.header("connection")) |conn| {
            request.is_keep_alive = !utils.eqlIgnoreCase(conn, "close");
        }
        request.host = request.header("host");
        if (request.content_type) |ct| {
            request.is_json = std.mem.indexOf(u8, ct, "application/json") != null;
            request.is_form = std.mem.indexOf(u8, ct, "application/x-www-form-urlencoded") != null;
            request.is_multipart = std.mem.indexOf(u8, ct, "multipart/form-data") != null;
        }
        if (body_start < raw.len) {
            const body_data = raw[body_start..];
            if (request.content_length) |cl| {
                if (cl > config.max_body_size) return error.BodyTooLarge;
                const actual_len = @min(cl, body_data.len);
                request.body = try allocator.dupe(u8, body_data[0..actual_len]);
            } else if (body_data.len > 0) {
                request.body = try allocator.dupe(u8, body_data);
            }
        }
        return request;
    }

    fn parseRequestLine(self: *Request, line: []const u8) !void {
        var parts = std.mem.splitScalar(u8, line, ' ');
        const method_str = parts.next() orelse return error.InvalidMethod;
        self.method = constants.HttpMethod.fromString(method_str) orelse return error.InvalidMethod;
        const uri = parts.next() orelse return error.InvalidUri;
        const new_uri = try self.allocator.dupe(u8, uri);
        self.allocator.free(self.uri);
        self.uri = new_uri;
        if (std.mem.indexOf(u8, uri, "?")) |query_start| {
            const new_path = try self.allocator.dupe(u8, uri[0..query_start]);
            self.allocator.free(self.path);
            self.path = new_path;
            const qs = uri[query_start + 1 ..];
            if (qs.len > 0) self.query_string = try self.allocator.dupe(u8, qs);
        } else {
            const new_path = try self.allocator.dupe(u8, uri);
            self.allocator.free(self.path);
            self.path = new_path;
        }
        const version = parts.next() orelse "HTTP/1.1";
        const new_version = try self.allocator.dupe(u8, version);
        self.allocator.free(self.http_version);
        self.http_version = new_version;
    }

    fn parseHeaderLine(self: *Request, line: []const u8) !void {
        const colon_pos = std.mem.indexOf(u8, line, ":") orelse return;
        const name = utils.trimWhitespace(line[0..colon_pos]);
        const value = if (colon_pos + 1 < line.len) utils.trimWhitespace(line[colon_pos + 1 ..]) else "";
        const lower_name = try self.allocator.alloc(u8, name.len);
        for (name, 0..) |c, i| lower_name[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        const value_copy = try self.allocator.dupe(u8, value);
        try self.headers.put(lower_name, value_copy);
    }

    pub fn header(self: *const Request, name: []const u8) ?[]const u8 {
        var lower_buf: [256]u8 = undefined;
        if (name.len > lower_buf.len) return null;
        for (name, 0..) |c, i| lower_buf[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        return self.headers.get(lower_buf[0..name.len]);
    }

    pub fn query(self: *Request, key: []const u8) !?[]const u8 {
        if (self.query_params == null) {
            if (self.query_string) |qs| {
                self.query_params = try utils.parseQueryString(self.allocator, qs);
            } else return null;
        }
        return self.query_params.?.get(key);
    }

    pub fn args(self: *Request) !*std.StringHashMap([]const u8) {
        if (self.query_params == null) {
            if (self.query_string) |qs| {
                self.query_params = try utils.parseQueryString(self.allocator, qs);
            } else {
                self.query_params = std.StringHashMap([]const u8).init(self.allocator);
            }
        }
        return &self.query_params.?;
    }

    pub fn form(self: *Request, key: []const u8) !?[]const u8 {
        if (self.form_data == null) {
            if (self.body) |b| {
                if (self.is_form) {
                    self.form_data = try utils.parseQueryString(self.allocator, b);
                }
            }
            if (self.form_data == null) return null;
        }
        return self.form_data.?.get(key);
    }

    pub fn cookie(self: *Request, name: []const u8) !?[]const u8 {
        if (self.cookies == null) {
            if (self.headers.get("cookie")) |cookie_header| {
                self.cookies = try parseCookies(self.allocator, cookie_header);
            } else return null;
        }
        return self.cookies.?.get(name);
    }

    pub fn bodyRaw(self: *const Request) ?[]const u8 {
        return self.body;
    }

    pub fn getData(self: *const Request) ?[]const u8 {
        return self.body;
    }

    pub fn getJson(self: *const Request, comptime T: type) !T {
        const body_data = self.body orelse return error.InvalidBody;
        return std.json.parseFromSlice(T, self.allocator, body_data, .{});
    }

    pub fn bodyJson(self: *const Request, comptime T: type) !T {
        const body_data = self.body orelse return error.InvalidBody;
        return std.json.parseFromSlice(T, self.allocator, body_data, .{}) catch return error.JsonParseError;
    }

    pub fn bodyJsonAlloc(self: *const Request, comptime T: type) !std.json.Parsed(T) {
        const body_data = self.body orelse return error.InvalidBody;
        return std.json.parseFromSlice(T, self.allocator, body_data, .{});
    }

    pub fn isAjax(self: *const Request) bool {
        if (self.headers.get("x-requested-with")) |xrw| return utils.eqlIgnoreCase(xrw, "XMLHttpRequest");
        return false;
    }

    pub fn isXhr(self: *const Request) bool {
        return self.isAjax();
    }

    pub fn acceptsJson(self: *const Request) bool {
        if (self.headers.get("accept")) |accept| return std.mem.indexOf(u8, accept, "application/json") != null;
        return false;
    }

    pub fn acceptsHtml(self: *const Request) bool {
        if (self.headers.get("accept")) |accept| return std.mem.indexOf(u8, accept, "text/html") != null;
        return false;
    }

    pub fn acceptsMimeTypes(self: *const Request, mimetypes: []const []const u8) ?[]const u8 {
        if (self.headers.get("accept")) |accept| {
            for (mimetypes) |mt| {
                if (std.mem.indexOf(u8, accept, mt) != null) return mt;
            }
        }
        return null;
    }

    pub fn isSecure(self: *const Request) bool {
        return std.mem.eql(u8, self.scheme, "https");
    }

    pub fn getFullPath(self: *const Request) []const u8 {
        return self.uri;
    }

    pub fn getUserAgent(self: *const Request) ?[]const u8 {
        return self.header("user-agent");
    }

    pub fn getReferer(self: *const Request) ?[]const u8 {
        return self.header("referer");
    }

    pub fn getAuthorization(self: *const Request) ?[]const u8 {
        return self.header("authorization");
    }

    pub fn getContentType(self: *const Request) ?[]const u8 {
        return self.content_type;
    }
};

fn parseCookies(allocator: std.mem.Allocator, cookie_header: []const u8) !std.StringHashMap([]const u8) {
    var map = std.StringHashMap([]const u8).init(allocator);
    errdefer {
        var it = map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        map.deinit();
    }
    var pairs = std.mem.splitSequence(u8, cookie_header, "; ");
    while (pairs.next()) |pair| {
        const trimmed = utils.trimWhitespace(pair);
        if (trimmed.len == 0) continue;
        if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
            const name = try allocator.dupe(u8, trimmed[0..eq_pos]);
            errdefer allocator.free(name);
            const value = try allocator.dupe(u8, trimmed[eq_pos + 1 ..]);
            try map.put(name, value);
        }
    }
    return map;
}

test "Request.init creates request" {
    const allocator = std.testing.allocator;
    var config = Config{};
    var request = try Request.init(allocator, &config);
    defer request.deinit();
    try std.testing.expectEqual(constants.HttpMethod.GET, request.method);
}

test "Request.parse parses GET request" {
    const allocator = std.testing.allocator;
    var config = Config{};
    const raw = "GET /test?foo=bar HTTP/1.1\r\nHost: localhost\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();
    try std.testing.expectEqualStrings("/test", request.path);
    try std.testing.expectEqual(constants.HttpMethod.GET, request.method);
}

test "Request.parse parses POST with body" {
    const allocator = std.testing.allocator;
    var config = Config{};
    const raw = "POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Length: 11\r\n\r\nhello=world";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();
    try std.testing.expectEqual(constants.HttpMethod.POST, request.method);
    try std.testing.expectEqualStrings("hello=world", request.body.?);
}

test "Request.header returns value" {
    const allocator = std.testing.allocator;
    var config = Config{};
    const raw = "GET / HTTP/1.1\r\nHost: example.com\r\nX-Custom: test\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();
    try std.testing.expectEqualStrings("example.com", request.header("host").?);
}

test "Request.query parses query string" {
    const allocator = std.testing.allocator;
    var config = Config{};
    const raw = "GET /search?q=hello&page=1 HTTP/1.1\r\nHost: localhost\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();
    const q = try request.query("q");
    try std.testing.expectEqualStrings("hello", q.?);
}

test "Request.isAjax detects XHR" {
    const allocator = std.testing.allocator;
    var config = Config{};
    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\nX-Requested-With: XMLHttpRequest\r\n\r\n";
    var request = try Request.parse(allocator, &config, raw);
    defer request.deinit();
    try std.testing.expect(request.isAjax());
}
