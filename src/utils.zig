const std = @import("std");
const constants = @import("constants.zig");

pub fn urlDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const hex = input[i + 1 .. i + 3];
            const byte = std.fmt.parseInt(u8, hex, 16) catch {
                try result.append(allocator, input[i]);
                i += 1;
                continue;
            };
            try result.append(allocator, byte);
            i += 3;
        } else if (input[i] == '+') {
            try result.append(allocator, ' ');
            i += 1;
        } else {
            try result.append(allocator, input[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice(allocator);
}

pub fn urlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    for (input) |c| {
        if (isUnreserved(c)) {
            try result.append(allocator, c);
        } else {
            try result.append(allocator, '%');
            var buf: [2]u8 = undefined;
            _ = std.fmt.bufPrint(&buf, "{X:0>2}", .{c}) catch continue;
            try result.appendSlice(allocator, &buf);
        }
    }

    return result.toOwnedSlice(allocator);
}

pub fn sign(allocator: std.mem.Allocator, value: []const u8, secret: []const u8) ![]u8 {
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(secret);
    hmac.update(value);
    var result: [32]u8 = undefined;
    hmac.final(&result);

    const encoder = std.base64.url_safe_no_pad.Encoder;
    const sig_len = encoder.calcSize(result.len);
    const total_len = value.len + 1 + sig_len;

    var out = try allocator.alloc(u8, total_len);
    @memcpy(out[0..value.len], value);
    out[value.len] = '.';

    _ = encoder.encode(out[value.len + 1 ..], &result);
    return out;
}

pub fn verify(allocator: std.mem.Allocator, signed_value: []const u8, secret: []const u8) !?[]u8 {
    const dot_pos = std.mem.lastIndexOfScalar(u8, signed_value, '.') orelse return null;
    const value = signed_value[0..dot_pos];
    const signature = signed_value[dot_pos + 1 ..];

    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(secret);
    hmac.update(value);
    var expected: [32]u8 = undefined;
    hmac.final(&expected);

    var decoded_sig: [32]u8 = undefined;
    const decoder = std.base64.url_safe_no_pad.Decoder;
    _ = decoder.decode(&decoded_sig, signature) catch return null;

    if (std.crypto.utils.timingSafeEql([32]u8, expected, decoded_sig)) {
        return try allocator.dupe(u8, value);
    }
    return null;
}

fn isUnreserved(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or
        (c >= 'a' and c <= 'z') or
        (c >= '0' and c <= '9') or
        c == '-' or c == '_' or c == '.' or c == '~';
}

pub fn parseQueryString(allocator: std.mem.Allocator, query: []const u8) !std.StringHashMap([]const u8) {
    var map = std.StringHashMap([]const u8).init(allocator);
    errdefer {
        var it = map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        map.deinit();
    }

    if (query.len == 0) return map;

    var pairs = std.mem.splitScalar(u8, query, '&');
    while (pairs.next()) |pair| {
        if (pair.len == 0) continue;

        var kv = std.mem.splitScalar(u8, pair, '=');
        const raw_key = kv.next() orelse continue;
        const raw_value = kv.next() orelse "";

        const key = try urlDecode(allocator, raw_key);
        errdefer allocator.free(key);
        const value = try urlDecode(allocator, raw_value);

        try map.put(key, value);
    }

    return map;
}

pub fn freeQueryMap(allocator: std.mem.Allocator, map: *std.StringHashMap([]const u8)) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        allocator.free(entry.value_ptr.*);
    }
    map.deinit();
}

pub fn splitPath(path: []const u8) std.mem.SplitIterator(u8, .scalar) {
    const trimmed = std.mem.trim(u8, path, "/");
    return std.mem.splitScalar(u8, trimmed, '/');
}

pub fn normalizePath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var segments: std.ArrayList([]const u8) = .empty;
    defer segments.deinit(allocator);

    var it = splitPath(path);
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".")) {
            continue;
        } else if (std.mem.eql(u8, segment, "..")) {
            if (segments.items.len > 0) {
                _ = segments.pop();
            }
        } else {
            try segments.append(allocator, segment);
        }
    }

    if (segments.items.len == 0) {
        return try allocator.dupe(u8, "/");
    }

    var total_len: usize = 1;
    for (segments.items) |seg| {
        total_len += seg.len + 1;
    }

    const result = try allocator.alloc(u8, total_len);
    var pos: usize = 0;
    for (segments.items) |seg| {
        result[pos] = '/';
        pos += 1;
        @memcpy(result[pos .. pos + seg.len], seg);
        pos += seg.len;
    }
    result[pos] = 0;

    return result[0..pos];
}

pub fn isPathTraversal(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |segment| {
        if (std.mem.eql(u8, segment, "..")) {
            return true;
        }
    }

    if (std.mem.indexOf(u8, path, "..\\") != null or
        std.mem.indexOf(u8, path, "\\..") != null)
    {
        return true;
    }

    return false;
}

pub fn trimWhitespace(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\n");
}

pub fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (toLowerChar(ca) != toLowerChar(cb)) return false;
    }
    return true;
}

fn toLowerChar(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

pub fn toLower(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const output = try allocator.alloc(u8, input.len);
    for (input, 0..) |c, i| {
        output[i] = std.ascii.toLower(c);
    }
    return output;
}

pub fn startsWith(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    return std.mem.eql(u8, haystack[0..needle.len], needle);
}

pub fn endsWith(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    return std.mem.eql(u8, haystack[haystack.len - needle.len ..], needle);
}

pub fn parseInt(comptime T: type, s: []const u8) ?T {
    return std.fmt.parseInt(T, s, 10) catch null;
}

pub fn parseFloat(comptime T: type, s: []const u8) ?T {
    return std.fmt.parseFloat(T, s) catch null;
}

pub fn formatTimestamp(buf: *[24]u8) []const u8 {
    const ts = std.time.timestamp();
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(ts) };
    const day_seconds = epoch_seconds.getDaySeconds();
    const epoch_day = epoch_seconds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();

    const hour = day_seconds.getHoursIntoDay();
    const minute = day_seconds.getMinutesIntoHour();
    const second = day_seconds.getSecondsIntoMinute();

    const year = year_day.year;
    const month_info = epoch_day.calculateYearDay();
    const month = month_info.month.numeric();
    const day = year_day.day_of_month;

    const result = std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}", .{
        year, month, day, hour, minute, second,
    }) catch return "";
    return result;
}

pub fn formatHttpDate(buf: *[29]u8, ts: i64) []const u8 {
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(ts) };
    const day_seconds = epoch_seconds.getDaySeconds();
    const epoch_day = epoch_seconds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();

    const hour = day_seconds.getHoursIntoDay();
    const minute = day_seconds.getMinutesIntoHour();
    const second = day_seconds.getSecondsIntoMinute();

    const year = year_day.year;
    const month_day = year_day.calculateMonthDay();
    const month = month_day.month;
    const day = month_day.day_index + 1;

    const day_of_week = (epoch_day.day + 3) % 7;

    const day_names = [_][]const u8{ "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
    const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    _ = std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        day_names[@as(usize, @intCast(day_of_week))],
        day,
        month_names[month.numeric() - 1],
        year,
        hour,
        minute,
        second,
    }) catch return "";
    return buf[0..29];
}

pub fn htmlEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    for (input) |c| {
        switch (c) {
            '<' => try result.appendSlice(allocator, "&lt;"),
            '>' => try result.appendSlice(allocator, "&gt;"),
            '&' => try result.appendSlice(allocator, "&amp;"),
            '"' => try result.appendSlice(allocator, "&quot;"),
            '\'' => try result.appendSlice(allocator, "&#x27;"),
            else => try result.append(allocator, c),
        }
    }

    return result.toOwnedSlice(allocator);
}

pub fn jsonEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    for (input) |c| {
        switch (c) {
            '"' => try result.appendSlice(allocator, "\\\""),
            '\\' => try result.appendSlice(allocator, "\\\\"),
            '\n' => try result.appendSlice(allocator, "\\n"),
            '\r' => try result.appendSlice(allocator, "\\r"),
            '\t' => try result.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    var buf: [6]u8 = undefined;
                    const hex = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c}) catch continue;
                    try result.appendSlice(allocator, hex);
                } else {
                    try result.append(allocator, c);
                }
            },
        }
    }

    return result.toOwnedSlice(allocator);
}

pub fn base64Encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const encoded_len = std.base64.standard.Encoder.calcSize(input.len);
    const result = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(result);

    _ = std.base64.standard.Encoder.encode(result, input);
    return result;
}

pub fn base64Decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(input) catch return error.OutOfMemory;
    const result = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(result);

    std.base64.standard.Decoder.decode(result, input) catch return error.OutOfMemory;
    return result;
}

pub fn generateRandomId(allocator: std.mem.Allocator, len: usize) ![]u8 {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const result = try allocator.alloc(u8, len);
    errdefer allocator.free(result);

    var prng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
    const random = prng.random();

    for (result) |*c| {
        c.* = chars[random.intRangeAtMost(usize, 0, chars.len - 1)];
    }

    return result;
}

pub fn joinPaths(allocator: std.mem.Allocator, base: []const u8, path: []const u8) ![]u8 {
    const base_trimmed = std.mem.trimRight(u8, base, "/");
    const path_trimmed = std.mem.trimLeft(u8, path, "/");

    const total_len = base_trimmed.len + 1 + path_trimmed.len;
    const result = try allocator.alloc(u8, total_len);

    @memcpy(result[0..base_trimmed.len], base_trimmed);
    result[base_trimmed.len] = '/';
    @memcpy(result[base_trimmed.len + 1 ..], path_trimmed);

    return result;
}

pub fn hashHmacSha256(data: []const u8, key: []const u8) [32]u8 {
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(key);
    hmac.update(data);
    var result: [32]u8 = undefined;
    hmac.final(&result);
    return result;
}

pub fn generateSecureBytes(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

pub fn generateSecureHex(allocator: std.mem.Allocator, byte_len: usize) ![]u8 {
    const bytes = try allocator.alloc(u8, byte_len);
    defer allocator.free(bytes);
    std.crypto.random.bytes(bytes);
    const hex_len = byte_len * 2;
    const hex = try allocator.alloc(u8, hex_len);
    _ = std.fmt.bufPrint(hex, "{x}", .{std.fmt.fmtSliceHexLower(bytes)}) catch return error.OutOfMemory;
    return hex;
}

pub fn base64UrlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded_len = encoder.calcSize(input.len);
    const result = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(result, input);
    return result;
}

pub fn base64UrlDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(input) catch return error.OutOfMemory;
    const result = try allocator.alloc(u8, decoded_len);
    decoder.decode(result, input) catch return error.OutOfMemory;
    return result;
}

pub fn timestamp() i64 {
    return std.time.timestamp();
}

pub fn timestampMs() i64 {
    return std.time.milliTimestamp();
}

test "urlDecode decodes percent-encoded strings" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const decoded = try urlDecode(allocator, "hello%20world");
    defer allocator.free(decoded);
    try testing.expectEqualStrings("hello world", decoded);

    const decoded2 = try urlDecode(allocator, "a%2Bb%3Dc");
    defer allocator.free(decoded2);
    try testing.expectEqualStrings("a+b=c", decoded2);
}

test "urlDecode handles plus as space" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const decoded = try urlDecode(allocator, "hello+world");
    defer allocator.free(decoded);
    try testing.expectEqualStrings("hello world", decoded);
}

test "urlEncode encodes special characters" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const encoded = try urlEncode(allocator, "hello world");
    defer allocator.free(encoded);
    try testing.expectEqualStrings("hello%20world", encoded);
}

test "parseQueryString parses correctly" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var map = try parseQueryString(allocator, "foo=bar&baz=qux");
    defer freeQueryMap(allocator, &map);

    try testing.expectEqualStrings("bar", map.get("foo").?);
    try testing.expectEqualStrings("qux", map.get("baz").?);
}

test "parseQueryString handles empty query" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var map = try parseQueryString(allocator, "");
    defer freeQueryMap(allocator, &map);

    try testing.expectEqual(@as(usize, 0), map.count());
}

test "isPathTraversal detects traversal attempts" {
    const testing = std.testing;
    try testing.expect(isPathTraversal("../etc/passwd"));
    try testing.expect(isPathTraversal("/foo/../bar"));
    try testing.expect(isPathTraversal("..\\windows\\system32"));
    try testing.expect(!isPathTraversal("/foo/bar/baz"));
    try testing.expect(!isPathTraversal("normal/path"));
}

test "eqlIgnoreCase compares correctly" {
    const testing = std.testing;
    try testing.expect(eqlIgnoreCase("Hello", "hello"));
    try testing.expect(eqlIgnoreCase("CONTENT-TYPE", "content-type"));
    try testing.expect(!eqlIgnoreCase("foo", "bar"));
    try testing.expect(!eqlIgnoreCase("foo", "foobar"));
}

test "htmlEscape escapes HTML characters" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const escaped = try htmlEscape(allocator, "<script>alert('xss')</script>");
    defer allocator.free(escaped);
    try testing.expectEqualStrings("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", escaped);
}

test "startsWith and endsWith work correctly" {
    const testing = std.testing;
    try testing.expect(startsWith("hello world", "hello"));
    try testing.expect(!startsWith("hello", "hello world"));
    try testing.expect(endsWith("hello world", "world"));
    try testing.expect(!endsWith("hello", "hello world"));
}

test "parseInt parses integers" {
    const testing = std.testing;
    try testing.expectEqual(@as(i32, 42), parseInt(i32, "42").?);
    try testing.expectEqual(@as(i32, -10), parseInt(i32, "-10").?);
    try testing.expect(parseInt(i32, "invalid") == null);
}

test "joinPaths joins correctly" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const joined = try joinPaths(allocator, "/foo/", "/bar/baz");
    defer allocator.free(joined);
    try testing.expectEqualStrings("/foo/bar/baz", joined);

    const joined2 = try joinPaths(allocator, "/foo", "bar");
    defer allocator.free(joined2);
    try testing.expectEqualStrings("/foo/bar", joined2);
}
