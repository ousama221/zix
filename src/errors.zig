const std = @import("std");
const constants = @import("constants.zig");

pub const ZixError = error{
    ServerStartFailed,
    ServerStopFailed,
    ConnectionFailed,
    ConnectionClosed,
    BindFailed,
    ListenFailed,
    AcceptFailed,
    SocketCreationFailed,
    SocketOptionFailed,
    DuplicateRoute,
    NoBody,

    RequestParseFailed,
    RequestTimeout,
    RequestTooLarge,
    InvalidMethod,
    InvalidUri,
    InvalidHttpVersion,
    InvalidHeader,
    InvalidBody,
    InvalidContentLength,
    InvalidChunkedEncoding,

    ResponseWriteFailed,
    ResponseAlreadySent,
    HeadersTooLarge,
    BodyTooLarge,

    RouteNotFound,
    MethodNotAllowed,
    RouteAlreadyExists,
    InvalidRoute,
    TooManyRoutes,
    TooManyParams,

    MiddlewareChainBroken,
    MiddlewareError,
    MiddlewareLimitExceeded,

    TemplateNotFound,
    TemplateParseError,
    TemplateRenderError,
    TemplateSyntaxError,
    TemplateIncludeDepthExceeded,
    TemplateVariableNotFound,
    TemplateCacheFull,

    StaticFileNotFound,
    StaticFileReadError,
    StaticFileTooLarge,
    DirectoryTraversal,
    InvalidPath,

    JsonParseError,
    JsonSerializeError,
    InvalidJsonContentType,

    SessionNotFound,
    SessionExpired,
    SessionCreateFailed,
    InvalidSessionId,

    CookieParseError,
    CookieTooLarge,
    InvalidCookieName,

    FormParseError,
    InvalidFormData,
    MultipartParseError,

    AllocationFailed,
    OutOfMemory,
    BufferOverflow,
    InvalidState,
    InternalError,

    SecurityViolation,
    CorsViolation,
    CsrfViolation,

    Unauthorized,
    Forbidden,
    BadRequest,
    NotAcceptable,
    Conflict,
    Gone,
    PayloadTooLarge,
    UriTooLong,
    UnsupportedMediaType,
    UnprocessableEntity,
    TooManyRequests,
    InternalServerError,
    NotImplemented,
    BadGateway,
    ServiceUnavailable,
    GatewayTimeout,
};

pub const ErrorInfo = struct {
    code: u16,
    message: []const u8,
    detail: ?[]const u8 = null,

    pub fn toJson(self: *const ErrorInfo, allocator: std.mem.Allocator) ![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(allocator);

        try list.appendSlice(allocator, "{\"error\":{\"code\":");
        var buf: [8]u8 = undefined;
        const code_str = std.fmt.bufPrint(&buf, "{d}", .{self.code}) catch return error.OutOfMemory;
        try list.appendSlice(allocator, code_str);
        try list.appendSlice(allocator, ",\"message\":\"");
        try appendJsonEscaped(&list, allocator, self.message);
        try list.appendSlice(allocator, "\"");
        if (self.detail) |d| {
            try list.appendSlice(allocator, ",\"detail\":\"");
            try appendJsonEscaped(&list, allocator, d);
            try list.appendSlice(allocator, "\"");
        }
        try list.appendSlice(allocator, "}}");
        return list.toOwnedSlice(allocator);
    }

    pub fn toHtml(self: *const ErrorInfo, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator,
            \\<!DOCTYPE html>
            \\<html lang="en">
            \\<head>
            \\<meta charset="UTF-8">
            \\<meta name="viewport" content="width=device-width, initial-scale=1.0">
            \\<title>Error {d}</title>
            \\<style>
            \\body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);}}
            \\.container{{text-align:center;color:white;padding:2rem;}}
            \\h1{{font-size:6rem;margin:0;text-shadow:2px 2px 4px rgba(0,0,0,0.2);}}
            \\p{{font-size:1.5rem;margin:1rem 0;opacity:0.9;}}
            \\.detail{{font-size:1rem;opacity:0.7;margin-top:0.5rem;}}
            \\a{{color:white;text-decoration:none;border:2px solid white;padding:0.75rem 1.5rem;border-radius:30px;display:inline-block;margin-top:1rem;transition:all 0.3s ease;}}
            \\a:hover{{background:white;color:#667eea;}}
            \\</style>
            \\</head>
            \\<body>
            \\<div class="container">
            \\<h1>{d}</h1>
            \\<p>{s}</p>
            \\{s}
            \\<a href="/">Go Home</a>
            \\</div>
            \\</body>
            \\</html>
        , .{
            self.code,
            self.code,
            self.message,
            if (self.detail) |d| blk: {
                break :blk std.fmt.allocPrint(allocator, "<p class=\"detail\">{s}</p>", .{d}) catch "";
            } else "",
        });
    }
};

fn appendJsonEscaped(list: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try list.appendSlice(allocator, "\\\""),
            '\\' => try list.appendSlice(allocator, "\\\\"),
            '\n' => try list.appendSlice(allocator, "\\n"),
            '\r' => try list.appendSlice(allocator, "\\r"),
            '\t' => try list.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    var buf: [6]u8 = undefined;
                    const hex = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c}) catch continue;
                    try list.appendSlice(allocator, hex);
                } else {
                    try list.append(allocator, c);
                }
            },
        }
    }
}

pub fn fromError(err: ZixError) ErrorInfo {
    return switch (err) {
        error.RouteNotFound => ErrorInfo{
            .code = constants.HttpStatus.NotFound,
            .message = "Not Found",
            .detail = "The requested resource was not found",
        },
        error.MethodNotAllowed => ErrorInfo{
            .code = constants.HttpStatus.MethodNotAllowed,
            .message = "Method Not Allowed",
            .detail = "The request method is not supported for this resource",
        },
        error.RequestTooLarge, error.BodyTooLarge, error.PayloadTooLarge => ErrorInfo{
            .code = constants.HttpStatus.PayloadTooLarge,
            .message = "Payload Too Large",
            .detail = "The request body exceeds the maximum allowed size",
        },
        error.BadRequest, error.RequestParseFailed, error.InvalidMethod, error.InvalidUri, error.InvalidHeader, error.InvalidBody => ErrorInfo{
            .code = constants.HttpStatus.BadRequest,
            .message = "Bad Request",
            .detail = "The request could not be understood by the server",
        },
        error.Unauthorized => ErrorInfo{
            .code = constants.HttpStatus.Unauthorized,
            .message = "Unauthorized",
            .detail = "Authentication is required",
        },
        error.Forbidden, error.SecurityViolation, error.DirectoryTraversal => ErrorInfo{
            .code = constants.HttpStatus.Forbidden,
            .message = "Forbidden",
            .detail = "Access to this resource is denied",
        },
        error.RequestTimeout => ErrorInfo{
            .code = constants.HttpStatus.RequestTimeout,
            .message = "Request Timeout",
            .detail = "The server timed out waiting for the request",
        },
        error.TooManyRequests => ErrorInfo{
            .code = constants.HttpStatus.TooManyRequests,
            .message = "Too Many Requests",
            .detail = "You have sent too many requests in a given amount of time",
        },
        error.UnprocessableEntity, error.JsonParseError, error.FormParseError => ErrorInfo{
            .code = constants.HttpStatus.UnprocessableEntity,
            .message = "Unprocessable Entity",
            .detail = "The request was well-formed but could not be processed",
        },
        error.StaticFileNotFound, error.TemplateNotFound => ErrorInfo{
            .code = constants.HttpStatus.NotFound,
            .message = "Not Found",
            .detail = "The requested file was not found",
        },
        error.NotImplemented => ErrorInfo{
            .code = constants.HttpStatus.NotImplemented,
            .message = "Not Implemented",
            .detail = "The server does not support this functionality",
        },
        error.ServiceUnavailable => ErrorInfo{
            .code = constants.HttpStatus.ServiceUnavailable,
            .message = "Service Unavailable",
            .detail = "The server is temporarily unavailable",
        },
        else => ErrorInfo{
            .code = constants.HttpStatus.InternalServerError,
            .message = "Internal Server Error",
            .detail = "An unexpected error occurred",
        },
    };
}

pub fn httpStatusToError(status_code: u16) ?ZixError {
    return switch (status_code) {
        400 => error.BadRequest,
        401 => error.Unauthorized,
        403 => error.Forbidden,
        404 => error.RouteNotFound,
        405 => error.MethodNotAllowed,
        408 => error.RequestTimeout,
        409 => error.Conflict,
        410 => error.Gone,
        413 => error.PayloadTooLarge,
        414 => error.UriTooLong,
        415 => error.UnsupportedMediaType,
        422 => error.UnprocessableEntity,
        429 => error.TooManyRequests,
        500 => error.InternalServerError,
        501 => error.NotImplemented,
        502 => error.BadGateway,
        503 => error.ServiceUnavailable,
        504 => error.GatewayTimeout,
        else => null,
    };
}

pub fn errorToHttpStatus(err: ZixError) u16 {
    return fromError(err).code;
}

test "fromError returns correct error info" {
    const testing = std.testing;

    const not_found = fromError(error.RouteNotFound);
    try testing.expectEqual(@as(u16, 404), not_found.code);
    try testing.expectEqualStrings("Not Found", not_found.message);

    const method_not_allowed = fromError(error.MethodNotAllowed);
    try testing.expectEqual(@as(u16, 405), method_not_allowed.code);

    const internal = fromError(error.InternalError);
    try testing.expectEqual(@as(u16, 500), internal.code);
}

test "ErrorInfo.toJson produces valid JSON" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const info = ErrorInfo{
        .code = 404,
        .message = "Not Found",
        .detail = "Resource not found",
    };

    const json = try info.toJson(allocator);
    defer allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"code\":404") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"message\":\"Not Found\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"detail\":\"Resource not found\"") != null);
}

test "ErrorInfo.toJson without detail" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const info = ErrorInfo{
        .code = 500,
        .message = "Internal Server Error",
    };

    const json = try info.toJson(allocator);
    defer allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"detail\"") == null);
}

test "httpStatusToError maps correctly" {
    const testing = std.testing;
    try testing.expectEqual(ZixError.BadRequest, httpStatusToError(400).?);
    try testing.expectEqual(ZixError.RouteNotFound, httpStatusToError(404).?);
    try testing.expectEqual(ZixError.InternalServerError, httpStatusToError(500).?);
    try testing.expect(httpStatusToError(200) == null);
}

test "errorToHttpStatus maps correctly" {
    const testing = std.testing;
    try testing.expectEqual(@as(u16, 404), errorToHttpStatus(error.RouteNotFound));
    try testing.expectEqual(@as(u16, 405), errorToHttpStatus(error.MethodNotAllowed));
    try testing.expectEqual(@as(u16, 500), errorToHttpStatus(error.InternalError));
}

test "appendJsonEscaped escapes special characters" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);

    try appendJsonEscaped(&list, allocator, "hello\nworld\"test\\");
    try testing.expectEqualStrings("hello\\nworld\\\"test\\\\", list.items);
}
