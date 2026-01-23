const std = @import("std");

pub const Version = struct {
    pub const major: u32 = 0;
    pub const minor: u32 = 0;
    pub const patch: u32 = 1;
    pub const string = "0.0.1";
    pub const full = "Zix/0.0.1";
};

pub const Framework = struct {
    pub const name = "Zix";
    pub const description = "A fast, modern web framework for Zig";
    pub const homepage = "https://github.com/zix-framework/zix";
    pub const license = "MIT";
};

pub const Defaults = struct {
    pub const port: u16 = 3000;
    pub const address = "127.0.0.1";
    pub const max_body_size: usize = 10 * 1024 * 1024;
    pub const max_header_size: usize = 8 * 1024;
    pub const max_uri_size: usize = 8 * 1024;
    pub const read_timeout_ms: u32 = 30_000;
    pub const write_timeout_ms: u32 = 30_000;
    pub const keep_alive_timeout_ms: u32 = 60_000;
    pub const max_connections: u32 = 1024;
    pub const buffer_size: usize = 16 * 1024;
    pub const server_name = "Zix/" ++ Version.string;
    pub const template_dir = "templates";
    pub const static_dir = "static";
    pub const static_mount_path = "/static";
};

pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    TRACE,
    CONNECT,

    pub fn fromString(s: []const u8) ?HttpMethod {
        return method_map.get(s);
    }

    pub fn toString(self: HttpMethod) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .PATCH => "PATCH",
            .HEAD => "HEAD",
            .OPTIONS => "OPTIONS",
            .TRACE => "TRACE",
            .CONNECT => "CONNECT",
        };
    }

    const method_map = std.StaticStringMap(HttpMethod).initComptime(.{
        .{ "GET", .GET },
        .{ "POST", .POST },
        .{ "PUT", .PUT },
        .{ "DELETE", .DELETE },
        .{ "PATCH", .PATCH },
        .{ "HEAD", .HEAD },
        .{ "OPTIONS", .OPTIONS },
        .{ "TRACE", .TRACE },
        .{ "CONNECT", .CONNECT },
    });
};

pub const HttpStatus = struct {
    pub const Continue: u16 = 100;
    pub const SwitchingProtocols: u16 = 101;
    pub const Processing: u16 = 102;
    pub const EarlyHints: u16 = 103;

    pub const OK: u16 = 200;
    pub const Created: u16 = 201;
    pub const Accepted: u16 = 202;
    pub const NonAuthoritativeInfo: u16 = 203;
    pub const NoContent: u16 = 204;
    pub const ResetContent: u16 = 205;
    pub const PartialContent: u16 = 206;
    pub const MultiStatus: u16 = 207;
    pub const AlreadyReported: u16 = 208;

    pub const MultipleChoices: u16 = 300;
    pub const MovedPermanently: u16 = 301;
    pub const Found: u16 = 302;
    pub const SeeOther: u16 = 303;
    pub const NotModified: u16 = 304;
    pub const UseProxy: u16 = 305;
    pub const TemporaryRedirect: u16 = 307;
    pub const PermanentRedirect: u16 = 308;

    pub const BadRequest: u16 = 400;
    pub const Unauthorized: u16 = 401;
    pub const PaymentRequired: u16 = 402;
    pub const Forbidden: u16 = 403;
    pub const NotFound: u16 = 404;
    pub const MethodNotAllowed: u16 = 405;
    pub const NotAcceptable: u16 = 406;
    pub const ProxyAuthRequired: u16 = 407;
    pub const RequestTimeout: u16 = 408;
    pub const Conflict: u16 = 409;
    pub const Gone: u16 = 410;
    pub const LengthRequired: u16 = 411;
    pub const PreconditionFailed: u16 = 412;
    pub const PayloadTooLarge: u16 = 413;
    pub const URITooLong: u16 = 414;
    pub const UnsupportedMediaType: u16 = 415;
    pub const RangeNotSatisfiable: u16 = 416;
    pub const ExpectationFailed: u16 = 417;
    pub const ImATeapot: u16 = 418;
    pub const MisdirectedRequest: u16 = 421;
    pub const UnprocessableEntity: u16 = 422;
    pub const Locked: u16 = 423;
    pub const FailedDependency: u16 = 424;
    pub const TooEarly: u16 = 425;
    pub const UpgradeRequired: u16 = 426;
    pub const PreconditionRequired: u16 = 428;
    pub const TooManyRequests: u16 = 429;
    pub const RequestHeaderFieldsTooLarge: u16 = 431;
    pub const UnavailableForLegalReasons: u16 = 451;

    pub const InternalServerError: u16 = 500;
    pub const NotImplemented: u16 = 501;
    pub const BadGateway: u16 = 502;
    pub const ServiceUnavailable: u16 = 503;
    pub const GatewayTimeout: u16 = 504;
    pub const HTTPVersionNotSupported: u16 = 505;
    pub const VariantAlsoNegotiates: u16 = 506;
    pub const InsufficientStorage: u16 = 507;
    pub const LoopDetected: u16 = 508;
    pub const NotExtended: u16 = 510;
    pub const NetworkAuthRequired: u16 = 511;

    pub fn getPhrase(code: u16) []const u8 {
        return switch (code) {
            100 => "Continue",
            101 => "Switching Protocols",
            102 => "Processing",
            103 => "Early Hints",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            203 => "Non-Authoritative Information",
            204 => "No Content",
            205 => "Reset Content",
            206 => "Partial Content",
            207 => "Multi-Status",
            208 => "Already Reported",
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            305 => "Use Proxy",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Payload Too Large",
            414 => "URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Range Not Satisfiable",
            417 => "Expectation Failed",
            418 => "I'm a teapot",
            421 => "Misdirected Request",
            422 => "Unprocessable Entity",
            423 => "Locked",
            424 => "Failed Dependency",
            425 => "Too Early",
            426 => "Upgrade Required",
            428 => "Precondition Required",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            451 => "Unavailable For Legal Reasons",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            505 => "HTTP Version Not Supported",
            506 => "Variant Also Negotiates",
            507 => "Insufficient Storage",
            508 => "Loop Detected",
            510 => "Not Extended",
            511 => "Network Authentication Required",
            else => "Unknown Status",
        };
    }

    pub fn isSuccess(code: u16) bool {
        return code >= 200 and code < 300;
    }

    pub fn isRedirect(code: u16) bool {
        return code >= 300 and code < 400;
    }

    pub fn isClientError(code: u16) bool {
        return code >= 400 and code < 500;
    }

    pub fn isServerError(code: u16) bool {
        return code >= 500 and code < 600;
    }

    pub fn isError(code: u16) bool {
        return code >= 400;
    }
};

pub const MimeTypes = struct {
    pub const html = "text/html; charset=utf-8";
    pub const json = "application/json; charset=utf-8";
    pub const xml = "application/xml; charset=utf-8";
    pub const plain = "text/plain; charset=utf-8";
    pub const css = "text/css; charset=utf-8";
    pub const javascript = "application/javascript; charset=utf-8";
    pub const form = "application/x-www-form-urlencoded";
    pub const multipart = "multipart/form-data";
    pub const octet_stream = "application/octet-stream";
    pub const png = "image/png";
    pub const jpeg = "image/jpeg";
    pub const gif = "image/gif";
    pub const webp = "image/webp";
    pub const svg = "image/svg+xml";
    pub const ico = "image/x-icon";
    pub const woff = "font/woff";
    pub const woff2 = "font/woff2";
    pub const ttf = "font/ttf";
    pub const otf = "font/otf";
    pub const eot = "application/vnd.ms-fontobject";
    pub const pdf = "application/pdf";
    pub const zip = "application/zip";
    pub const gzip = "application/gzip";
    pub const mp3 = "audio/mpeg";
    pub const mp4 = "video/mp4";
    pub const webm = "video/webm";
    pub const ogg = "audio/ogg";
    pub const wav = "audio/wav";
    pub const avi = "video/x-msvideo";
    pub const markdown = "text/markdown; charset=utf-8";
    pub const yaml = "text/yaml; charset=utf-8";
    pub const csv = "text/csv; charset=utf-8";
    pub const ics = "text/calendar; charset=utf-8";
    pub const wasm = "application/wasm";
    pub const tar = "application/x-tar";
    pub const rar = "application/vnd.rar";
    pub const bz2 = "application/x-bzip2";
    pub const xz = "application/x-xz";
    pub const sevenZ = "application/x-7z-compressed";
    pub const doc = "application/msword";
    pub const docx = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    pub const xls = "application/vnd.ms-excel";
    pub const xlsx = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    pub const ppt = "application/vnd.ms-powerpoint";
    pub const pptx = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    pub const rtf = "application/rtf";
    pub const epub = "application/epub+zip";
    pub const flac = "audio/flac";
    pub const aac = "audio/aac";
    pub const m4a = "audio/mp4";
    pub const mkv = "video/x-matroska";
    pub const mov = "video/quicktime";
    pub const flv = "video/x-flv";
    pub const wmv = "video/x-ms-wmv";
    pub const bmp = "image/bmp";
    pub const tiff = "image/tiff";
    pub const avif = "image/avif";
    pub const heic = "image/heic";
    pub const apng = "image/apng";
    pub const sourcemap = "application/json";
    pub const ts_file = "video/mp2t";
    pub const tsx = "text/tsx";
    pub const jsx = "text/jsx";
    pub const vue = "text/x-vue";
    pub const scss = "text/x-scss";
    pub const sass = "text/x-sass";
    pub const less = "text/x-less";

    pub fn fromExtension(ext: []const u8) []const u8 {
        return extension_map.get(ext) orelse octet_stream;
    }

    pub fn fromPath(path: []const u8) []const u8 {
        const ext = std.fs.path.extension(path);
        return fromExtension(ext);
    }

    const extension_map = std.StaticStringMap([]const u8).initComptime(.{
        .{ ".html", html },
        .{ ".htm", html },
        .{ ".json", json },
        .{ ".xml", xml },
        .{ ".txt", plain },
        .{ ".css", css },
        .{ ".js", javascript },
        .{ ".mjs", javascript },
        .{ ".png", png },
        .{ ".jpg", jpeg },
        .{ ".jpeg", jpeg },
        .{ ".gif", gif },
        .{ ".webp", webp },
        .{ ".svg", svg },
        .{ ".ico", ico },
        .{ ".woff", woff },
        .{ ".woff2", woff2 },
        .{ ".ttf", ttf },
        .{ ".otf", otf },
        .{ ".eot", eot },
        .{ ".pdf", pdf },
        .{ ".zip", zip },
        .{ ".gz", gzip },
        .{ ".mp3", mp3 },
        .{ ".mp4", mp4 },
        .{ ".webm", webm },
        .{ ".ogg", ogg },
        .{ ".wav", wav },
        .{ ".avi", avi },
        .{ ".md", markdown },
        .{ ".yaml", yaml },
        .{ ".yml", yaml },
        .{ ".csv", csv },
        .{ ".ics", ics },
        .{ ".wasm", wasm },
        .{ ".tar", tar },
        .{ ".rar", rar },
        .{ ".bz2", bz2 },
        .{ ".xz", xz },
        .{ ".7z", sevenZ },
        .{ ".doc", doc },
        .{ ".docx", docx },
        .{ ".xls", xls },
        .{ ".xlsx", xlsx },
        .{ ".ppt", ppt },
        .{ ".pptx", pptx },
        .{ ".rtf", rtf },
        .{ ".epub", epub },
        .{ ".flac", flac },
        .{ ".aac", aac },
        .{ ".m4a", m4a },
        .{ ".mkv", mkv },
        .{ ".mov", mov },
        .{ ".flv", flv },
        .{ ".wmv", wmv },
        .{ ".bmp", bmp },
        .{ ".tiff", tiff },
        .{ ".tif", tiff },
        .{ ".avif", avif },
        .{ ".heic", heic },
        .{ ".apng", apng },
        .{ ".map", sourcemap },
        .{ ".ts", ts_file },
        .{ ".tsx", tsx },
        .{ ".jsx", jsx },
        .{ ".vue", vue },
        .{ ".scss", scss },
        .{ ".sass", sass },
        .{ ".less", less },
    });
};

pub const Headers = struct {
    pub const ContentType = "Content-Type";
    pub const ContentLength = "Content-Length";
    pub const ContentEncoding = "Content-Encoding";
    pub const ContentDisposition = "Content-Disposition";
    pub const CacheControl = "Cache-Control";
    pub const Pragma = "Pragma";
    pub const ETag = "ETag";
    pub const LastModified = "Last-Modified";
    pub const IfModifiedSince = "If-Modified-Since";
    pub const IfNoneMatch = "If-None-Match";
    pub const Expires = "Expires";
    pub const Location = "Location";
    pub const Authorization = "Authorization";
    pub const WWWAuthenticate = "WWW-Authenticate";
    pub const Cookie = "Cookie";
    pub const SetCookie = "Set-Cookie";
    pub const Host = "Host";
    pub const UserAgent = "User-Agent";
    pub const Accept = "Accept";
    pub const AcceptLanguage = "Accept-Language";
    pub const AcceptEncoding = "Accept-Encoding";
    pub const Connection = "Connection";
    pub const KeepAlive = "Keep-Alive";
    pub const XFrameOptions = "X-Frame-Options";
    pub const XContentTypeOptions = "X-Content-Type-Options";
    pub const XXSSProtection = "X-XSS-Protection";
    pub const ReferrerPolicy = "Referrer-Policy";
    pub const ContentSecurityPolicy = "Content-Security-Policy";
    pub const StrictTransportSecurity = "Strict-Transport-Security";
    pub const PermissionsPolicy = "Permissions-Policy";
    pub const AccessControlAllowOrigin = "Access-Control-Allow-Origin";
    pub const AccessControlAllowMethods = "Access-Control-Allow-Methods";
    pub const AccessControlAllowHeaders = "Access-Control-Allow-Headers";
    pub const AccessControlExposeHeaders = "Access-Control-Expose-Headers";
    pub const AccessControlMaxAge = "Access-Control-Max-Age";
    pub const AccessControlAllowCredentials = "Access-Control-Allow-Credentials";
    pub const XRequestId = "X-Request-Id";
    pub const XForwardedFor = "X-Forwarded-For";
    pub const XForwardedProto = "X-Forwarded-Proto";
    pub const XForwardedHost = "X-Forwarded-Host";
    pub const XRealIP = "X-Real-IP";
    pub const Server = "Server";
    pub const Date = "Date";
    pub const Vary = "Vary";
    pub const Origin = "Origin";
    pub const Referer = "Referer";
    pub const Range = "Range";
    pub const ContentRange = "Content-Range";
    pub const AcceptRanges = "Accept-Ranges";
    pub const TransferEncoding = "Transfer-Encoding";
};

pub const Security = struct {
    pub const default_x_frame_options = "DENY";
    pub const default_x_content_type_options = "nosniff";
    pub const default_x_xss_protection = "1; mode=block";
    pub const default_referrer_policy = "strict-origin-when-cross-origin";
    pub const default_csp = "default-src 'self'";
    pub const default_hsts = "max-age=31536000; includeSubDomains";
};

pub const Session = struct {
    pub const cookie_name = "zix_session";
    pub const default_max_age: i64 = 86400;
    pub const secure_cookie = true;
    pub const http_only = true;
    pub const same_site = "Strict";
};

pub const Auth = struct {
    pub const default_token_lifetime: i64 = 3600;
    pub const refresh_token_lifetime: i64 = 604800;
    pub const salt_length: usize = 16;
    pub const hash_length: usize = 32;
    pub const session_key_user_id = "_user_id";
    pub const session_key_authenticated = "_authenticated";
    pub const session_key_role = "_role";
    pub const session_key_remember = "_remember";
    pub const bearer_prefix = "Bearer ";
    pub const basic_prefix = "Basic ";
    pub const default_login_view = "/login";
    pub const api_key_header = "X-API-Key";
};

pub const Static = struct {
    pub const default_cache_max_age: u32 = 86400;
    pub const index_files = &[_][]const u8{ "index.html", "index.htm" };
    pub const default_charset = "utf-8";
};

pub const Plugin = struct {
    pub const default_directory = "plugins";
    pub const auto_discover = false;
    pub const enabled_default = true;
};

pub const Logger = struct {
    pub const default_level = "info";
    pub const format_text = "text";
    pub const format_json = "json";
    pub const format_compact = "compact";

    pub const color_trace = "\x1b[90m";
    pub const color_debug = "\x1b[36m";
    pub const color_info = "\x1b[32m";
    pub const color_warn = "\x1b[33m";
    pub const color_err = "\x1b[31m";
    pub const color_fatal = "\x1b[35m";
    pub const color_reset = "\x1b[0m";
    pub const color_bold = "\x1b[1m";
    pub const color_dim = "\x1b[90m";
};

pub const Response = struct {
    pub const default_content_type = "text/plain; charset=utf-8";
    pub const html_content_type = "text/html; charset=utf-8";
    pub const json_content_type = "application/json; charset=utf-8";
    pub const xml_content_type = "application/xml; charset=utf-8";
};

pub const Templates = struct {
    pub const default_extension = ".html";
    pub const variable_start = "{{";
    pub const variable_end = "}}";
    pub const block_start = "{%";
    pub const block_end = "%}";
    pub const comment_start = "{#";
    pub const comment_end = "#}";
    pub const max_template_size: usize = 5 * 1024 * 1024;
    pub const max_include_depth: usize = 50;
};

pub const Router = struct {
    pub const param_prefix: u8 = ':';
    pub const wildcard: u8 = '*';
    pub const max_params: usize = 20;
};

pub const ErrorPages = struct {
    pub const @"400" =
        \\<!DOCTYPE html>
        \\<html lang="en">
        \\<head>
        \\    <meta charset="UTF-8">
        \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
        \\    <title>400 - Bad Request</title>
        \\    <style>
        \\        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        \\        .container { text-align: center; padding: 2rem; }
        \\        h1 { font-size: 6rem; margin: 0; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        \\        p { font-size: 1.5rem; opacity: 0.9; }
        \\        a { color: white; text-decoration: underline; }
        \\    </style>
        \\</head>
        \\<body>
        \\    <div class="container">
        \\        <h1>400</h1>
        \\        <p>Bad Request</p>
        \\        <p>The server could not understand your request.</p>
        \\        <a href="/">Return Home</a>
        \\    </div>
        \\</body>
        \\</html>
    ;

    pub const @"401" =
        \\<!DOCTYPE html>
        \\<html lang="en">
        \\<head>
        \\    <meta charset="UTF-8">
        \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
        \\    <title>401 - Unauthorized</title>
        \\    <style>
        \\        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; }
        \\        .container { text-align: center; padding: 2rem; }
        \\        h1 { font-size: 6rem; margin: 0; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        \\        p { font-size: 1.5rem; opacity: 0.9; }
        \\        a { color: white; text-decoration: underline; }
        \\    </style>
        \\</head>
        \\<body>
        \\    <div class="container">
        \\        <h1>401</h1>
        \\        <p>Unauthorized</p>
        \\        <p>Authentication is required to access this resource.</p>
        \\        <a href="/">Return Home</a>
        \\    </div>
        \\</body>
        \\</html>
    ;

    pub const @"403" =
        \\<!DOCTYPE html>
        \\<html lang="en">
        \\<head>
        \\    <meta charset="UTF-8">
        \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
        \\    <title>403 - Forbidden</title>
        \\    <style>
        \\        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%); color: #333; }
        \\        .container { text-align: center; padding: 2rem; }
        \\        h1 { font-size: 6rem; margin: 0; text-shadow: 2px 2px 4px rgba(0,0,0,0.1); }
        \\        p { font-size: 1.5rem; opacity: 0.8; }
        \\        a { color: #333; text-decoration: underline; }
        \\    </style>
        \\</head>
        \\<body>
        \\    <div class="container">
        \\        <h1>403</h1>
        \\        <p>Forbidden</p>
        \\        <p>You don't have permission to access this resource.</p>
        \\        <a href="/">Return Home</a>
        \\    </div>
        \\</body>
        \\</html>
    ;

    pub const @"404" =
        \\<!DOCTYPE html>
        \\<html lang="en">
        \\<head>
        \\    <meta charset="UTF-8">
        \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
        \\    <title>404 - Page Not Found</title>
        \\    <style>
        \\        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white; }
        \\        .container { text-align: center; padding: 2rem; }
        \\        h1 { font-size: 8rem; margin: 0; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); animation: pulse 2s infinite; }
        \\        @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.05); } }
        \\        p { font-size: 1.5rem; opacity: 0.9; }
        \\        a { color: white; text-decoration: underline; transition: opacity 0.3s; }
        \\        a:hover { opacity: 0.8; }
        \\    </style>
        \\</head>
        \\<body>
        \\    <div class="container">
        \\        <h1>404</h1>
        \\        <p>Oops! The page you're looking for doesn't exist.</p>
        \\        <a href="/">Return Home</a>
        \\    </div>
        \\</body>
        \\</html>
    ;

    pub const @"405" =
        \\<!DOCTYPE html>
        \\<html lang="en">
        \\<head>
        \\    <meta charset="UTF-8">
        \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
        \\    <title>405 - Method Not Allowed</title>
        \\    <style>
        \\        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white; }
        \\        .container { text-align: center; padding: 2rem; }
        \\        h1 { font-size: 6rem; margin: 0; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        \\        p { font-size: 1.5rem; opacity: 0.9; }
        \\        a { color: white; text-decoration: underline; }
        \\    </style>
        \\</head>
        \\<body>
        \\    <div class="container">
        \\        <h1>405</h1>
        \\        <p>Method Not Allowed</p>
        \\        <p>The request method is not supported for this resource.</p>
        \\        <a href="/">Return Home</a>
        \\    </div>
        \\</body>
        \\</html>
    ;

    pub const @"500" =
        \\<!DOCTYPE html>
        \\<html lang="en">
        \\<head>
        \\    <meta charset="UTF-8">
        \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
        \\    <title>500 - Internal Server Error</title>
        \\    <style>
        \\        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: linear-gradient(135deg, #434343 0%, #000000 100%); color: white; }
        \\        .container { text-align: center; padding: 2rem; }
        \\        h1 { font-size: 6rem; margin: 0; text-shadow: 2px 2px 4px rgba(0,0,0,0.5); }
        \\        p { font-size: 1.5rem; opacity: 0.9; }
        \\        a { color: #4facfe; text-decoration: underline; }
        \\    </style>
        \\</head>
        \\<body>
        \\    <div class="container">
        \\        <h1>500</h1>
        \\        <p>Internal Server Error</p>
        \\        <p>Something went wrong on our end. Please try again later.</p>
        \\        <a href="/">Return Home</a>
        \\    </div>
        \\</body>
        \\</html>
    ;

    pub const @"503" =
        \\<!DOCTYPE html>
        \\<html lang="en">
        \\<head>
        \\    <meta charset="UTF-8">
        \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
        \\    <title>503 - Service Unavailable</title>
        \\    <style>
        \\        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%); color: #333; }
        \\        .container { text-align: center; padding: 2rem; }
        \\        h1 { font-size: 6rem; margin: 0; text-shadow: 2px 2px 4px rgba(0,0,0,0.1); }
        \\        p { font-size: 1.5rem; opacity: 0.8; }
        \\        a { color: #333; text-decoration: underline; }
        \\        .spinner { display: inline-block; width: 30px; height: 30px; border: 3px solid rgba(0,0,0,0.2); border-radius: 50%; border-top-color: #333; animation: spin 1s linear infinite; margin-top: 1rem; }
        \\        @keyframes spin { to { transform: rotate(360deg); } }
        \\    </style>
        \\</head>
        \\<body>
        \\    <div class="container">
        \\        <h1>503</h1>
        \\        <p>Service Temporarily Unavailable</p>
        \\        <p>We're performing maintenance. Please check back soon.</p>
        \\        <div class="spinner"></div>
        \\        <br><br>
        \\        <a href="/">Retry</a>
        \\    </div>
        \\</body>
        \\</html>
    ;

    pub fn getPage(status: u16) []const u8 {
        return switch (status) {
            400 => @"400",
            401 => @"401",
            403 => @"403",
            404 => @"404",
            405 => @"405",
            500 => @"500",
            503 => @"503",
            else => @"500",
        };
    }
};

test "HttpMethod.fromString" {
    const testing = @import("std").testing;
    try testing.expectEqual(HttpMethod.GET, HttpMethod.fromString("GET").?);
    try testing.expectEqual(HttpMethod.POST, HttpMethod.fromString("POST").?);
    try testing.expect(HttpMethod.fromString("INVALID") == null);
}

test "HttpStatus.getPhrase" {
    const testing = @import("std").testing;
    try testing.expectEqualStrings("OK", HttpStatus.getPhrase(200));
    try testing.expectEqualStrings("Not Found", HttpStatus.getPhrase(404));
    try testing.expectEqualStrings("Internal Server Error", HttpStatus.getPhrase(500));
}

test "HttpStatus category checks" {
    const testing = @import("std").testing;
    try testing.expect(HttpStatus.isSuccess(200));
    try testing.expect(HttpStatus.isSuccess(201));
    try testing.expect(!HttpStatus.isSuccess(404));
    try testing.expect(HttpStatus.isRedirect(301));
    try testing.expect(HttpStatus.isClientError(404));
    try testing.expect(HttpStatus.isServerError(500));
    try testing.expect(HttpStatus.isError(400));
    try testing.expect(HttpStatus.isError(500));
}

test "MimeTypes.fromExtension" {
    const testing = @import("std").testing;
    try testing.expectEqualStrings(MimeTypes.html, MimeTypes.fromExtension(".html"));
    try testing.expectEqualStrings(MimeTypes.json, MimeTypes.fromExtension(".json"));
    try testing.expectEqualStrings(MimeTypes.octet_stream, MimeTypes.fromExtension(".unknown"));
}

test "ErrorPages.getPage" {
    const testing = @import("std").testing;
    try testing.expect(ErrorPages.getPage(404).len > 0);
    try testing.expect(ErrorPages.getPage(500).len > 0);
}
