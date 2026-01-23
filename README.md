<div align="center">

<a href="https://muhammad-fiaz.github.io/zix/"><img src="https://img.shields.io/badge/docs-muhammad--fiaz.github.io-blue" alt="Documentation"></a>
<a href="https://ziglang.org/"><img src="https://img.shields.io/badge/Zig-0.15.0-orange.svg?logo=zig" alt="Zig Version"></a>
<a href="https://github.com/muhammad-fiaz/zix"><img src="https://img.shields.io/github/stars/muhammad-fiaz/zix" alt="GitHub stars"></a>
<a href="https://github.com/muhammad-fiaz/zix/issues"><img src="https://img.shields.io/github/issues/muhammad-fiaz/zix" alt="GitHub issues"></a>
<a href="https://github.com/muhammad-fiaz/zix/pulls"><img src="https://img.shields.io/github/issues-pr/muhammad-fiaz/zix" alt="GitHub pull requests"></a>
<a href="https://github.com/muhammad-fiaz/zix/blob/main/LICENSE"><img src="https://img.shields.io/github/license/muhammad-fiaz/zix" alt="License"></a>
<a href="https://github.com/muhammad-fiaz/zix/actions/workflows/ci.yml"><img src="https://github.com/muhammad-fiaz/zix/actions/workflows/ci.yml/badge.svg" alt="CI"></a>

<p><em>A fast, modern web framework for Zig.</em></p>

<b><a href="https://muhammad-fiaz.github.io/zix/">Documentation</a> |
<a href="https://muhammad-fiaz.github.io/zix/api/index">API Reference</a> |
<a href="https://muhammad-fiaz.github.io/zix/guide/getting-started">Quick Start</a> |
<a href="CONTRIBUTING.md">Contributing</a></b>

</div>

## Overview

Zix is a modern web framework for the Zig programming language. It provides a familiar, intuitive API for building web applications while leveraging Zig's performance, memory safety, and compile-time guarantees.

> [!NOTE]
> Zix is a work in progress and Docs are not yet ready but you can use `zig build docs` to generate docs.

**⭐️ If you love `zix`, make sure to give it a star! ⭐️**

## Quick Start

### Installation

Add Zix to your `build.zig.zon`:

```bash
zig fetch --save git+https://github.com/muhammad-fiaz/zix
```

Then in your `build.zig`:

```zig
const zix_dep = b.dependency("zix", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zix", zix_dep.module("zix"));
```

### Hello World

```zig
const std = @import("std");
const zix = @import("zix");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var app = try zix.createApp(allocator, .{
        .port = 3000,
    });
    defer {
        app.deinit();
        allocator.destroy(app);
    }

    try app.get("/", struct {
        fn handler(ctx: *zix.Context) !void {
            try ctx.text("Hello, World!");
        }
    }.handler);

    try app.get("/json", struct {
        fn handler(ctx: *zix.Context) !void {
            try ctx.json(.{ .message = "Hello!", .framework = "Zix" });
        }
    }.handler);

    try app.run();
}
```

## Configuration

All configuration is centralized in a single `Config` struct:

```zig
var app = try zix.createApp(allocator, .{
    .address = "0.0.0.0",
    .port = 8080,
    .enable_logging = true,
    .enable_security_headers = true,
    .cors_enabled = true,
    .cors_allow_origin = "*",
    .template_dir = "templates",
    .static_dir = "public",
    .static_mount_path = "/static",
    .debug_mode = true,
});
```

## Routing

```zig
// HTTP methods
try app.get("/users", listUsers);
try app.post("/users", createUser);
try app.put("/users/:id", updateUser);
try app.patch("/users/:id", patchUser);
try app.delete("/users/:id", deleteUser);

// Route parameters
try app.get("/users/:id", struct {
    fn handler(ctx: *zix.Context) !void {
        const id = ctx.param("id") orelse "unknown";
        try ctx.json(.{ .user_id = id });
    }
}.handler);

// Query parameters
try app.get("/search", struct {
    fn handler(ctx: *zix.Context) !void {
        const query = try ctx.query("q") orelse "";
        const page = try ctx.query("page") orelse "1";
        try ctx.json(.{ .query = query, .page = page });
    }
}.handler);
```

## Middleware

```zig
// Global middleware
try app.use(zix.middleware.securityHeaders());
try app.use(zix.middleware.cors());
try app.use(zix.middleware.recovery());

// Custom middleware
const authMiddleware = struct {
    fn check(ctx: *zix.Context, next: zix.NextFn) !void {
        const token = ctx.header("Authorization");
        if (token == null) {
            try ctx.unauthorized();
            ctx.abort();
            return;
        }
        try next(ctx);
    }
}.check;

try app.use(authMiddleware);
```

## Response Types

```zig
// Text
try ctx.text("Hello, World!");

// HTML
try ctx.html("<h1>Welcome</h1>");

// JSON
try ctx.json(.{ .status = "ok", .count = 42 });

// Redirect
try ctx.redirect("/login");

// File download
try ctx.sendFile("report.pdf", "monthly-report.pdf");

// Status codes
_ = ctx.status(201);
try ctx.json(.{ .created = true });

// Cookies
try ctx.setCookie(.{
    .name = "session",
    .value = "abc123",
    .max_age = 3600,
    .http_only = true,
});
```

## External Logger

Plug in your own logging backend:

```zig
fn myLogger(level: zix.Level, message: []const u8, timestamp: i64) void {
    // Send to your logging service
    std.debug.print("[{s}] {s}\n", .{ level.toString(), message });
}

app.setExternalLogger(myLogger);
```

## Static Files

```zig
try app.static("/assets", "public");
```

Files in `public/` will be served at `/assets/`:
- `public/css/style.css` → `/assets/css/style.css`
- `public/js/app.js` → `/assets/js/app.js`

## Templates

```zig
app.enableTemplates();

try app.get("/", struct {
    fn handler(ctx: *zix.Context) !void {
        try ctx.render("index.html", .{
            .title = "Welcome",
            .user = "Alice",
        });
    }
}.handler);
```

Template syntax:
```html
<h1>{{ title }}</h1>
{% if user %}
  <p>Hello, {{ user }}!</p>
{% endif %}
{% for item in items %}
  <li>{{ item }}</li>
{% endfor %}
```

## Error Handling

```zig
// Custom 404 handler
app.notFound(struct {
    fn handler(ctx: *zix.Context) !void {
        _ = ctx.status(404);
        try ctx.json(.{ .error = "Resource not found" });
    }
}.handler);

// Custom error handler for specific errors
try app.errorHandler("MyError", struct {
    fn handler(ctx: *zix.Context, err: anyerror) anyerror!void {
        _ = err;
        try ctx.status(500).json(.{ .error = "A custom error occurred" });
    }
}.handler);
```

## Building and Running

```bash
# Build the library
zig build

# Run tests
zig build test

# Build and run examples
zig build example-basic
zig build run-basic

zig build example-json-api
zig build run-json-api

# Generate documentation
zig build docs
```

## License

This project is licensed under the Apache-2.0 License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.
