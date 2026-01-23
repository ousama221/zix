const std = @import("std");
const constants = @import("constants.zig");
const Config = @import("config.zig").Config;
const utils = @import("utils.zig");

pub const TemplateError = error{
    TemplateNotFound,
    TemplateSyntaxError,
    TemplateRenderError,
    TemplateIncludeDepthExceeded,
    TemplateVariableNotFound,
    TemplateCacheFull,
    OutOfMemory,
};

pub const Template = struct {
    allocator: std.mem.Allocator,
    content: []const u8,
    name: []const u8,
    compiled: bool,
    nodes: std.ArrayListUnmanaged(Node),
    parent: ?[]const u8,
    blocks: std.StringHashMap(std.ArrayListUnmanaged(Node)),

    pub const Node = union(enum) {
        text: []const u8,
        variable: []const u8,
        escaped_variable: []const u8,
        if_start: []const u8,
        if_else: void,
        if_end: void,
        for_start: ForLoop,
        for_end: void,
        include: []const u8,
        block: []const u8,
        end_block: void,
        extends: []const u8,
        raw: []const u8,
    };

    pub const ForLoop = struct {
        item: []const u8,
        collection: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator, name: []const u8, content: []const u8) Template {
        return Template{
            .allocator = allocator,
            .content = content,
            .name = name,
            .compiled = false,
            .nodes = .{},
            .parent = null,
            .blocks = std.StringHashMap(std.ArrayListUnmanaged(Node)).init(allocator),
        };
    }

    pub fn deinit(self: *Template) void {
        self.nodes.deinit(self.allocator);
        var it = self.blocks.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.blocks.deinit();
    }

    pub fn compile(self: *Template) !void {
        if (self.compiled) return;

        self.nodes.clearRetainingCapacity();

        var pos: usize = 0;
        const content = self.content;
        var current_block_name: ?[]const u8 = null;

        while (pos < content.len) {
            const var_start_opt = std.mem.indexOf(u8, content[pos..], constants.Templates.variable_start);
            const tag_start_opt = std.mem.indexOf(u8, content[pos..], constants.Templates.block_start);

            var next_pos = content.len;
            var is_var = false;

            if (var_start_opt) |vs| {
                next_pos = pos + vs;
                is_var = true;
            }
            if (tag_start_opt) |ts| {
                const tag_abs = pos + ts;
                if (tag_abs < next_pos) {
                    next_pos = tag_abs;
                    is_var = false;
                }
            }

            if (next_pos > pos) {
                const text_node = Node{ .text = content[pos..next_pos] };
                try self.addNode(text_node, current_block_name);
            }

            if (next_pos == content.len) break;

            if (is_var) {
                const end_marker = constants.Templates.variable_end;
                if (std.mem.indexOf(u8, content[next_pos..], end_marker)) |end_idx| {
                    const inner = std.mem.trim(u8, content[next_pos + constants.Templates.variable_start.len .. next_pos + end_idx], " \t\r\n");

                    if (inner.len > 0 and inner[0] == '!') {
                        try self.addNode(Node{ .raw = inner[1..] }, current_block_name);
                    } else {
                        try self.addNode(Node{ .escaped_variable = inner }, current_block_name);
                    }
                    pos = next_pos + end_idx + end_marker.len;
                } else {
                    try self.addNode(Node{ .text = content[next_pos..] }, current_block_name);
                    break;
                }
            } else {
                const end_marker = constants.Templates.block_end;
                if (std.mem.indexOf(u8, content[next_pos..], end_marker)) |end_idx| {
                    const inner = std.mem.trim(u8, content[next_pos + constants.Templates.block_start.len .. next_pos + end_idx], " \t\r\n");
                    const node = try parseTag(inner);

                    switch (node) {
                        .extends => |parent| {
                            self.parent = parent;
                        },
                        .block => |name| {
                            current_block_name = name;
                            try self.blocks.put(name, .{});
                        },
                        .end_block => {
                            if (current_block_name) |name| {
                                try self.nodes.append(self.allocator, Node{ .block = name });
                                current_block_name = null;
                            }
                        },
                        else => {
                            try self.addNode(node, current_block_name);
                        },
                    }
                    pos = next_pos + end_idx + end_marker.len;
                } else {
                    try self.addNode(Node{ .text = content[next_pos..] }, current_block_name);
                    break;
                }
            }
        }

        self.compiled = true;
    }

    fn addNode(self: *Template, node: Node, block_name: ?[]const u8) !void {
        if (block_name) |name| {
            if (self.blocks.getPtr(name)) |list| {
                try list.append(self.allocator, node);
            }
        } else {
            try self.nodes.append(self.allocator, node);
        }
    }
};

fn parseTag(inner: []const u8) !Template.Node {
    var it = std.mem.tokenizeAny(u8, inner, " \t\r\n");
    const keyword = it.next() orelse return Template.Node{ .text = "" };

    if (std.mem.eql(u8, keyword, "if")) {
        return Template.Node{ .if_start = it.rest() };
    } else if (std.mem.eql(u8, keyword, "else")) {
        return Template.Node.if_else;
    } else if (std.mem.eql(u8, keyword, "endif")) {
        return Template.Node.if_end;
    } else if (std.mem.eql(u8, keyword, "for")) {
        const item = it.next() orelse return TemplateError.TemplateSyntaxError;
        _ = it.next();
        const collection = it.rest();
        return Template.Node{ .for_start = .{ .item = item, .collection = collection } };
    } else if (std.mem.eql(u8, keyword, "endfor")) {
        return Template.Node.for_end;
    } else if (std.mem.eql(u8, keyword, "block")) {
        return Template.Node{ .block = it.rest() };
    } else if (std.mem.eql(u8, keyword, "endblock")) {
        return Template.Node.end_block;
    } else if (std.mem.eql(u8, keyword, "extends")) {
        const path = std.mem.trim(u8, it.rest(), "\"' ");
        return Template.Node{ .extends = path };
    } else if (std.mem.eql(u8, keyword, "include")) {
        const path = std.mem.trim(u8, it.rest(), "\"' ");
        return Template.Node{ .include = path };
    }

    return Template.Node{ .text = "" };
}

pub const TemplateEngine = struct {
    allocator: std.mem.Allocator,
    config: *const Config,
    cache: std.StringHashMap(Template),
    cache_enabled: bool,

    pub fn init(allocator: std.mem.Allocator, config: *const Config) TemplateEngine {
        return TemplateEngine{
            .allocator = allocator,
            .config = config,
            .cache = std.StringHashMap(Template).init(allocator),
            .cache_enabled = true,
        };
    }

    pub fn deinit(self: *TemplateEngine) void {
        var it = self.cache.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
            self.allocator.free(entry.value_ptr.content);
            self.allocator.free(entry.value_ptr.name);
        }
        self.cache.deinit();
    }

    pub fn load(self: *TemplateEngine, name: []const u8) !*Template {
        if (self.cache_enabled) {
            if (self.cache.getPtr(name)) |t| return t;
        }

        const path = try utils.joinPaths(self.allocator, self.config.template_dir, name);
        defer self.allocator.free(path);

        const f = std.fs.cwd().openFile(path, .{}) catch return TemplateError.TemplateNotFound;
        defer f.close();

        const content = f.readToEndAlloc(self.allocator, constants.Templates.max_template_size) catch return TemplateError.TemplateSyntaxError;
        errdefer self.allocator.free(content);

        const name_dup = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_dup);

        var tmpl = Template.init(self.allocator, name_dup, content);
        try tmpl.compile();

        if (self.cache_enabled) {
            const key_dup = try self.allocator.dupe(u8, name);
            try self.cache.put(key_dup, tmpl);
            return self.cache.getPtr(name).?;
        }
        return &tmpl;
    }

    pub fn render(self: *TemplateEngine, name: []const u8, data: anytype) anyerror![]u8 {
        const tmpl = try self.load(name);
        if (tmpl.parent) |parent_name| {
            return self.renderParent(parent_name, tmpl.blocks, data);
        }
        return self.renderNodes(tmpl.nodes.items, null, data);
    }

    fn renderParent(self: *TemplateEngine, parent_name: []const u8, child_blocks: std.StringHashMap(std.ArrayListUnmanaged(Template.Node)), data: anytype) ![]u8 {
        const parent = try self.load(parent_name);
        if (parent.parent) |grandparent| {
            var merged_blocks = std.StringHashMap(std.ArrayListUnmanaged(Template.Node)).init(self.allocator);
            defer merged_blocks.deinit();

            var it = parent.blocks.iterator();
            while (it.next()) |entry| {
                if (child_blocks.get(entry.key_ptr.*)) |child_nodes| {
                    try merged_blocks.put(entry.key_ptr.*, child_nodes);
                } else {
                    try merged_blocks.put(entry.key_ptr.*, entry.value_ptr.*);
                }
            }

            var child_it = child_blocks.iterator();
            while (child_it.next()) |entry| {
                if (!merged_blocks.contains(entry.key_ptr.*)) {
                    try merged_blocks.put(entry.key_ptr.*, entry.value_ptr.*);
                }
            }

            return self.renderParent(grandparent, merged_blocks, data);
        }

        return self.renderNodes(parent.nodes.items, &child_blocks, data);
    }

    fn renderNodes(self: *TemplateEngine, nodes: []const Template.Node, blocks: ?*const std.StringHashMap(std.ArrayListUnmanaged(Template.Node)), data: anytype) ![]u8 {
        var result: std.ArrayListUnmanaged(u8) = .{};
        errdefer result.deinit(self.allocator);

        var i: usize = 0;
        var skip = false;
        var depth: usize = 0;

        while (i < nodes.len) : (i += 1) {
            const node = nodes[i];

            if (skip) {
                switch (node) {
                    .if_start => depth += 1,
                    .if_end => {
                        if (depth == 0) {
                            skip = false;
                        } else {
                            depth -= 1;
                        }
                    },
                    .if_else => {
                        if (depth == 0) skip = false;
                    },
                    else => {},
                }
                continue;
            }

            switch (node) {
                .text => |t| try result.appendSlice(self.allocator, t),
                .variable, .escaped_variable => |name| {
                    if (try self.resolve(data, name)) |val| {
                        defer self.allocator.free(val);
                        if (node == .escaped_variable) {
                            const esc = try utils.htmlEscape(self.allocator, val);
                            defer self.allocator.free(esc);
                            try result.appendSlice(self.allocator, esc);
                        } else {
                            try result.appendSlice(self.allocator, val);
                        }
                    }
                },
                .raw => |name| {
                    if (try self.resolve(data, name)) |val| {
                        defer self.allocator.free(val);
                        try result.appendSlice(self.allocator, val);
                    }
                },
                .if_start => |cond| {
                    if (!try self.eval(data, cond)) skip = true;
                },
                .if_else => skip = true,
                .if_end => {},
                .include => |path| {
                    const content = try self.render(path, data);
                    defer self.allocator.free(content);
                    try result.appendSlice(self.allocator, content);
                },
                .block => |name| {
                    const target_nodes = if (self.getBlock(blocks, name)) |bn| bn else &std.ArrayListUnmanaged(Template.Node){};
                    if (target_nodes.items.len > 0) {
                        const content = try self.renderNodes(target_nodes.items, blocks, data);
                        defer self.allocator.free(content);
                        try result.appendSlice(self.allocator, content);
                    }
                },
                .extends => {},
                .for_start => |loop_info| {
                    var loop_end = i + 1;
                    var d: usize = 1;
                    while (loop_end < nodes.len) : (loop_end += 1) {
                        switch (nodes[loop_end]) {
                            .for_start => d += 1,
                            .for_end => {
                                d -= 1;
                                if (d == 0) break;
                            },
                            else => {},
                        }
                    }

                    const loop_body = nodes[i + 1 .. loop_end];
                    try self.renderLoop(loop_body, blocks, data, loop_info, &result);
                    i = loop_end;
                },
                else => {},
            }
        }
        return result.toOwnedSlice(self.allocator);
    }

    fn getBlock(self: *TemplateEngine, blocks: ?*const std.StringHashMap(std.ArrayListUnmanaged(Template.Node)), name: []const u8) ?*const std.ArrayListUnmanaged(Template.Node) {
        _ = self;
        if (blocks) |b| {
            if (b.getPtr(name)) |ptr| return ptr;
        }
        return null;
    }

    fn renderLoop(self: *TemplateEngine, nodes: []const Template.Node, blocks: ?*const std.StringHashMap(std.ArrayListUnmanaged(Template.Node)), data: anytype, info: Template.ForLoop, result: *std.ArrayListUnmanaged(u8)) !void {
        const T = @TypeOf(data);
        const type_info = @typeInfo(T);
        if (type_info != .@"struct") return;

        inline for (type_info.@"struct".fields) |field| {
            if (std.mem.eql(u8, field.name, info.collection)) {
                const collection = @field(data, field.name);
                const CType = @TypeOf(collection);
                const c_info = @typeInfo(CType);

                if (c_info == .pointer and c_info.pointer.size == .one and @typeInfo(c_info.pointer.child) == .array) {
                    for (collection.*) |it| {
                        const content = try self.renderNodes(nodes, blocks, it);
                        defer self.allocator.free(content);
                        try result.appendSlice(self.allocator, content);
                    }
                    return;
                }

                if (c_info == .array or (c_info == .pointer and c_info.pointer.size == .slice)) {
                    for (collection) |it| {
                        const content = try self.renderNodes(nodes, blocks, it);
                        defer self.allocator.free(content);
                        try result.appendSlice(self.allocator, content);
                    }
                    return;
                }
                return;
            }
        }
    }

    fn resolve(self: *TemplateEngine, data: anytype, path: []const u8) !?[]u8 {
        const T = @TypeOf(data);
        const type_info = @typeInfo(T);

        if (type_info == .@"struct") {
            inline for (type_info.@"struct".fields) |field| {
                if (std.mem.eql(u8, field.name, path)) {
                    const val = @field(data, field.name);
                    return try self.stringify(val);
                }
            }
        }
        return null;
    }

    fn eval(self: *TemplateEngine, data: anytype, cond: []const u8) !bool {
        if (try self.resolve(data, cond)) |val| {
            defer self.allocator.free(val);
            if (val.len == 0) return false;
            if (std.mem.eql(u8, val, "false")) return false;
            if (std.mem.eql(u8, val, "0")) return false;
            return true;
        }
        return false;
    }

    fn stringify(self: *TemplateEngine, val: anytype) ![]u8 {
        const T = @TypeOf(val);
        const info = @typeInfo(T);

        if (T == []const u8) return self.allocator.dupe(u8, val);
        if (T == []u8) return self.allocator.dupe(u8, val);

        if (info == .int or info == .float) {
            return std.fmt.allocPrint(self.allocator, "{d}", .{val});
        }
        if (T == bool) {
            return std.fmt.allocPrint(self.allocator, "{}", .{val});
        }
        if (info == .pointer) {
            if (info.pointer.size == .slice and info.pointer.child == u8) {
                return self.allocator.dupe(u8, val);
            }
            if (info.pointer.size == .one) {
                return self.stringify(val.*);
            }
        }
        if (info == .array) {
            if (info.array.child == u8) {
                return std.fmt.allocPrint(self.allocator, "{s}", .{val});
            }
        }
        return self.allocator.dupe(u8, "");
    }
};
