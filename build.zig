const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.createModule(.{
        .root_source_file = b.path("src/zix.zig"),
    });

    const exposed_module = b.addModule("zix", .{
        .root_source_file = b.path("src/zix.zig"),
    });

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zix.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");

    const builtin = @import("builtin");
    if (target.result.os.tag == builtin.os.tag and target.result.cpu.arch == builtin.cpu.arch) {
        test_step.dependOn(&run_tests.step);
    } else {
        const install_tests = b.addInstallArtifact(tests, .{});
        test_step.dependOn(&install_tests.step);
    }

    const lib = b.addLibrary(.{
        .name = "zix",
        .linkage = .static,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zix.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(lib);

    const install_docs = b.addInstallDirectory(.{
        .source_dir = lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&install_docs.step);

    const examples = [_]struct { name: []const u8, path: []const u8, skip_run_all: bool }{
        .{ .name = "basic", .path = "examples/basic.zig", .skip_run_all = true },
        .{ .name = "json-api", .path = "examples/json_api.zig", .skip_run_all = true },
        .{ .name = "static-files", .path = "examples/static_files.zig", .skip_run_all = true },
        .{ .name = "templates", .path = "examples/templates.zig", .skip_run_all = true },
        .{ .name = "advanced-api", .path = "examples/advanced_api.zig", .skip_run_all = true },
        .{ .name = "session", .path = "examples/session_example.zig", .skip_run_all = true },
    };

    const run_all_examples = b.step("run-all-examples", "Run all examples sequentially");
    var previous_run_step: ?*std.Build.Step = null;

    inline for (examples) |example| {
        const exe = b.addExecutable(.{
            .name = "example-" ++ example.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(example.path),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });

        exe.root_module.addImport("zix", exposed_module);

        if (target.result.os.tag == .windows) {
            exe.root_module.linkSystemLibrary("ws2_32", .{});
        }

        const install_exe = b.addInstallArtifact(exe, .{});
        const example_step = b.step("example-" ++ example.name, "Build " ++ example.name ++ " example");
        example_step.dependOn(&install_exe.step);

        const run_exe = b.addRunArtifact(exe);
        run_exe.step.dependOn(&install_exe.step);
        run_exe.addArg("--help");

        const run_step = b.step("run-" ++ example.name, "Run " ++ example.name ++ " example");
        run_step.dependOn(&run_exe.step);

        if (!example.skip_run_all) {
            const run_all_exe = b.addRunArtifact(exe);
            run_all_exe.addArg("--help");

            if (previous_run_step) |prev| {
                run_all_exe.step.dependOn(prev);
            }
            previous_run_step = &run_all_exe.step;
        }
    }

    if (previous_run_step) |last| {
        run_all_examples.dependOn(last);
    }
}
