const std = @import("std");

const builtin = @import("builtin");

comptime {
    const required_zig = "0.14.0-dev.2545+e2e363361";
    const current_zig = builtin.zig_version;
    const min_zig = std.SemanticVersion.parse(required_zig) catch unreachable;
    if (current_zig.order(min_zig) == .lt) {
        const error_message = "Your version of zig is too old\nDownload {} or newer";
        @compileError(std.fmt.comptimePrint(error_message, .{min_zig}));
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe_mod.linkSystemLibrary("z", .{});

    const misshod_dep = b.dependency("misshod", .{
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("misshod", misshod_dep.module("misshod"));

    const exe = b.addExecutable(.{
        .name = "msshd",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    const auth_test_mod = b.createModule(.{
        .root_source_file = b.path("src/auth.zig"),
        .target = target,
        .optimize = optimize,
    });
    auth_test_mod.addImport("misshod", misshod_dep.module("misshod"));
    auth_test_mod.linkSystemLibrary("z", .{});
    const auth_tests = b.addTest(.{
        .root_module = auth_test_mod,
    });
    const run_auth_tests = b.addRunArtifact(auth_tests);

    const test_step = b.step("test", "Run msshd tests");
    test_step.dependOn(&run_auth_tests.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run");
    run_step.dependOn(&run_cmd.step);
}
