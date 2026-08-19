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

    // These are diagnostic tools: their traces are the point, so they ask
    // for what the library no longer prints by default.
    const misshod_dep = b.dependency("misshod", .{
        .target = target,
        .optimize = optimize,
        .trace = .info,
    });
    exe_mod.addImport("misshod", misshod_dep.module("misshod"));

    const exe = b.addExecutable(.{
        .name = "mssh",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run");
    run_step.dependOn(&run_cmd.step);

    const known_hosts_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/known_hosts.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "misshod", .module = misshod_dep.module("misshod") },
            },
        }),
    });
    const run_known_hosts_tests = b.addRunArtifact(known_hosts_tests);
    const test_step = b.step("test", "Run mssh tests");
    test_step.dependOn(&run_known_hosts_tests.step);
}



