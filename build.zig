const std = @import("std");
const builtin = @import("builtin");

comptime {
    const required_zig = "0.16.0";
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

    // UNSAFE: This may print plaintext packets, private keys, shared secrets,
    // and derived encryption/MAC keys. Never enable it in production or CI.
    const unsafe_secret_tracing = b.option(
        bool,
        "unsafe-secret-tracing",
        "UNSAFE: allow diagnostic dumps of plaintext and cryptographic secrets",
    ) orelse false;
    const options = b.addOptions();
    options.addOption(bool, "unsafe_secret_tracing", unsafe_secret_tracing);

    const mod = b.addModule("misshod", .{
        .root_source_file = b.path("src/misshod.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addOptions("misshod_build_options", options);
    mod.linkSystemLibrary("z", .{});

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addOptions("misshod_build_options", options);
    test_mod.linkSystemLibrary("z", .{});

    const lib_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_lib_tests = b.addRunArtifact(lib_tests);

    const safe_trace_options = b.addOptions();
    safe_trace_options.addOption(bool, "unsafe_secret_tracing", false);
    const safe_trace_test_mod = b.createModule(.{
        .root_source_file = b.path("src/trace_gate_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    safe_trace_test_mod.addOptions("misshod_build_options", safe_trace_options);
    const safe_trace_tests = b.addTest(.{
        .root_module = safe_trace_test_mod,
    });
    const run_safe_trace_tests = b.addRunArtifact(safe_trace_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_safe_trace_tests.step);

    const production_client_mod = b.createModule(.{
        .root_source_file = b.path("examples/production/client.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    production_client_mod.addImport("misshod", mod);
    production_client_mod.linkSystemLibrary("z", .{});
    const production_client = b.addExecutable(.{
        .name = "misshod-production-client-example",
        .root_module = production_client_mod,
    });
    const production_client_tests = b.addTest(.{
        .root_module = production_client_mod,
    });
    const run_production_client_tests = b.addRunArtifact(production_client_tests);

    const production_server_mod = b.createModule(.{
        .root_source_file = b.path("examples/production/server.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    production_server_mod.addImport("misshod", mod);
    production_server_mod.addAnonymousImport("production_test_host_key", .{
        .root_source_file = b.path("testserver/id_ed25519_passwordless"),
    });
    production_server_mod.linkSystemLibrary("z", .{});
    const production_server = b.addExecutable(.{
        .name = "misshod-production-server-example",
        .root_module = production_server_mod,
    });
    const production_server_tests = b.addTest(.{
        .root_module = production_server_mod,
    });
    const run_production_server_tests = b.addRunArtifact(production_server_tests);

    const production_examples_step = b.step(
        "production-examples",
        "Compile-check production client and server integration examples",
    );
    production_examples_step.dependOn(&production_client.step);
    production_examples_step.dependOn(&production_server.step);
    production_examples_step.dependOn(&run_production_client_tests.step);
    production_examples_step.dependOn(&run_production_server_tests.step);

    const malformed_mod = b.createModule(.{
        .root_source_file = b.path("test/malformed.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    malformed_mod.addImport("misshod", mod);
    malformed_mod.linkSystemLibrary("z", .{});
    const malformed_tests = b.addTest(.{
        .root_module = malformed_mod,
    });
    const run_malformed_tests = b.addRunArtifact(malformed_tests);
    const malformed_step = b.step("malformed", "Run the bounded deterministic malformed-input corpus");
    malformed_step.dependOn(&run_malformed_tests.step);

    const stress_mod = b.createModule(.{
        .root_source_file = b.path("test/stress/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    stress_mod.addImport("misshod", mod);
    stress_mod.addAnonymousImport("stress_host_key", .{
        .root_source_file = b.path("testserver/id_ed25519_passwordless"),
    });
    stress_mod.linkSystemLibrary("z", .{});
    const stress_exe = b.addExecutable(.{
        .name = "misshod-stress",
        .root_module = stress_mod,
    });

    const run_stress = b.addRunArtifact(stress_exe);
    if (b.args) |args| run_stress.addArgs(args);
    const stress_step = b.step("stress", "Run deterministic in-process stress acceptance");
    stress_step.dependOn(&run_stress.step);

    const soak_cmd = b.addSystemCommand(&.{ "bash", "test/stress/soak.sh" });
    soak_cmd.addArtifactArg(stress_exe);
    if (b.args) |args| soak_cmd.addArgs(args);
    const soak_step = b.step("soak", "Run duration/seed/peer-selected soak coverage");
    soak_step.dependOn(&soak_cmd.step);

    const interop_cmd = b.addSystemCommand(&.{ "bash", "interop/run.sh" });
    interop_cmd.step.dependOn(&run_lib_tests.step);

    const interop_step = b.step("interop", "Run OpenSSH/libssh interoperability tests");
    interop_step.dependOn(&interop_cmd.step);
}
