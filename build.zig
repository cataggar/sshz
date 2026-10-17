const std = @import("std");
const builtin = @import("builtin");

comptime {
    const required_zig = "0.17.0";
    const current_zig = builtin.zig_version;
    const min_zig = std.SemanticVersion.parse(required_zig) catch unreachable;
    if (current_zig.order(min_zig) == .lt) {
        const error_message = "Your version of zig is too old\nDownload {} or newer";
        @compileError(std.fmt.comptimePrint(error_message, .{min_zig}));
    }
}

/// zlib is built from source rather than taken from the system.
///
/// `zlib@openssh.com` compression is not optional -- `protocol.zig` reaches
/// `zlib.h` unconditionally -- so a system library made the whole package
/// unbuildable anywhere one is not installed and discoverable, Windows
/// included. The dependency carries zlib's own sources and compiles them for
/// whatever target is being built, so the same `zig build` works on every
/// host, and every module here links the one static artifact.
fn linkZlib(b: *std.Build, mod: *std.Build.Module) void {
    const dep = b.dependency("zlib", .{
        .target = mod.resolved_target.?,
        .optimize = mod.optimize.?,
    });
    mod.linkLibrary(dep.artifact("z"));
    const translate_dep = b.dependency("translate_c", .{});
    const bindings: @import("translate_c").Translator = .init(translate_dep, .{
        .name = "sshz-zlib",
        .c_source_file = b.addWriteFiles().add("sshz-zlib.h",
            \\#define Z_SOLO 1
            \\#include <zlib.h>
            \\
        ),
        .target = mod.resolved_target.?,
        .optimize = mod.optimize.?,
        .link_libc = false,
    });
    // Only stream APIs are needed. Z_SOLO excludes file-I/O headers, so the
    // bindings also translate for Android before the consumer supplies an NDK.
    bindings.addIncludePath(dep.path(""));
    mod.addImport("zlib-c", bindings.mod);
}

/// How much the library is allowed to print.
///
/// `off` by default because an application that links sshz owns its own
/// stderr -- and, if it draws a terminal UI, its own screen. `sshz` and
/// `sshzd` ask for `info`.
pub const TraceLevel = enum { off, info, debug };

/// What a build gets when it does not ask. Named so `trace_off_test` can
/// assert on it: changing this to anything but `off` fails the suite.
const default_trace_level: TraceLevel = .off;
const default_channel_capacity: u8 = 4;

/// What `-Dversion` reports when nobody passes one.
///
/// The tag is the source of truth for a release: a tagged build passes
/// `-Dversion=${GITHUB_REF_NAME#v}` and stamps its own tag. This fallback
/// tracks the version declared in `build.zig.zon` so an untagged build
/// still reports something truthful.
const default_version = "0.2.1";

/// Emitted as a name rather than the enum itself so `util.zig` keeps one
/// definition of the level and maps onto it explicitly.
fn addTraceLevel(options: *std.Build.Step.Options, level: TraceLevel) void {
    options.addOption([]const u8, "trace_level", @tagName(level));
}

pub const AlgorithmOptions = struct {
    kex_mlkem1024nistp384_sha384: bool = true,
    kex_mlkem768nistp256_sha256: bool = true,
    kex_mlkem768x25519_sha256: bool = true,
    kex_curve25519_sha256: bool = true,
    kex_ecdh_sha2_nistp384: bool = true,
    kex_ecdh_sha2_nistp256: bool = true,
    cipher_aes256_gcm: bool = true,
    cipher_chacha20_poly1305: bool = true,
    cipher_aes128_gcm: bool = true,
    cipher_aes256_ctr: bool = true,
    cipher_aes192_ctr: bool = true,
    cipher_aes128_ctr: bool = true,
    mac_hmac_sha2_512_etm: bool = true,
    mac_hmac_sha2_256_etm: bool = true,
    mac_hmac_sha2_512: bool = true,
    mac_hmac_sha2_256: bool = true,
    sig_ssh_mldsa87_p384: bool = true,
    sig_ssh_mldsa44_ed25519: bool = true,
    sig_ecdsa_sha2_nistp384: bool = true,
    sig_ssh_ed25519: bool = true,
    sig_ecdsa_sha2_nistp256: bool = true,
    sig_rsa_sha2_512: bool = true,
    sig_rsa_sha2_256: bool = true,
};

fn addAlgorithmOptions(options: *std.Build.Step.Options, alg: AlgorithmOptions) void {
    options.addOption(bool, "kex_mlkem1024nistp384_sha384", alg.kex_mlkem1024nistp384_sha384);
    options.addOption(bool, "kex_mlkem768nistp256_sha256", alg.kex_mlkem768nistp256_sha256);
    options.addOption(bool, "kex_mlkem768x25519_sha256", alg.kex_mlkem768x25519_sha256);
    options.addOption(bool, "kex_curve25519_sha256", alg.kex_curve25519_sha256);
    options.addOption(bool, "kex_ecdh_sha2_nistp384", alg.kex_ecdh_sha2_nistp384);
    options.addOption(bool, "kex_ecdh_sha2_nistp256", alg.kex_ecdh_sha2_nistp256);
    options.addOption(bool, "cipher_aes256_gcm", alg.cipher_aes256_gcm);
    options.addOption(bool, "cipher_chacha20_poly1305", alg.cipher_chacha20_poly1305);
    options.addOption(bool, "cipher_aes128_gcm", alg.cipher_aes128_gcm);
    options.addOption(bool, "cipher_aes256_ctr", alg.cipher_aes256_ctr);
    options.addOption(bool, "cipher_aes192_ctr", alg.cipher_aes192_ctr);
    options.addOption(bool, "cipher_aes128_ctr", alg.cipher_aes128_ctr);
    options.addOption(bool, "mac_hmac_sha2_512_etm", alg.mac_hmac_sha2_512_etm);
    options.addOption(bool, "mac_hmac_sha2_256_etm", alg.mac_hmac_sha2_256_etm);
    options.addOption(bool, "mac_hmac_sha2_512", alg.mac_hmac_sha2_512);
    options.addOption(bool, "mac_hmac_sha2_256", alg.mac_hmac_sha2_256);
    options.addOption(bool, "sig_ssh_mldsa87_p384", alg.sig_ssh_mldsa87_p384);
    options.addOption(bool, "sig_ssh_mldsa44_ed25519", alg.sig_ssh_mldsa44_ed25519);
    options.addOption(bool, "sig_ecdsa_sha2_nistp384", alg.sig_ecdsa_sha2_nistp384);
    options.addOption(bool, "sig_ssh_ed25519", alg.sig_ssh_ed25519);
    options.addOption(bool, "sig_ecdsa_sha2_nistp256", alg.sig_ecdsa_sha2_nistp256);
    options.addOption(bool, "sig_rsa_sha2_512", alg.sig_rsa_sha2_512);
    options.addOption(bool, "sig_rsa_sha2_256", alg.sig_rsa_sha2_256);
}

fn addSshzOptions(
    options: *std.Build.Step.Options,
    unsafe_secret_tracing: bool,
    trace_level: TraceLevel,
    channel_capacity: u8,
    version: []const u8,
) void {
    options.addOption(bool, "unsafe_secret_tracing", unsafe_secret_tracing);
    addTraceLevel(options, trace_level);
    options.addOption(u8, "channel_capacity", channel_capacity);
    options.addOption([]const u8, "version", version);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const trace_level = b.option(
        TraceLevel,
        "trace",
        "How much sshz prints to stderr (default: off)",
    ) orelse default_trace_level;

    // UNSAFE: This may print plaintext packets, private keys, shared secrets,
    // and derived encryption/MAC keys. Never enable it in production or CI.
    const unsafe_secret_tracing = b.option(
        bool,
        "unsafe-secret-tracing",
        "UNSAFE: allow diagnostic dumps of plaintext and cryptographic secrets",
    ) orelse false;
    const channel_capacity = b.option(
        u8,
        "channel_capacity",
        "Compile-time channel-table capacity (default: 4)",
    ) orelse default_channel_capacity;
    const version = b.option(
        []const u8,
        "version",
        "Version string reported by the library (release builds pass the tag)",
    ) orelse default_version;
    const secure_algorithms = b.option(
        bool,
        "secure-algorithms",
        "Enable the default suite of modern SSH algorithms (default: true). Set false to select individual algorithms.",
    ) orelse true;
    const alg_options = AlgorithmOptions{
        .kex_mlkem1024nistp384_sha384 = b.option(bool, "mlkem1024nistp384-sha384", "Enable mlkem1024nistp384-sha384 KEX") orelse secure_algorithms,
        .kex_mlkem768nistp256_sha256 = b.option(bool, "mlkem768nistp256-sha256", "Enable mlkem768nistp256-sha256 KEX") orelse secure_algorithms,
        .kex_mlkem768x25519_sha256 = b.option(bool, "mlkem768x25519-sha256", "Enable mlkem768x25519-sha256 KEX") orelse secure_algorithms,
        .kex_curve25519_sha256 = b.option(bool, "curve25519-sha256", "Enable curve25519-sha256 and curve25519-sha256@libssh.org KEX") orelse secure_algorithms,
        .kex_ecdh_sha2_nistp384 = b.option(bool, "ecdh-sha2-nistp384", "Enable ecdh-sha2-nistp384 KEX") orelse secure_algorithms,
        .kex_ecdh_sha2_nistp256 = b.option(bool, "ecdh-sha2-nistp256", "Enable ecdh-sha2-nistp256 KEX") orelse secure_algorithms,
        .cipher_aes256_gcm = b.option(bool, "aes256-gcm", "Enable aes256-gcm@openssh.com cipher") orelse secure_algorithms,
        .cipher_chacha20_poly1305 = b.option(bool, "chacha20-poly1305", "Enable chacha20-poly1305@openssh.com cipher") orelse secure_algorithms,
        .cipher_aes128_gcm = b.option(bool, "aes128-gcm", "Enable aes128-gcm@openssh.com cipher") orelse secure_algorithms,
        .cipher_aes256_ctr = b.option(bool, "aes256-ctr", "Enable aes256-ctr cipher") orelse secure_algorithms,
        .cipher_aes192_ctr = b.option(bool, "aes192-ctr", "Enable aes192-ctr cipher") orelse secure_algorithms,
        .cipher_aes128_ctr = b.option(bool, "aes128-ctr", "Enable aes128-ctr cipher") orelse secure_algorithms,
        .mac_hmac_sha2_512_etm = b.option(bool, "hmac-sha2-512-etm", "Enable hmac-sha2-512-etm@openssh.com MAC") orelse secure_algorithms,
        .mac_hmac_sha2_256_etm = b.option(bool, "hmac-sha2-256-etm", "Enable hmac-sha2-256-etm@openssh.com MAC") orelse secure_algorithms,
        .mac_hmac_sha2_512 = b.option(bool, "hmac-sha2-512", "Enable hmac-sha2-512 MAC") orelse secure_algorithms,
        .mac_hmac_sha2_256 = b.option(bool, "hmac-sha2-256", "Enable hmac-sha2-256 MAC") orelse secure_algorithms,
        .sig_ssh_mldsa87_p384 = b.option(bool, "ssh-mldsa87-p384", "Enable the ssh-mldsa87-p384 composite signature algorithm") orelse secure_algorithms,
        .sig_ssh_mldsa44_ed25519 = b.option(bool, "ssh-mldsa44-ed25519", "Enable the ssh-mldsa44-ed25519 composite signature algorithm") orelse secure_algorithms,
        .sig_ecdsa_sha2_nistp384 = b.option(bool, "ecdsa-sha2-nistp384", "Enable the ecdsa-sha2-nistp384 signature algorithm") orelse secure_algorithms,
        .sig_ssh_ed25519 = b.option(bool, "ssh-ed25519", "Enable the ssh-ed25519 signature algorithm") orelse secure_algorithms,
        .sig_ecdsa_sha2_nistp256 = b.option(bool, "ecdsa-sha2-nistp256", "Enable the ecdsa-sha2-nistp256 signature algorithm") orelse secure_algorithms,
        .sig_rsa_sha2_512 = b.option(bool, "rsa-sha2-512", "Enable the rsa-sha2-512 signature algorithm") orelse secure_algorithms,
        .sig_rsa_sha2_256 = b.option(bool, "rsa-sha2-256", "Enable the rsa-sha2-256 signature algorithm") orelse secure_algorithms,
    };
    const options = b.addOptions();
    addSshzOptions(options, unsafe_secret_tracing, trace_level, channel_capacity, version);
    addAlgorithmOptions(options, alg_options);

    const mod = b.addModule("sshz", .{
        .root_source_file = b.path("src/sshz.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addOptions("sshz_build_options", options);
    linkZlib(b, mod);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addOptions("sshz_build_options", options);
    linkZlib(b, test_mod);

    const lib_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_lib_tests = b.addRunArtifact(lib_tests);

    const safe_trace_options = b.addOptions();
    addSshzOptions(safe_trace_options, false, trace_level, channel_capacity, version);
    addAlgorithmOptions(safe_trace_options, alg_options);
    const safe_trace_test_mod = b.createModule(.{
        .root_source_file = b.path("src/trace_gate_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    safe_trace_test_mod.addOptions("sshz_build_options", safe_trace_options);
    const safe_trace_tests = b.addTest(.{
        .root_module = safe_trace_test_mod,
    });
    const run_safe_trace_tests = b.addRunArtifact(safe_trace_tests);

    // Built with the options a dependent gets, not the ones this invocation
    // was given, so `zig build test -Dtrace=info` does not silently excuse
    // the default from staying quiet.
    const default_trace_options = b.addOptions();
    addSshzOptions(default_trace_options, false, default_trace_level, default_channel_capacity, version);
    addAlgorithmOptions(default_trace_options, .{});
    const trace_off_test_mod = b.createModule(.{
        .root_source_file = b.path("src/trace_off_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    trace_off_test_mod.addOptions("sshz_build_options", default_trace_options);
    const trace_off_tests = b.addTest(.{
        .root_module = trace_off_test_mod,
    });
    const run_trace_off_tests = b.addRunArtifact(trace_off_tests);

    const configured_capacity_options = b.addOptions();
    addSshzOptions(configured_capacity_options, false, default_trace_level, 8, version);
    addAlgorithmOptions(configured_capacity_options, .{});
    const configured_capacity_test_mod = b.createModule(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    configured_capacity_test_mod.addOptions("sshz_build_options", configured_capacity_options);
    linkZlib(b, configured_capacity_test_mod);
    const configured_capacity_tests = b.addTest(.{
        .root_module = configured_capacity_test_mod,
        .filters = &.{"configured channel capacity supports concurrent tunnel channels"},
    });
    const run_configured_capacity_tests = b.addRunArtifact(configured_capacity_tests);

    const restricted_sig_options = b.addOptions();
    addSshzOptions(restricted_sig_options, false, default_trace_level, default_channel_capacity, version);
    addAlgorithmOptions(restricted_sig_options, .{
        .sig_ssh_mldsa87_p384 = true,
        .sig_ssh_mldsa44_ed25519 = false,
        .sig_ecdsa_sha2_nistp384 = true,
        .sig_ssh_ed25519 = false,
        .sig_ecdsa_sha2_nistp256 = false,
        .sig_rsa_sha2_512 = false,
        .sig_rsa_sha2_256 = false,
    });
    const restricted_sig_test_mod = b.createModule(.{
        .root_source_file = b.path("src/restricted_sig_algs_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    restricted_sig_test_mod.addOptions("sshz_build_options", restricted_sig_options);
    linkZlib(b, restricted_sig_test_mod);
    const restricted_sig_tests = b.addTest(.{
        .root_module = restricted_sig_test_mod,
        .filters = &.{"restricted signature algorithms advertise and accept only ssh-mldsa87-p384 and ecdsa-sha2-nistp384"},
    });
    const run_restricted_sig_tests = b.addRunArtifact(restricted_sig_tests);

    const restricted_algorithm_options = b.addOptions();
    addSshzOptions(restricted_algorithm_options, false, default_trace_level, default_channel_capacity, version);
    addAlgorithmOptions(restricted_algorithm_options, .{
        .kex_mlkem1024nistp384_sha384 = true,
        .kex_mlkem768nistp256_sha256 = true,
        .kex_mlkem768x25519_sha256 = false,
        .kex_curve25519_sha256 = false,
        .kex_ecdh_sha2_nistp384 = true,
        .kex_ecdh_sha2_nistp256 = false,
        .cipher_aes256_gcm = true,
        .cipher_chacha20_poly1305 = false,
        .cipher_aes128_gcm = false,
        .cipher_aes256_ctr = true,
        .cipher_aes192_ctr = false,
        .cipher_aes128_ctr = false,
        .mac_hmac_sha2_512_etm = true,
        .mac_hmac_sha2_256_etm = false,
        .mac_hmac_sha2_512 = false,
        .mac_hmac_sha2_256 = false,
        .sig_ssh_mldsa87_p384 = true,
        .sig_ssh_mldsa44_ed25519 = false,
        .sig_ecdsa_sha2_nistp384 = true,
        .sig_ssh_ed25519 = false,
        .sig_ecdsa_sha2_nistp256 = false,
        .sig_rsa_sha2_512 = false,
        .sig_rsa_sha2_256 = false,
    });
    const restricted_algorithm_test_mod = b.createModule(.{
        .root_source_file = b.path("src/restricted_algorithms_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    restricted_algorithm_test_mod.addOptions("sshz_build_options", restricted_algorithm_options);
    linkZlib(b, restricted_algorithm_test_mod);
    const restricted_algorithm_tests = b.addTest(.{
        .root_module = restricted_algorithm_test_mod,
        .filters = &.{"restricted CNSA/NIST algorithm build"},
    });
    const run_restricted_algorithm_tests = b.addRunArtifact(restricted_algorithm_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_safe_trace_tests.step);
    test_step.dependOn(&run_trace_off_tests.step);
    test_step.dependOn(&run_configured_capacity_tests.step);
    test_step.dependOn(&run_restricted_sig_tests.step);
    test_step.dependOn(&run_restricted_algorithm_tests.step);

    const production_client_mod = b.createModule(.{
        .root_source_file = b.path("examples/production/client.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    production_client_mod.addImport("sshz", mod);
    production_client_mod.addAnonymousImport("production_test_host_key", .{
        .root_source_file = b.path("testserver/id_ed25519_passwordless"),
    });
    linkZlib(b, production_client_mod);
    const production_client = b.addExecutable(.{
        .name = "sshz-production-client-example",
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
    production_server_mod.addImport("sshz", mod);
    production_server_mod.addAnonymousImport("production_test_host_key", .{
        .root_source_file = b.path("testserver/id_ed25519_passwordless"),
    });
    linkZlib(b, production_server_mod);
    const production_server = b.addExecutable(.{
        .name = "sshz-production-server-example",
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
    malformed_mod.addImport("sshz", mod);
    linkZlib(b, malformed_mod);
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
    stress_mod.addImport("sshz", mod);
    stress_mod.addAnonymousImport("stress_host_key", .{
        .root_source_file = b.path("testserver/id_ed25519_passwordless"),
    });
    linkZlib(b, stress_mod);
    const stress_exe = b.addExecutable(.{
        .name = "sshz-stress",
        .root_module = stress_mod,
    });

    const run_stress = b.addRunArtifact(stress_exe);
    run_stress.addPassthruArgs();
    const stress_step = b.step("stress", "Run deterministic in-process stress acceptance");
    stress_step.dependOn(&run_stress.step);

    const soak_cmd = b.addSystemCommand(&.{ "bash", "test/stress/soak.sh" });
    soak_cmd.addArtifactArg(stress_exe);
    soak_cmd.addPassthruArgs();
    const soak_step = b.step("soak", "Run duration/seed/peer-selected soak coverage");
    soak_step.dependOn(&soak_cmd.step);

    const interop_cmd = b.addSystemCommand(&.{ "bash", "interop/run.sh" });
    interop_cmd.step.dependOn(&run_lib_tests.step);

    const interop_step = b.step("interop", "Run OpenSSH/libssh interoperability tests");
    interop_step.dependOn(&interop_cmd.step);
}
