const std = @import("std");
const Sshz = @import("sshz.zig");
const Key = @import("key.zig");
const PrivKey = @import("privkey.zig");
const Protocol = @import("protocol.zig");

comptime {
    if (!Sshz.SignatureAlgorithm.Mldsa87P384.isEnabled()) {
        @compileError("expected ssh-mldsa87-p384 to be enabled");
    }
    if (!Sshz.SignatureAlgorithm.EcdsaP384Sha384.isEnabled()) {
        @compileError("expected ecdsa-sha2-nistp384 to be enabled");
    }
    if (Sshz.SignatureAlgorithm.Mldsa44Ed25519.isEnabled()) {
        @compileError("expected ssh-mldsa44-ed25519 to be disabled");
    }
    if (Sshz.SignatureAlgorithm.Ed25519.isEnabled()) {
        @compileError("expected ssh-ed25519 to be disabled");
    }
    if (Sshz.SignatureAlgorithm.EcdsaP256Sha256.isEnabled()) {
        @compileError("expected ecdsa-sha2-nistp256 to be disabled");
    }
    if (Sshz.SignatureAlgorithm.RsaSha512.isEnabled()) {
        @compileError("expected rsa-sha2-512 to be disabled");
    }
    if (Sshz.SignatureAlgorithm.RsaSha256.isEnabled()) {
        @compileError("expected rsa-sha2-256 to be disabled");
    }
    if (!Sshz.KeyAlgorithm.Mldsa87P384.isEnabled() or !Sshz.KeyAlgorithm.EcdsaP384.isEnabled()) {
        @compileError("expected Mldsa87P384 and EcdsaP384 key algorithms to be enabled");
    }
    if (Sshz.KeyAlgorithm.Ed25519.isEnabled() or Sshz.KeyAlgorithm.Rsa.isEnabled()) {
        @compileError("expected Ed25519 and Rsa key algorithms to be disabled");
    }
}

test "restricted signature algorithms advertise and accept only ssh-mldsa87-p384 and ecdsa-sha2-nistp384" {
    try std.testing.expectEqualStrings(
        "ssh-mldsa87-p384,ecdsa-sha2-nistp384",
        Key.client_hostkey_algorithms,
    );

    var mldsa87 = PrivKey.testKeyMldsa87P384();
    defer mldsa87.clear();
    var mldsa_pub_blob: Key.Blob = .{};
    const mldsa_pub = try Key.parsePublicKeyBlob(try mldsa87.publicBlob(&mldsa_pub_blob));
    var mldsa_sig_blob: Key.SignatureBlob = .{};
    defer mldsa_sig_blob.clear();
    const mldsa_sig = try mldsa87.sign(.Mldsa87P384, "restricted-msg", &mldsa_sig_blob);
    try Key.verifySignature(mldsa_pub, mldsa_sig, "restricted-msg");

    var p384 = PrivKey.testKeyEcdsaP384();
    defer p384.clear();
    var p384_pub_blob: Key.Blob = .{};
    const p384_pub = try Key.parsePublicKeyBlob(try p384.publicBlob(&p384_pub_blob));
    var p384_sig_blob: Key.SignatureBlob = .{};
    defer p384_sig_blob.clear();
    const p384_sig = try p384.sign(.EcdsaP384Sha384, "restricted-msg", &p384_sig_blob);
    try Key.verifySignature(p384_pub, p384_sig, "restricted-msg");

    // Disabled ssh-ed25519 must be rejected for signing, verification, and host key selection.
    var ed_key = try PrivKey.decodeOpenSshPrivateKey(PrivKey.testkey_valid, null);
    defer ed_key.clear();
    try std.testing.expectEqualStrings("", ed_key.hostKeyAlgorithms());
    try std.testing.expect(Key.selectHostKeyAlgorithm("ssh-ed25519", &ed_key) == null);
    try std.testing.expect(Key.selectHostKeyAlgorithm("ssh-ed25519,rsa-sha2-256", null) == null);

    var ed_sig_blob: Key.SignatureBlob = .{};
    defer ed_sig_blob.clear();
    try std.testing.expectError(
        error.SignatureAlgorithmMismatch,
        ed_key.sign(.Ed25519, "restricted-msg", &ed_sig_blob),
    );

    const peer_only_ed25519: Protocol.KexInit = .{
        .offers = Protocol.localAlgorithmOffers("ssh-ed25519"),
        .language_c2s = "",
        .language_s2c = "",
        .first_kex_packet_follows = false,
    };
    try std.testing.expectError(
        Sshz.IoError.AlgorithmNegotiationFailed,
        Protocol.negotiateAlgorithms(peer_only_ed25519, .Client, Key.client_hostkey_algorithms),
    );
    try std.testing.expectError(
        Sshz.IoError.AlgorithmNegotiationFailed,
        Protocol.negotiateAlgorithms(peer_only_ed25519, .Server, "ssh-ed25519"),
    );
}
