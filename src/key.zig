const std = @import("std");
const build_options = @import("sshz_build_options");
const BufferReader = @import("buffer.zig").BufferReader;
const BufferWriter = @import("buffer.zig").BufferWriter;
const BufferError = @import("buffer.zig").BufferError;

pub const Mldsa87 = std.crypto.sign.mldsa.MLDSA87;
pub const Mldsa44 = std.crypto.sign.mldsa.MLDSA44;
pub const Ed25519 = std.crypto.sign.Ed25519;
pub const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
pub const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const mldsa87_p384_name = "ssh-mldsa87-p384";
pub const mldsa44_ed25519_name = "ssh-mldsa44-ed25519";
pub const ed25519_name = "ssh-ed25519";
pub const ecdsa_p384_name = "ecdsa-sha2-nistp384";
pub const ecdsa_p384_curve_name = "nistp384";
pub const ecdsa_p256_name = "ecdsa-sha2-nistp256";
pub const ecdsa_p256_curve_name = "nistp256";
pub const rsa_key_name = "ssh-rsa";
pub const rsa_sha2_256_name = "rsa-sha2-256";
pub const rsa_sha2_512_name = "rsa-sha2-512";

pub const composite_prefix = "CompositeAlgorithmSignatures2025";
pub const mldsa87_p384_domain = "COMPSIG-MLDSA87-ECDSA-P384-SHA512";
pub const mldsa44_ed25519_domain = "COMPSIG-MLDSA44-ED25519-SHA512";

const all_signature_algorithms = [_]SignatureAlgorithm{
    .Mldsa87P384,
    .Mldsa44Ed25519,
    .Ed25519,
    .EcdsaP384Sha384,
    .EcdsaP256Sha256,
    .RsaSha512,
    .RsaSha256,
};

comptime {
    var any_enabled = false;
    for (all_signature_algorithms) |alg| {
        if (alg.isEnabled()) any_enabled = true;
    }
    if (!any_enabled) {
        @compileError("at least one SSH signature algorithm must be enabled");
    }
}

const client_hostkey_preference = blk: {
    var enabled: [all_signature_algorithms.len]SignatureAlgorithm = undefined;
    var count: usize = 0;
    for (all_signature_algorithms) |alg| {
        if (alg.isEnabled()) {
            enabled[count] = alg;
            count += 1;
        }
    }
    const final = enabled[0..count].*;
    break :blk final;
};

pub const client_hostkey_algorithms = blk: {
    var names: []const u8 = "";
    for (client_hostkey_preference) |alg| {
        if (names.len > 0) names = names ++ ",";
        names = names ++ alg.name();
    }
    break :blk names;
};

pub const server_sig_algs_value = client_hostkey_algorithms;

pub const MinRsaBits = 2048;
pub const MinRsaBytes = MinRsaBits / 8;
pub const MaxRsaBits = 4096;
pub const MaxRsaBytes = MaxRsaBits / 8;
pub const MaxPublicKeyBlobLen = 4 + ecdsa_p384_name.len + 4 + ecdsa_p384_curve_name.len + 4 + EcdsaP384.PublicKey.uncompressed_sec1_encoded_length;
// Both mpints (e and n) may need their own leading zero pad byte when the
// high bit of the first octet is set, so budget one pad for each.
pub const MaxRsaPublicKeyBlobLen = 4 + rsa_key_name.len + 4 + 8 + 1 + 4 + MaxRsaBytes + 1;
pub const MaxMldsa87P384PublicKeyPayloadLen = Mldsa87.PublicKey.encoded_length + 4 + EcdsaP384.PublicKey.uncompressed_sec1_encoded_length;
pub const MaxMldsa44Ed25519PublicKeyPayloadLen = Mldsa44.PublicKey.encoded_length + Ed25519.PublicKey.encoded_length;
pub const MaxKeyBlobLen = 4 + mldsa87_p384_name.len + 4 + MaxMldsa87P384PublicKeyPayloadLen;
pub const MaxSignaturePayloadLen = Mldsa87.Signature.encoded_length + 2 * (4 + EcdsaP384.SecretKey.encoded_length + 1);
pub const MaxSignatureBlobLen = 4 + mldsa87_p384_name.len + 4 + MaxSignaturePayloadLen;

comptime {
    std.debug.assert(MaxKeyBlobLen == 2717);
    std.debug.assert(MaxSignatureBlobLen == 4757);
}

pub const KeyError = error{
    UnsupportedKeyAlgorithm,
    InvalidKeyBlob,
    InvalidSignature,
    SignatureAlgorithmMismatch,
    SigningFailed,
    RsaComponentTooLarge,
    RsaKeyTooSmall,
} || BufferError;

pub const KeyAlgorithm = enum {
    Mldsa87P384,
    Mldsa44Ed25519,
    Ed25519,
    EcdsaP384,
    EcdsaP256,
    Rsa,

    pub const ssh_mldsa87_p384: KeyAlgorithm = .Mldsa87P384;
    pub const ssh_mldsa44_ed25519: KeyAlgorithm = .Mldsa44Ed25519;
    pub const ssh_ed25519: KeyAlgorithm = .Ed25519;
    pub const ecdsa_sha2_nistp384: KeyAlgorithm = .EcdsaP384;
    pub const ecdsa_sha2_nistp256: KeyAlgorithm = .EcdsaP256;
    pub const ssh_rsa: KeyAlgorithm = .Rsa;
    pub const rsa: KeyAlgorithm = .Rsa;

    pub fn name(self: KeyAlgorithm) []const u8 {
        return switch (self) {
            .Mldsa87P384 => mldsa87_p384_name,
            .Mldsa44Ed25519 => mldsa44_ed25519_name,
            .Ed25519 => ed25519_name,
            .EcdsaP384 => ecdsa_p384_name,
            .EcdsaP256 => ecdsa_p256_name,
            .Rsa => rsa_key_name,
        };
    }

    pub fn isEnabled(self: KeyAlgorithm) bool {
        return switch (self) {
            .Mldsa87P384 => SignatureAlgorithm.Mldsa87P384.isEnabled(),
            .Mldsa44Ed25519 => SignatureAlgorithm.Mldsa44Ed25519.isEnabled(),
            .Ed25519 => SignatureAlgorithm.Ed25519.isEnabled(),
            .EcdsaP384 => SignatureAlgorithm.EcdsaP384Sha384.isEnabled(),
            .EcdsaP256 => SignatureAlgorithm.EcdsaP256Sha256.isEnabled(),
            .Rsa => SignatureAlgorithm.RsaSha512.isEnabled() or SignatureAlgorithm.RsaSha256.isEnabled(),
        };
    }
};

pub const SignatureAlgorithm = enum {
    Mldsa87P384,
    Mldsa44Ed25519,
    Ed25519,
    EcdsaP384Sha384,
    EcdsaP256Sha256,
    RsaSha512,
    RsaSha256,

    pub const ssh_mldsa87_p384: SignatureAlgorithm = .Mldsa87P384;
    pub const ssh_mldsa44_ed25519: SignatureAlgorithm = .Mldsa44Ed25519;
    pub const ssh_ed25519: SignatureAlgorithm = .Ed25519;
    pub const ecdsa_sha2_nistp384: SignatureAlgorithm = .EcdsaP384Sha384;
    pub const ecdsa_sha2_nistp256: SignatureAlgorithm = .EcdsaP256Sha256;
    pub const rsa_sha2_512: SignatureAlgorithm = .RsaSha512;
    pub const rsa_sha2_256: SignatureAlgorithm = .RsaSha256;

    pub fn fromName(alg_name: []const u8) ?SignatureAlgorithm {
        if (std.mem.eql(u8, alg_name, mldsa87_p384_name)) return .Mldsa87P384;
        if (std.mem.eql(u8, alg_name, mldsa44_ed25519_name)) return .Mldsa44Ed25519;
        if (std.mem.eql(u8, alg_name, ed25519_name)) return .Ed25519;
        if (std.mem.eql(u8, alg_name, ecdsa_p384_name)) return .EcdsaP384Sha384;
        if (std.mem.eql(u8, alg_name, ecdsa_p256_name)) return .EcdsaP256Sha256;
        if (std.mem.eql(u8, alg_name, rsa_sha2_256_name)) return .RsaSha256;
        if (std.mem.eql(u8, alg_name, rsa_sha2_512_name)) return .RsaSha512;
        return null;
    }

    pub fn name(self: SignatureAlgorithm) []const u8 {
        return switch (self) {
            .Mldsa87P384 => mldsa87_p384_name,
            .Mldsa44Ed25519 => mldsa44_ed25519_name,
            .Ed25519 => ed25519_name,
            .EcdsaP384Sha384 => ecdsa_p384_name,
            .EcdsaP256Sha256 => ecdsa_p256_name,
            .RsaSha256 => rsa_sha2_256_name,
            .RsaSha512 => rsa_sha2_512_name,
        };
    }

    pub fn keyAlgorithm(self: SignatureAlgorithm) KeyAlgorithm {
        return switch (self) {
            .Mldsa87P384 => .Mldsa87P384,
            .Mldsa44Ed25519 => .Mldsa44Ed25519,
            .Ed25519 => .Ed25519,
            .EcdsaP384Sha384 => .EcdsaP384,
            .EcdsaP256Sha256 => .EcdsaP256,
            .RsaSha256, .RsaSha512 => .Rsa,
        };
    }

    pub fn isEnabled(self: SignatureAlgorithm) bool {
        return switch (self) {
            .Mldsa87P384 => if (@hasDecl(build_options, "sig_ssh_mldsa87_p384")) build_options.sig_ssh_mldsa87_p384 else true,
            .Mldsa44Ed25519 => if (@hasDecl(build_options, "sig_ssh_mldsa44_ed25519")) build_options.sig_ssh_mldsa44_ed25519 else true,
            .Ed25519 => if (@hasDecl(build_options, "sig_ssh_ed25519")) build_options.sig_ssh_ed25519 else true,
            .EcdsaP384Sha384 => if (@hasDecl(build_options, "sig_ecdsa_sha2_nistp384")) build_options.sig_ecdsa_sha2_nistp384 else true,
            .EcdsaP256Sha256 => if (@hasDecl(build_options, "sig_ecdsa_sha2_nistp256")) build_options.sig_ecdsa_sha2_nistp256 else true,
            .RsaSha512 => if (@hasDecl(build_options, "sig_rsa_sha2_512")) build_options.sig_rsa_sha2_512 else true,
            .RsaSha256 => if (@hasDecl(build_options, "sig_rsa_sha2_256")) build_options.sig_rsa_sha2_256 else true,
        };
    }
};

fn buildCompositeMessage(comptime domain: []const u8, msg: []const u8) [composite_prefix.len + domain.len + 1 + Sha512.digest_length]u8 {
    var m_prime: [composite_prefix.len + domain.len + 1 + Sha512.digest_length]u8 = undefined;
    @memcpy(m_prime[0..composite_prefix.len], composite_prefix);
    @memcpy(m_prime[composite_prefix.len .. composite_prefix.len + domain.len], domain);
    m_prime[composite_prefix.len + domain.len] = 0x00;
    Sha512.hash(msg, m_prime[composite_prefix.len + domain.len + 1 ..][0..Sha512.digest_length], .{});
    return m_prime;
}

pub const Blob = struct {
    buf: [MaxKeyBlobLen]u8 = undefined,
    len: usize = 0,

    pub fn set(self: *Blob, bytes: []const u8) KeyError!void {
        self.clear();
        if (bytes.len > self.buf.len) return error.InvalidKeyBlob;
        @memcpy(self.buf[0..bytes.len], bytes);
        self.len = bytes.len;
    }

    pub fn slice(self: *const Blob) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn clear(self: *Blob) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

/// Caller-owned signature output; clear it as soon as the signature is consumed.
pub const SignatureBlob = struct {
    buf: [MaxSignatureBlobLen]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const SignatureBlob) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn clear(self: *SignatureBlob) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const RsaComponent = struct {
    bytes: [MaxRsaBytes]u8 = @splat(0),
    len: usize = 0,

    pub fn set(self: *RsaComponent, bytes: []const u8) KeyError!void {
        const trimmed = trimMpint(bytes);
        self.clear();
        if (trimmed.len > MaxRsaBytes) return error.RsaComponentTooLarge;
        @memcpy(self.bytes[0..trimmed.len], trimmed);
        self.len = trimmed.len;
    }

    pub fn slice(self: *const RsaComponent) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn clear(self: *RsaComponent) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const RsaPrivateKey = struct {
    n: RsaComponent = .{},
    e: RsaComponent = .{},
    d: RsaComponent = .{},
    iqmp: RsaComponent = .{},
    p: RsaComponent = .{},
    q: RsaComponent = .{},

    pub fn clear(self: *RsaPrivateKey) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const PublicKey = union(KeyAlgorithm) {
    Mldsa87P384: struct {
        mldsa_public: [Mldsa87.PublicKey.encoded_length]u8,
        ecdsa_sec1: [EcdsaP384.PublicKey.uncompressed_sec1_encoded_length]u8,
    },
    Mldsa44Ed25519: struct {
        mldsa_public: [Mldsa44.PublicKey.encoded_length]u8,
        ed25519_public: [Ed25519.PublicKey.encoded_length]u8,
    },
    Ed25519: [Ed25519.PublicKey.encoded_length]u8,
    EcdsaP384: [EcdsaP384.PublicKey.uncompressed_sec1_encoded_length]u8,
    EcdsaP256: [EcdsaP256.PublicKey.uncompressed_sec1_encoded_length]u8,
    Rsa: struct {
        n: RsaComponent,
        e: RsaComponent,
    },

    pub fn algorithm(self: PublicKey) KeyAlgorithm {
        return switch (self) {
            .Mldsa87P384 => .Mldsa87P384,
            .Mldsa44Ed25519 => .Mldsa44Ed25519,
            .Ed25519 => .Ed25519,
            .EcdsaP384 => .EcdsaP384,
            .EcdsaP256 => .EcdsaP256,
            .Rsa => .Rsa,
        };
    }

    pub fn validate(self: PublicKey) KeyError!void {
        switch (self) {
            .Mldsa87P384 => |comp| {
                _ = Mldsa87.PublicKey.fromBytes(comp.mldsa_public) catch return error.InvalidKeyBlob;
                if (comp.ecdsa_sec1[0] != 0x04) return error.InvalidKeyBlob;
                _ = EcdsaP384.PublicKey.fromSec1(&comp.ecdsa_sec1) catch return error.InvalidKeyBlob;
            },
            .Mldsa44Ed25519 => |comp| {
                _ = Mldsa44.PublicKey.fromBytes(comp.mldsa_public) catch return error.InvalidKeyBlob;
                _ = Ed25519.PublicKey.fromBytes(comp.ed25519_public) catch return error.InvalidKeyBlob;
            },
            .Ed25519 => |raw| {
                _ = Ed25519.PublicKey.fromBytes(raw) catch return error.InvalidKeyBlob;
            },
            .EcdsaP384 => |sec1| {
                if (sec1[0] != 0x04) return error.InvalidKeyBlob;
                _ = EcdsaP384.PublicKey.fromSec1(&sec1) catch return error.InvalidKeyBlob;
            },
            .EcdsaP256 => |sec1| {
                if (sec1[0] != 0x04) return error.InvalidKeyBlob;
                _ = EcdsaP256.PublicKey.fromSec1(&sec1) catch return error.InvalidKeyBlob;
            },
            .Rsa => |rsa| try validateRsaPublicComponents(rsa.n.slice(), rsa.e.slice()),
        }
    }
};

/// Caller-owned private key material; call clear before releasing or replacing it.
pub const PrivateKey = union(KeyAlgorithm) {
    Mldsa87P384: struct {
        mldsa_public: [Mldsa87.PublicKey.encoded_length]u8,
        ecdsa_sec1: [EcdsaP384.PublicKey.uncompressed_sec1_encoded_length]u8,
        mldsa_seed: [Mldsa87.seed_length]u8,
        ecdsa_scalar: [EcdsaP384.SecretKey.encoded_length]u8,
    },
    Mldsa44Ed25519: struct {
        mldsa_public: [Mldsa44.PublicKey.encoded_length]u8,
        ed25519_public: [Ed25519.PublicKey.encoded_length]u8,
        mldsa_seed: [Mldsa44.seed_length]u8,
        ed25519_seed: [Ed25519.KeyPair.seed_length]u8,
    },
    Ed25519: struct {
        public: [Ed25519.PublicKey.encoded_length]u8,
        secret: [Ed25519.SecretKey.encoded_length]u8,
    },
    EcdsaP384: struct {
        public_sec1: [EcdsaP384.PublicKey.uncompressed_sec1_encoded_length]u8,
        secret_scalar: [EcdsaP384.SecretKey.encoded_length]u8,
    },
    EcdsaP256: struct {
        public_sec1: [EcdsaP256.PublicKey.uncompressed_sec1_encoded_length]u8,
        secret_scalar: [EcdsaP256.SecretKey.encoded_length]u8,
    },
    Rsa: RsaPrivateKey,

    pub fn algorithm(self: *const PrivateKey) KeyAlgorithm {
        return switch (self.*) {
            .Mldsa87P384 => .Mldsa87P384,
            .Mldsa44Ed25519 => .Mldsa44Ed25519,
            .Ed25519 => .Ed25519,
            .EcdsaP384 => .EcdsaP384,
            .EcdsaP256 => .EcdsaP256,
            .Rsa => .Rsa,
        };
    }

    pub fn defaultSignatureAlgorithm(self: *const PrivateKey) SignatureAlgorithm {
        return switch (self.*) {
            .Mldsa87P384 => .Mldsa87P384,
            .Mldsa44Ed25519 => .Mldsa44Ed25519,
            .Ed25519 => .Ed25519,
            .EcdsaP384 => .EcdsaP384Sha384,
            .EcdsaP256 => .EcdsaP256Sha256,
            .Rsa => if (SignatureAlgorithm.RsaSha512.isEnabled()) .RsaSha512 else .RsaSha256,
        };
    }

    pub fn hostKeyAlgorithms(self: *const PrivateKey) []const u8 {
        return switch (self.*) {
            .Mldsa87P384 => if (SignatureAlgorithm.Mldsa87P384.isEnabled()) mldsa87_p384_name else "",
            .Mldsa44Ed25519 => if (SignatureAlgorithm.Mldsa44Ed25519.isEnabled()) mldsa44_ed25519_name else "",
            .Ed25519 => if (SignatureAlgorithm.Ed25519.isEnabled()) ed25519_name else "",
            .EcdsaP384 => if (SignatureAlgorithm.EcdsaP384Sha384.isEnabled()) ecdsa_p384_name else "",
            .EcdsaP256 => if (SignatureAlgorithm.EcdsaP256Sha256.isEnabled()) ecdsa_p256_name else "",
            .Rsa => if (SignatureAlgorithm.RsaSha512.isEnabled() and SignatureAlgorithm.RsaSha256.isEnabled())
                rsa_sha2_512_name ++ "," ++ rsa_sha2_256_name
            else if (SignatureAlgorithm.RsaSha512.isEnabled())
                rsa_sha2_512_name
            else if (SignatureAlgorithm.RsaSha256.isEnabled())
                rsa_sha2_256_name
            else
                "",
        };
    }

    pub fn supportsSignatureAlgorithm(self: *const PrivateKey, alg: SignatureAlgorithm) bool {
        return alg.isEnabled() and self.algorithm() == alg.keyAlgorithm();
    }

    pub fn publicBlob(self: *const PrivateKey, out: *Blob) KeyError![]const u8 {
        return writePublicKeyBlob(self.publicKey(), out);
    }

    pub fn publicKey(self: *const PrivateKey) PublicKey {
        return switch (self.*) {
            .Mldsa87P384 => |*key| .{ .Mldsa87P384 = .{
                .mldsa_public = key.mldsa_public,
                .ecdsa_sec1 = key.ecdsa_sec1,
            } },
            .Mldsa44Ed25519 => |*key| .{ .Mldsa44Ed25519 = .{
                .mldsa_public = key.mldsa_public,
                .ed25519_public = key.ed25519_public,
            } },
            .Ed25519 => |*key| .{ .Ed25519 = key.public },
            .EcdsaP384 => |*key| .{ .EcdsaP384 = key.public_sec1 },
            .EcdsaP256 => |*key| .{ .EcdsaP256 = key.public_sec1 },
            .Rsa => |*key| .{ .Rsa = .{ .n = key.n, .e = key.e } },
        };
    }

    pub fn validate(self: *const PrivateKey) KeyError!void {
        switch (self.*) {
            .Mldsa87P384 => |*key| {
                _ = Mldsa87.PublicKey.fromBytes(key.mldsa_public) catch return error.InvalidKeyBlob;
                var mldsa_kp = Mldsa87.newKeyFromSeed(&key.mldsa_seed);
                defer std.crypto.secureZero(u8, std.mem.asBytes(&mldsa_kp.sk));
                if (!std.mem.eql(u8, &mldsa_kp.pk.toBytes(), &key.mldsa_public)) return error.InvalidKeyBlob;

                if (key.ecdsa_sec1[0] != 0x04) return error.InvalidKeyBlob;
                _ = EcdsaP384.PublicKey.fromSec1(&key.ecdsa_sec1) catch return error.InvalidKeyBlob;
                var secret = EcdsaP384.SecretKey.fromBytes(key.ecdsa_scalar) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
                var keypair = EcdsaP384.KeyPair.fromSecretKey(secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&keypair));
                if (!std.mem.eql(u8, &keypair.public_key.toUncompressedSec1(), &key.ecdsa_sec1)) return error.InvalidKeyBlob;
            },
            .Mldsa44Ed25519 => |*key| {
                _ = Mldsa44.PublicKey.fromBytes(key.mldsa_public) catch return error.InvalidKeyBlob;
                var mldsa_kp = Mldsa44.newKeyFromSeed(&key.mldsa_seed);
                defer std.crypto.secureZero(u8, std.mem.asBytes(&mldsa_kp.sk));
                if (!std.mem.eql(u8, &mldsa_kp.pk.toBytes(), &key.mldsa_public)) return error.InvalidKeyBlob;

                _ = Ed25519.PublicKey.fromBytes(key.ed25519_public) catch return error.InvalidKeyBlob;
                var keypair = Ed25519.KeyPair.generateDeterministic(key.ed25519_seed) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&keypair));
                if (!std.mem.eql(u8, &keypair.public_key.toBytes(), &key.ed25519_public)) return error.InvalidKeyBlob;
            },
            .Ed25519 => |*key| {
                _ = Ed25519.PublicKey.fromBytes(key.public) catch return error.InvalidKeyBlob;
                var secret = Ed25519.SecretKey.fromBytes(key.secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
                var keypair = Ed25519.KeyPair.fromSecretKey(secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&keypair));
                if (!std.mem.eql(u8, &keypair.public_key.toBytes(), &key.public)) return error.InvalidKeyBlob;
            },
            .EcdsaP384 => |*key| {
                if (key.public_sec1[0] != 0x04) return error.InvalidKeyBlob;
                _ = EcdsaP384.PublicKey.fromSec1(&key.public_sec1) catch return error.InvalidKeyBlob;
                var secret = EcdsaP384.SecretKey.fromBytes(key.secret_scalar) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
                var keypair = EcdsaP384.KeyPair.fromSecretKey(secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&keypair));
                if (!std.mem.eql(u8, &keypair.public_key.toUncompressedSec1(), &key.public_sec1)) return error.InvalidKeyBlob;
            },
            .EcdsaP256 => |*key| {
                if (key.public_sec1[0] != 0x04) return error.InvalidKeyBlob;
                _ = EcdsaP256.PublicKey.fromSec1(&key.public_sec1) catch return error.InvalidKeyBlob;
                var secret = EcdsaP256.SecretKey.fromBytes(key.secret_scalar) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
                var keypair = EcdsaP256.KeyPair.fromSecretKey(secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&keypair));
                if (!std.mem.eql(u8, &keypair.public_key.toUncompressedSec1(), &key.public_sec1)) return error.InvalidKeyBlob;
            },
            .Rsa => |*key| {
                try validateRsaPublicComponents(key.n.slice(), key.e.slice());
                if (key.d.len == 0 or key.iqmp.len == 0 or key.p.len == 0 or key.q.len == 0) {
                    return error.InvalidKeyBlob;
                }
            },
        }
    }

    pub fn sign(self: *const PrivateKey, alg: SignatureAlgorithm, msg: []const u8, out: *SignatureBlob) KeyError![]const u8 {
        out.clear();
        errdefer out.clear();
        if (!self.supportsSignatureAlgorithm(alg)) return error.SignatureAlgorithmMismatch;

        var signature_payload_buf: [MaxSignaturePayloadLen]u8 = undefined;
        defer std.crypto.secureZero(u8, &signature_payload_buf);
        var signature_payload: []const u8 = undefined;

        switch (self.*) {
            .Mldsa87P384 => |*key| {
                var m_prime = buildCompositeMessage(mldsa87_p384_domain, msg);
                defer std.crypto.secureZero(u8, &m_prime);

                var mldsa_kp = Mldsa87.newKeyFromSeed(&key.mldsa_seed);
                defer std.crypto.secureZero(u8, std.mem.asBytes(&mldsa_kp.sk));
                if (!std.mem.eql(u8, &mldsa_kp.pk.toBytes(), &key.mldsa_public)) return error.InvalidKeyBlob;

                var signer = mldsa_kp.sk.signerWithContext(null, mldsa87_p384_domain) catch return error.SigningFailed;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&signer));
                signer.update(&m_prime);
                var mldsa_sig = signer.finalize();
                defer std.crypto.secureZero(u8, std.mem.asBytes(&mldsa_sig));
                var mldsa_sig_bytes = mldsa_sig.toBytes();
                defer std.crypto.secureZero(u8, &mldsa_sig_bytes);

                var ecdsa_secret = EcdsaP384.SecretKey.fromBytes(key.ecdsa_scalar) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&ecdsa_secret));
                var ecdsa_kp = EcdsaP384.KeyPair.fromSecretKey(ecdsa_secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&ecdsa_kp));
                if (!std.mem.eql(u8, &ecdsa_kp.public_key.toUncompressedSec1(), &key.ecdsa_sec1)) return error.InvalidKeyBlob;
                var ecdsa_sig = ecdsa_kp.sign(&m_prime, null) catch return error.SigningFailed;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&ecdsa_sig));

                var inner = BufferWriter.init(&signature_payload_buf, 0);
                try inner.writeBytes(&mldsa_sig_bytes);
                try writeMpint(&inner, &ecdsa_sig.r);
                try writeMpint(&inner, &ecdsa_sig.s);
                signature_payload = inner.active();
            },
            .Mldsa44Ed25519 => |*key| {
                var m_prime = buildCompositeMessage(mldsa44_ed25519_domain, msg);
                defer std.crypto.secureZero(u8, &m_prime);

                var mldsa_kp = Mldsa44.newKeyFromSeed(&key.mldsa_seed);
                defer std.crypto.secureZero(u8, std.mem.asBytes(&mldsa_kp.sk));
                if (!std.mem.eql(u8, &mldsa_kp.pk.toBytes(), &key.mldsa_public)) return error.InvalidKeyBlob;

                var signer = mldsa_kp.sk.signerWithContext(null, mldsa44_ed25519_domain) catch return error.SigningFailed;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&signer));
                signer.update(&m_prime);
                var mldsa_sig = signer.finalize();
                defer std.crypto.secureZero(u8, std.mem.asBytes(&mldsa_sig));
                var mldsa_sig_bytes = mldsa_sig.toBytes();
                defer std.crypto.secureZero(u8, &mldsa_sig_bytes);

                _ = Ed25519.PublicKey.fromBytes(key.ed25519_public) catch return error.InvalidKeyBlob;
                var ed_kp = Ed25519.KeyPair.generateDeterministic(key.ed25519_seed) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&ed_kp));
                if (!std.mem.eql(u8, &ed_kp.public_key.toBytes(), &key.ed25519_public)) return error.InvalidKeyBlob;
                var ed_sig = ed_kp.sign(&m_prime, null) catch return error.SigningFailed;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&ed_sig));
                var ed_sig_bytes = ed_sig.toBytes();
                defer std.crypto.secureZero(u8, &ed_sig_bytes);

                const total_len = Mldsa44.Signature.encoded_length + Ed25519.Signature.encoded_length;
                @memcpy(signature_payload_buf[0..Mldsa44.Signature.encoded_length], &mldsa_sig_bytes);
                @memcpy(signature_payload_buf[Mldsa44.Signature.encoded_length..total_len], &ed_sig_bytes);
                signature_payload = signature_payload_buf[0..total_len];
            },
            .Ed25519 => |*key| {
                _ = Ed25519.PublicKey.fromBytes(key.public) catch return error.InvalidKeyBlob;
                var secret = Ed25519.SecretKey.fromBytes(key.secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
                var keypair = Ed25519.KeyPair.fromSecretKey(secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&keypair));
                if (!std.mem.eql(u8, &keypair.public_key.toBytes(), &key.public)) return error.InvalidKeyBlob;
                var sig = keypair.sign(msg, null) catch return error.SigningFailed;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&sig));
                var sigbytes = sig.toBytes();
                defer std.crypto.secureZero(u8, &sigbytes);
                @memcpy(signature_payload_buf[0..sigbytes.len], &sigbytes);
                signature_payload = signature_payload_buf[0..sigbytes.len];
            },
            .EcdsaP384 => |*key| {
                if (key.public_sec1[0] != 0x04) return error.InvalidKeyBlob;
                _ = EcdsaP384.PublicKey.fromSec1(&key.public_sec1) catch return error.InvalidKeyBlob;
                var secret = EcdsaP384.SecretKey.fromBytes(key.secret_scalar) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
                var keypair = EcdsaP384.KeyPair.fromSecretKey(secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&keypair));
                if (!std.mem.eql(u8, &keypair.public_key.toUncompressedSec1(), &key.public_sec1)) return error.InvalidKeyBlob;
                var sig = keypair.sign(msg, null) catch return error.SigningFailed;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&sig));
                var inner = BufferWriter.init(&signature_payload_buf, 0);
                try writeMpint(&inner, &sig.r);
                try writeMpint(&inner, &sig.s);
                signature_payload = inner.active();
            },
            .EcdsaP256 => |*key| {
                if (key.public_sec1[0] != 0x04) return error.InvalidKeyBlob;
                _ = EcdsaP256.PublicKey.fromSec1(&key.public_sec1) catch return error.InvalidKeyBlob;
                var secret = EcdsaP256.SecretKey.fromBytes(key.secret_scalar) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
                var keypair = EcdsaP256.KeyPair.fromSecretKey(secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&keypair));
                if (!std.mem.eql(u8, &keypair.public_key.toUncompressedSec1(), &key.public_sec1)) return error.InvalidKeyBlob;
                var sig = keypair.sign(msg, null) catch return error.SigningFailed;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&sig));
                var sigbytes = sig.toBytes();
                defer std.crypto.secureZero(u8, &sigbytes);
                var inner = BufferWriter.init(&signature_payload_buf, 0);
                try writeMpint(&inner, sigbytes[0 .. sigbytes.len / 2]);
                try writeMpint(&inner, sigbytes[sigbytes.len / 2 ..]);
                signature_payload = inner.active();
            },
            .Rsa => |*key| {
                signature_payload = switch (alg) {
                    .RsaSha256 => try rsaSign(std.crypto.hash.sha2.Sha256, key, msg, signature_payload_buf[0..MaxRsaBytes]),
                    .RsaSha512 => try rsaSign(std.crypto.hash.sha2.Sha512, key, msg, signature_payload_buf[0..MaxRsaBytes]),
                    else => return error.SignatureAlgorithmMismatch,
                };
            },
        }

        var outer = BufferWriter.init(&out.buf, 0);
        try outer.writeU32LenString(alg.name());
        try outer.writeU32LenString(signature_payload);
        out.len = outer.active().len;
        return out.slice();
    }

    pub fn clear(self: *PrivateKey) void {
        const alg = self.algorithm();
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = switch (alg) {
            .Mldsa87P384 => .{ .Mldsa87P384 = .{
                .mldsa_public = @splat(0),
                .ecdsa_sec1 = @splat(0),
                .mldsa_seed = @splat(0),
                .ecdsa_scalar = @splat(0),
            } },
            .Mldsa44Ed25519 => .{ .Mldsa44Ed25519 = .{
                .mldsa_public = @splat(0),
                .ed25519_public = @splat(0),
                .mldsa_seed = @splat(0),
                .ed25519_seed = @splat(0),
            } },
            .Ed25519 => .{ .Ed25519 = .{
                .public = @splat(0),
                .secret = @splat(0),
            } },
            .EcdsaP384 => .{ .EcdsaP384 = .{
                .public_sec1 = @splat(0),
                .secret_scalar = @splat(0),
            } },
            .EcdsaP256 => .{ .EcdsaP256 = .{
                .public_sec1 = @splat(0),
                .secret_scalar = @splat(0),
            } },
            .Rsa => .{ .Rsa = .{} },
        };
    }
};

fn expectZeroed(bytes: []const u8) !void {
    for (bytes) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "private key clear wipes every algorithm payload" {
    var mldsa87: PrivateKey = .{ .Mldsa87P384 = .{
        .mldsa_public = @splat(0xA5),
        .ecdsa_sec1 = @splat(0x5A),
        .mldsa_seed = @splat(0x3C),
        .ecdsa_scalar = @splat(0xC3),
    } };
    mldsa87.clear();
    try expectZeroed(&mldsa87.Mldsa87P384.mldsa_public);
    try expectZeroed(&mldsa87.Mldsa87P384.ecdsa_sec1);
    try expectZeroed(&mldsa87.Mldsa87P384.mldsa_seed);
    try expectZeroed(&mldsa87.Mldsa87P384.ecdsa_scalar);

    var mldsa44: PrivateKey = .{ .Mldsa44Ed25519 = .{
        .mldsa_public = @splat(0xA5),
        .ed25519_public = @splat(0x5A),
        .mldsa_seed = @splat(0x3C),
        .ed25519_seed = @splat(0xC3),
    } };
    mldsa44.clear();
    try expectZeroed(&mldsa44.Mldsa44Ed25519.mldsa_public);
    try expectZeroed(&mldsa44.Mldsa44Ed25519.ed25519_public);
    try expectZeroed(&mldsa44.Mldsa44Ed25519.mldsa_seed);
    try expectZeroed(&mldsa44.Mldsa44Ed25519.ed25519_seed);

    var ed25519: PrivateKey = .{ .Ed25519 = .{
        .public = @splat(0xA5),
        .secret = @splat(0x5A),
    } };
    ed25519.clear();
    try expectZeroed(&ed25519.Ed25519.public);
    try expectZeroed(&ed25519.Ed25519.secret);

    var ecdsa_p384: PrivateKey = .{ .EcdsaP384 = .{
        .public_sec1 = @splat(0xA5),
        .secret_scalar = @splat(0x5A),
    } };
    ecdsa_p384.clear();
    try expectZeroed(&ecdsa_p384.EcdsaP384.public_sec1);
    try expectZeroed(&ecdsa_p384.EcdsaP384.secret_scalar);

    var ecdsa: PrivateKey = .{ .EcdsaP256 = .{
        .public_sec1 = @splat(0xA5),
        .secret_scalar = @splat(0x5A),
    } };
    ecdsa.clear();
    try expectZeroed(&ecdsa.EcdsaP256.public_sec1);
    try expectZeroed(&ecdsa.EcdsaP256.secret_scalar);

    var rsa: PrivateKey = .{ .Rsa = .{} };
    try rsa.Rsa.d.set(&@as([MaxRsaBytes]u8, @splat(0xA5)));
    try rsa.Rsa.p.set(&@as([MaxRsaBytes]u8, @splat(0x5A)));
    rsa.clear();
    try expectZeroed(std.mem.asBytes(&rsa.Rsa));
}

test "private key signing errors clear caller output" {
    var key: PrivateKey = .{ .Ed25519 = .{
        .public = @splat(0),
        .secret = @splat(0),
    } };
    defer key.clear();
    var signature: SignatureBlob = undefined;
    @memset(std.mem.asBytes(&signature), 0xA5);

    try std.testing.expectError(error.SignatureAlgorithmMismatch, key.sign(.EcdsaP256Sha256, "message", &signature));
    try expectZeroed(std.mem.asBytes(&signature));
}

test "failed RSA component replacement clears the previous value" {
    var component: RsaComponent = .{};
    try component.set("private");
    var oversized: [MaxRsaBytes + 1]u8 = @splat(0xA5);
    defer std.crypto.secureZero(u8, &oversized);

    try std.testing.expectError(error.RsaComponentTooLarge, component.set(&oversized));
    try expectZeroed(std.mem.asBytes(&component));
}

test "failed public key blob operations clear caller output" {
    var out: Blob = .{};
    try out.set("previous-public-blob");
    var oversized: [MaxKeyBlobLen + 1]u8 = @splat(0x5A);
    try std.testing.expectError(error.InvalidKeyBlob, out.set(&oversized));
    try expectZeroed(std.mem.asBytes(&out));

    try out.set("previous-public-blob");
    const invalid_pub: PublicKey = .{ .EcdsaP256 = @splat(0) };
    try std.testing.expectError(error.InvalidKeyBlob, writePublicKeyBlob(invalid_pub, &out));
    try expectZeroed(std.mem.asBytes(&out));
}

pub fn parsePublicKeyBlob(blob: []const u8) KeyError!PublicKey {
    var r = BufferReader.init(blob);
    const alg = try r.readU32LenString();

    if (std.mem.eql(u8, alg, mldsa87_p384_name)) {
        const composite = try r.readU32LenString();
        if (r.off != r.payload.len) return error.InvalidKeyBlob;
        var comp_r = BufferReader.init(composite);
        const mldsa_pub = comp_r.readBytes(Mldsa87.PublicKey.encoded_length) catch return error.InvalidKeyBlob;
        const sec1 = comp_r.readU32LenString() catch return error.InvalidKeyBlob;
        if (comp_r.off != comp_r.payload.len) return error.InvalidKeyBlob;
        if (sec1.len != EcdsaP384.PublicKey.uncompressed_sec1_encoded_length or sec1[0] != 0x04) {
            return error.InvalidKeyBlob;
        }
        _ = Mldsa87.PublicKey.fromBytes(mldsa_pub[0..Mldsa87.PublicKey.encoded_length].*) catch return error.InvalidKeyBlob;
        _ = EcdsaP384.PublicKey.fromSec1(sec1) catch return error.InvalidKeyBlob;
        return .{ .Mldsa87P384 = .{
            .mldsa_public = mldsa_pub[0..Mldsa87.PublicKey.encoded_length].*,
            .ecdsa_sec1 = sec1[0..EcdsaP384.PublicKey.uncompressed_sec1_encoded_length].*,
        } };
    }

    if (std.mem.eql(u8, alg, mldsa44_ed25519_name)) {
        const composite = try r.readU32LenString();
        if (r.off != r.payload.len) return error.InvalidKeyBlob;
        if (composite.len != MaxMldsa44Ed25519PublicKeyPayloadLen) return error.InvalidKeyBlob;
        const mldsa_pub = composite[0..Mldsa44.PublicKey.encoded_length].*;
        const ed_pub = composite[Mldsa44.PublicKey.encoded_length..][0..Ed25519.PublicKey.encoded_length].*;
        _ = Mldsa44.PublicKey.fromBytes(mldsa_pub) catch return error.InvalidKeyBlob;
        _ = Ed25519.PublicKey.fromBytes(ed_pub) catch return error.InvalidKeyBlob;
        return .{ .Mldsa44Ed25519 = .{
            .mldsa_public = mldsa_pub,
            .ed25519_public = ed_pub,
        } };
    }

    if (std.mem.eql(u8, alg, ed25519_name)) {
        const public = try r.readU32LenString();
        if (public.len != Ed25519.PublicKey.encoded_length) return error.InvalidKeyBlob;
        _ = Ed25519.PublicKey.fromBytes(public[0..Ed25519.PublicKey.encoded_length].*) catch return error.InvalidKeyBlob;
        if (r.off != r.payload.len) return error.InvalidKeyBlob;
        return .{ .Ed25519 = public[0..Ed25519.PublicKey.encoded_length].* };
    }

    if (std.mem.eql(u8, alg, ecdsa_p384_name)) {
        const curve = try r.readU32LenString();
        if (!std.mem.eql(u8, curve, ecdsa_p384_curve_name)) return error.UnsupportedKeyAlgorithm;
        const sec1 = try r.readU32LenString();
        if (sec1.len != EcdsaP384.PublicKey.uncompressed_sec1_encoded_length or sec1[0] != 0x04) {
            return error.InvalidKeyBlob;
        }
        _ = EcdsaP384.PublicKey.fromSec1(sec1) catch return error.InvalidKeyBlob;
        if (r.off != r.payload.len) return error.InvalidKeyBlob;
        return .{ .EcdsaP384 = sec1[0..EcdsaP384.PublicKey.uncompressed_sec1_encoded_length].* };
    }

    if (std.mem.eql(u8, alg, ecdsa_p256_name)) {
        const curve = try r.readU32LenString();
        if (!std.mem.eql(u8, curve, ecdsa_p256_curve_name)) return error.UnsupportedKeyAlgorithm;
        const sec1 = try r.readU32LenString();
        if (sec1.len != EcdsaP256.PublicKey.uncompressed_sec1_encoded_length or sec1[0] != 0x04) {
            return error.InvalidKeyBlob;
        }
        _ = EcdsaP256.PublicKey.fromSec1(sec1) catch return error.InvalidKeyBlob;
        if (r.off != r.payload.len) return error.InvalidKeyBlob;
        return .{ .EcdsaP256 = sec1[0..EcdsaP256.PublicKey.uncompressed_sec1_encoded_length].* };
    }

    if (std.mem.eql(u8, alg, rsa_key_name)) {
        var e: RsaComponent = .{};
        var n: RsaComponent = .{};
        try e.set(try parsePositiveMpint(try r.readU32LenString(), error.InvalidKeyBlob));
        try n.set(try parsePositiveMpint(try r.readU32LenString(), error.InvalidKeyBlob));
        try validateRsaPublicComponents(n.slice(), e.slice());
        if (r.off != r.payload.len) return error.InvalidKeyBlob;
        return .{ .Rsa = .{ .n = n, .e = e } };
    }

    return error.UnsupportedKeyAlgorithm;
}

pub fn verifySignature(public_key: PublicKey, typed_signature: []const u8, msg: []const u8) KeyError!void {
    var r = BufferReader.init(typed_signature);
    const sig_name = try r.readU32LenString();
    const sig_payload = try r.readU32LenString();
    if (r.off != r.payload.len) return error.InvalidSignature;
    const sig_alg = SignatureAlgorithm.fromName(sig_name) orelse return error.UnsupportedKeyAlgorithm;
    if (!sig_alg.isEnabled()) return error.UnsupportedKeyAlgorithm;
    if (sig_alg.keyAlgorithm() != public_key.algorithm()) return error.SignatureAlgorithmMismatch;

    switch (public_key) {
        .Mldsa87P384 => |comp| {
            var sig_r = BufferReader.init(sig_payload);
            const mldsa_sig_bytes = sig_r.readBytes(Mldsa87.Signature.encoded_length) catch return error.InvalidSignature;
            const ecdsa_sig = try parseEcdsaSignatureReader(EcdsaP384, &sig_r);
            if (sig_r.off != sig_r.payload.len) return error.InvalidSignature;

            var m_prime = buildCompositeMessage(mldsa87_p384_domain, msg);
            defer std.crypto.secureZero(u8, &m_prime);

            const mldsa_pk = Mldsa87.PublicKey.fromBytes(comp.mldsa_public) catch return error.InvalidKeyBlob;
            const mldsa_sig = Mldsa87.Signature.fromBytes(mldsa_sig_bytes[0..Mldsa87.Signature.encoded_length].*) catch return error.InvalidSignature;
            mldsa_sig.verifyWithContext(&m_prime, mldsa_pk, mldsa87_p384_domain) catch return error.InvalidSignature;

            if (comp.ecdsa_sec1[0] != 0x04) return error.InvalidKeyBlob;
            const ecdsa_pk = EcdsaP384.PublicKey.fromSec1(&comp.ecdsa_sec1) catch return error.InvalidKeyBlob;
            ecdsa_sig.verify(&m_prime, ecdsa_pk) catch return error.InvalidSignature;
        },
        .Mldsa44Ed25519 => |comp| {
            if (sig_payload.len != Mldsa44.Signature.encoded_length + Ed25519.Signature.encoded_length) {
                return error.InvalidSignature;
            }
            const mldsa_sig_bytes = sig_payload[0..Mldsa44.Signature.encoded_length].*;
            const ed_sig_bytes = sig_payload[Mldsa44.Signature.encoded_length..][0..Ed25519.Signature.encoded_length].*;

            var m_prime = buildCompositeMessage(mldsa44_ed25519_domain, msg);
            defer std.crypto.secureZero(u8, &m_prime);

            const mldsa_pk = Mldsa44.PublicKey.fromBytes(comp.mldsa_public) catch return error.InvalidKeyBlob;
            const mldsa_sig = Mldsa44.Signature.fromBytes(mldsa_sig_bytes) catch return error.InvalidSignature;
            mldsa_sig.verifyWithContext(&m_prime, mldsa_pk, mldsa44_ed25519_domain) catch return error.InvalidSignature;

            const ed_pk = Ed25519.PublicKey.fromBytes(comp.ed25519_public) catch return error.InvalidKeyBlob;
            const ed_sig = Ed25519.Signature.fromBytes(ed_sig_bytes);
            ed_sig.verify(&m_prime, ed_pk) catch return error.InvalidSignature;
        },
        .Ed25519 => |raw_public| {
            if (sig_payload.len != Ed25519.Signature.encoded_length) return error.InvalidSignature;
            const pubkey = Ed25519.PublicKey.fromBytes(raw_public) catch return error.InvalidKeyBlob;
            const sig = Ed25519.Signature.fromBytes(sig_payload[0..Ed25519.Signature.encoded_length].*);
            sig.verify(msg, pubkey) catch return error.InvalidSignature;
        },
        .EcdsaP384 => |sec1| {
            if (sec1[0] != 0x04) return error.InvalidKeyBlob;
            const pubkey = EcdsaP384.PublicKey.fromSec1(&sec1) catch return error.InvalidKeyBlob;
            const sig = try parseEcdsaSignature(EcdsaP384, sig_payload);
            sig.verify(msg, pubkey) catch return error.InvalidSignature;
        },
        .EcdsaP256 => |sec1| {
            if (sec1[0] != 0x04) return error.InvalidKeyBlob;
            const pubkey = EcdsaP256.PublicKey.fromSec1(&sec1) catch return error.InvalidKeyBlob;
            const sig = try parseEcdsaSignature(EcdsaP256, sig_payload);
            sig.verify(msg, pubkey) catch return error.InvalidSignature;
        },
        .Rsa => |rsa| {
            switch (sig_alg) {
                .RsaSha256 => try rsaVerify(std.crypto.hash.sha2.Sha256, rsa.n.slice(), rsa.e.slice(), sig_payload, msg),
                .RsaSha512 => try rsaVerify(std.crypto.hash.sha2.Sha512, rsa.n.slice(), rsa.e.slice(), sig_payload, msg),
                else => return error.SignatureAlgorithmMismatch,
            }
        },
    }
}

pub fn signatureAlgorithm(typed_signature: []const u8) KeyError!SignatureAlgorithm {
    var r = BufferReader.init(typed_signature);
    const sig_name = try r.readU32LenString();
    _ = try r.readU32LenString();
    if (r.off != r.payload.len) return error.InvalidSignature;
    const alg = SignatureAlgorithm.fromName(sig_name) orelse return error.UnsupportedKeyAlgorithm;
    if (!alg.isEnabled()) return error.UnsupportedKeyAlgorithm;
    return alg;
}

pub fn writePublicKeyBlob(public_key: PublicKey, out: *Blob) KeyError![]const u8 {
    out.clear();
    errdefer out.clear();
    try public_key.validate();
    var w = BufferWriter.init(&out.buf, 0);
    switch (public_key) {
        .Mldsa87P384 => |comp| {
            var inner_buf: [MaxMldsa87P384PublicKeyPayloadLen]u8 = undefined;
            var inner = BufferWriter.init(&inner_buf, 0);
            try inner.writeBytes(&comp.mldsa_public);
            try inner.writeU32LenString(&comp.ecdsa_sec1);
            try w.writeU32LenString(mldsa87_p384_name);
            try w.writeU32LenString(inner.active());
        },
        .Mldsa44Ed25519 => |comp| {
            var inner_buf: [MaxMldsa44Ed25519PublicKeyPayloadLen]u8 = undefined;
            @memcpy(inner_buf[0..Mldsa44.PublicKey.encoded_length], &comp.mldsa_public);
            @memcpy(inner_buf[Mldsa44.PublicKey.encoded_length..], &comp.ed25519_public);
            try w.writeU32LenString(mldsa44_ed25519_name);
            try w.writeU32LenString(&inner_buf);
        },
        .Ed25519 => |raw| {
            try w.writeU32LenString(ed25519_name);
            try w.writeU32LenString(&raw);
        },
        .EcdsaP384 => |sec1| {
            try w.writeU32LenString(ecdsa_p384_name);
            try w.writeU32LenString(ecdsa_p384_curve_name);
            try w.writeU32LenString(&sec1);
        },
        .EcdsaP256 => |sec1| {
            try w.writeU32LenString(ecdsa_p256_name);
            try w.writeU32LenString(ecdsa_p256_curve_name);
            try w.writeU32LenString(&sec1);
        },
        .Rsa => |rsa| {
            try w.writeU32LenString(rsa_key_name);
            try writeMpint(&w, rsa.e.slice());
            try writeMpint(&w, rsa.n.slice());
        },
    }
    out.len = w.active().len;
    return out.slice();
}

pub fn selectHostKeyAlgorithm(peer_namelist: []const u8, private_key: ?*const PrivateKey) ?SignatureAlgorithm {
    if (private_key) |key| {
        var peer_names = std.mem.splitScalar(u8, peer_namelist, ',');
        while (peer_names.next()) |peer_name| {
            const alg = SignatureAlgorithm.fromName(peer_name) orelse continue;
            if (!alg.isEnabled()) continue;
            if (key.supportsSignatureAlgorithm(alg)) return alg;
        }
        return null;
    }

    for (client_hostkey_preference) |alg| {
        if (!nameListContains(peer_namelist, alg.name())) continue;
        return alg;
    }
    return null;
}

pub fn nameListContains(namelist: []const u8, needle: []const u8) bool {
    var iter = std.mem.splitSequence(u8, namelist, ",");
    while (iter.next()) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

pub fn writeMpint(w: *BufferWriter, bytes: []const u8) BufferError!void {
    const v = trimMpint(bytes);
    if (v.len == 0) {
        try w.writeU32(0);
        return;
    }

    const needs_pad = (v[0] & 0x80) != 0;
    try w.writeU32(@intCast(v.len + @intFromBool(needs_pad)));
    if (needs_pad) try w.writeU8(0);
    try w.writeBytes(v);
}

pub fn trimMpint(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) : (i += 1) {}
    return bytes[i..];
}

pub fn parsePositiveMpint(bytes: []const u8, err: KeyError) KeyError![]const u8 {
    if (bytes.len == 0 or (bytes[0] & 0x80) != 0) return err;
    if (bytes[0] == 0) {
        if (bytes.len == 1 or (bytes[1] & 0x80) == 0) return err;
        return bytes[1..];
    }
    return bytes;
}

fn parseEcdsaSignatureReader(comptime EcdsaScheme: type, r: *BufferReader) KeyError!EcdsaScheme.Signature {
    const r_raw = r.readU32LenString() catch return error.InvalidSignature;
    const s_raw = r.readU32LenString() catch return error.InvalidSignature;
    const r_mpint = try parsePositiveMpint(r_raw, error.InvalidSignature);
    const s_mpint = try parsePositiveMpint(s_raw, error.InvalidSignature);
    const coord_len = EcdsaScheme.SecretKey.encoded_length;
    if (r_mpint.len > coord_len or s_mpint.len > coord_len) {
        return error.InvalidSignature;
    }

    var raw: [EcdsaScheme.Signature.encoded_length]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &raw);
    @memcpy(raw[coord_len - r_mpint.len .. coord_len], r_mpint);
    @memcpy(raw[EcdsaScheme.Signature.encoded_length - s_mpint.len ..], s_mpint);
    return EcdsaScheme.Signature.fromBytes(raw);
}

fn parseEcdsaSignature(comptime EcdsaScheme: type, sig_payload: []const u8) KeyError!EcdsaScheme.Signature {
    var r = BufferReader.init(sig_payload);
    const sig = try parseEcdsaSignatureReader(EcdsaScheme, &r);
    if (r.off != r.payload.len) return error.InvalidSignature;
    return sig;
}

fn validateRsaPublicComponents(n: []const u8, e: []const u8) KeyError!void {
    if (n.len < MinRsaBytes) return error.RsaKeyTooSmall;
    if (n.len > MaxRsaBytes) return error.RsaComponentTooLarge;
    if (n[0] == 0 or e.len == 0 or e.len > 8 or e[0] == 0) return error.InvalidKeyBlob;
    const leading_bits: usize = 8 - @clz(n[0]);
    const modulus_bits = (n.len - 1) * 8 + leading_bits;
    if (modulus_bits < MinRsaBits) return error.RsaKeyTooSmall;
    if ((n[n.len - 1] & 1) == 0) return error.InvalidKeyBlob;
    if ((e[e.len - 1] & 1) == 0) return error.InvalidKeyBlob;
    if (e.len == 1 and e[0] < 3) return error.InvalidKeyBlob;
}

fn rsaSign(comptime Hash: type, key: *const RsaPrivateKey, msg: []const u8, out: *[MaxRsaBytes]u8) KeyError![]const u8 {
    try validateRsaPublicComponents(key.n.slice(), key.e.slice());
    const modulus_len = key.n.len;
    if (modulus_len == 0 or modulus_len > out.len) return error.InvalidKeyBlob;

    var encoded: [MaxRsaBytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded);
    try pkcs1v15Encode(Hash, msg, encoded[0..modulus_len]);

    const Modulus = std.crypto.ff.Modulus(MaxRsaBits);
    const modulus = Modulus.fromBytes(key.n.slice(), .big) catch return error.InvalidKeyBlob;
    const m = Modulus.Fe.fromBytes(modulus, encoded[0..modulus_len], .big) catch return error.InvalidKeyBlob;
    const s = modulus.powWithEncodedExponent(m, key.d.slice(), .big) catch return error.SigningFailed;
    s.toBytes(out[0..modulus_len], .big) catch return error.SigningFailed;
    return out[0..modulus_len];
}

fn rsaVerify(comptime Hash: type, n: []const u8, e: []const u8, sig: []const u8, msg: []const u8) KeyError!void {
    try validateRsaPublicComponents(n, e);
    if (sig.len != n.len) return error.InvalidSignature;

    const Modulus = std.crypto.ff.Modulus(MaxRsaBits);
    const modulus = Modulus.fromBytes(n, .big) catch return error.InvalidKeyBlob;
    const s = Modulus.Fe.fromBytes(modulus, sig, .big) catch return error.InvalidSignature;
    const m = modulus.powWithEncodedPublicExponent(s, e, .big) catch return error.InvalidSignature;

    var decoded: [MaxRsaBytes]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &decoded);
    m.toBytes(decoded[0..n.len], .big) catch return error.InvalidSignature;

    var expected: [MaxRsaBytes]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &expected);
    try pkcs1v15Encode(Hash, msg, expected[0..n.len]);
    if (!std.crypto.timing_safe.eql([MaxRsaBytes]u8, decoded, expected)) return error.InvalidSignature;
}

fn pkcs1v15Encode(comptime Hash: type, msg: []const u8, em: []u8) KeyError!void {
    const digest_prefix = digestInfoPrefix(Hash);
    const t_len = digest_prefix.len + Hash.digest_length;
    if (em.len < t_len + 11) return error.RsaKeyTooSmall;

    var digest: [Hash.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    Hash.hash(msg, &digest, .{});

    em[0] = 0x00;
    em[1] = 0x01;
    const ps_end = em.len - t_len - 1;
    @memset(em[2..ps_end], 0xff);
    em[ps_end] = 0x00;
    @memcpy(em[ps_end + 1 .. ps_end + 1 + digest_prefix.len], digest_prefix);
    @memcpy(em[em.len - Hash.digest_length ..], &digest);
}

fn digestInfoPrefix(comptime Hash: type) []const u8 {
    return &switch (Hash) {
        std.crypto.hash.sha2.Sha256 => .{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20,
        },
        std.crypto.hash.sha2.Sha512 => .{
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
            0x00, 0x04, 0x40,
        },
        else => @compileError("unsupported RSA hash"),
    };
}

test "nameListContains finds algorithm names exactly" {
    try std.testing.expect(nameListContains(client_hostkey_algorithms, rsa_sha2_512_name));
    try std.testing.expect(nameListContains(client_hostkey_algorithms, ed25519_name));
    try std.testing.expect(!nameListContains(client_hostkey_algorithms, "ssh-r"));
}

test "client host key preference favors modern compact keys first" {
    try std.testing.expectEqualStrings(
        "ssh-mldsa87-p384,ssh-mldsa44-ed25519,ssh-ed25519,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
        client_hostkey_algorithms,
    );
}

test "host key selection follows advertised client preference" {
    try std.testing.expectEqual(
        SignatureAlgorithm.Mldsa87P384,
        selectHostKeyAlgorithm("rsa-sha2-256,ssh-ed25519,ssh-mldsa44-ed25519,ssh-mldsa87-p384", null).?,
    );
    try std.testing.expectEqual(
        SignatureAlgorithm.Mldsa44Ed25519,
        selectHostKeyAlgorithm("rsa-sha2-256,ssh-ed25519,ssh-mldsa44-ed25519", null).?,
    );
    try std.testing.expectEqual(
        SignatureAlgorithm.Ed25519,
        selectHostKeyAlgorithm("rsa-sha2-256,rsa-sha2-512,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519", null).?,
    );
    try std.testing.expectEqual(
        SignatureAlgorithm.EcdsaP384Sha384,
        selectHostKeyAlgorithm("rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384", null).?,
    );
    try std.testing.expectEqual(
        SignatureAlgorithm.EcdsaP256Sha256,
        selectHostKeyAlgorithm("rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256", null).?,
    );
    try std.testing.expectEqual(
        SignatureAlgorithm.RsaSha512,
        selectHostKeyAlgorithm("rsa-sha2-256,rsa-sha2-512", null).?,
    );
    try std.testing.expectEqual(
        SignatureAlgorithm.RsaSha256,
        selectHostKeyAlgorithm("rsa-sha2-256", null).?,
    );
}

test "server host key selection follows peer client order and loaded key" {
    var rsa_key: PrivateKey = .{ .Rsa = .{} };
    defer rsa_key.clear();
    try std.testing.expectEqual(
        SignatureAlgorithm.RsaSha256,
        selectHostKeyAlgorithm("rsa-sha2-256,rsa-sha2-512", &rsa_key).?,
    );
    try std.testing.expect(
        selectHostKeyAlgorithm("ssh-ed25519,ecdsa-sha2-nistp256", &rsa_key) == null,
    );
}

test "RSA modulus policy enforces 2048 through 4096 bits and exponent at least three" {
    var modulus_2047: [MinRsaBytes]u8 = @splat(0xff);
    modulus_2047[0] = 0x7f;
    try std.testing.expectError(
        error.RsaKeyTooSmall,
        validateRsaPublicComponents(&modulus_2047, &.{3}),
    );
    var blob_backing: [MaxRsaPublicKeyBlobLen]u8 = undefined;
    var blob = BufferWriter.init(&blob_backing, 0);
    try blob.writeU32LenString(rsa_key_name);
    try writeMpint(&blob, &.{3});
    try writeMpint(&blob, &modulus_2047);
    try std.testing.expectError(error.RsaKeyTooSmall, parsePublicKeyBlob(blob.active()));
    var weak_private: PrivateKey = .{ .Rsa = .{} };
    defer weak_private.clear();
    try weak_private.Rsa.n.set(&modulus_2047);
    try weak_private.Rsa.e.set(&.{3});
    try weak_private.Rsa.d.set(&.{1});
    try weak_private.Rsa.iqmp.set(&.{1});
    try weak_private.Rsa.p.set(&.{1});
    try weak_private.Rsa.q.set(&.{1});
    try std.testing.expectError(error.RsaKeyTooSmall, weak_private.validate());
    var signature_backing: [64]u8 = undefined;
    var signature = BufferWriter.init(&signature_backing, 0);
    try signature.writeU32LenString(rsa_sha2_256_name);
    try signature.writeU32LenString("");
    try std.testing.expectError(
        error.RsaKeyTooSmall,
        verifySignature(weak_private.publicKey(), signature.active(), "message"),
    );
    var generated_signature: SignatureBlob = .{};
    try std.testing.expectError(
        error.RsaKeyTooSmall,
        weak_private.sign(.RsaSha256, "message", &generated_signature),
    );

    var modulus_2048: [MinRsaBytes]u8 = @splat(0xff);
    modulus_2048[0] = 0x80;
    try validateRsaPublicComponents(&modulus_2048, &.{3});
    try std.testing.expectError(
        error.InvalidKeyBlob,
        validateRsaPublicComponents(&modulus_2048, &.{1}),
    );

    const oversized: [MaxRsaBytes + 1]u8 = @splat(0xff);
    try std.testing.expectError(
        error.RsaComponentTooLarge,
        validateRsaPublicComponents(&oversized, &.{3}),
    );
}

test "RFC 8032 Ed25519 signature verifies through SSH encoding" {
    const public = [_]u8{
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    };
    const signature = [_]u8{
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
        0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
        0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
        0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
        0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
        0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
        0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
    };
    var typed_signature: [4 + ed25519_name.len + 4 + signature.len]u8 = undefined;
    var writer = BufferWriter.init(&typed_signature, 0);
    try writer.writeU32LenString(ed25519_name);
    try writer.writeU32LenString(&signature);

    try verifySignature(.{ .Ed25519 = public }, writer.active(), "");
    typed_signature[typed_signature.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verifySignature(.{ .Ed25519 = public }, &typed_signature, ""),
    );
}

test "mpint writer trims leading zeros and pads positive values" {
    var backing: [16]u8 = undefined;
    var w = BufferWriter.init(&backing, 0);
    try writeMpint(&w, &.{ 0, 0x80 });
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 2, 0, 0x80 }, w.active());
}

test "public key blob round-trip and malformed rejection for composite ML-DSA and P-384" {
    const PrivKey = @import("privkey.zig");

    var mldsa87_priv = PrivKey.testKeyMldsa87P384();
    defer mldsa87_priv.clear();
    var mldsa87_blob_buf: Blob = .{};
    const mldsa87_blob = try mldsa87_priv.publicBlob(&mldsa87_blob_buf);
    try std.testing.expectEqual(@as(usize, 2717), mldsa87_blob.len);
    const mldsa87_pub = try parsePublicKeyBlob(mldsa87_blob);
    try std.testing.expectEqual(KeyAlgorithm.Mldsa87P384, mldsa87_pub.algorithm());

    var mldsa87_bad = mldsa87_blob_buf;
    mldsa87_bad.buf[mldsa87_bad.len - 97] = 0x02; // corrupt uncompressed SEC1 prefix 0x04
    try std.testing.expectError(error.InvalidKeyBlob, parsePublicKeyBlob(mldsa87_bad.slice()));
    try std.testing.expectError(error.ReaderOutOfDataErr, parsePublicKeyBlob(mldsa87_blob[0 .. mldsa87_blob.len - 1]));
    var mldsa87_trailing: [MaxKeyBlobLen + 1]u8 = @splat(0);
    @memcpy(mldsa87_trailing[0..mldsa87_blob.len], mldsa87_blob);
    try std.testing.expectError(error.InvalidKeyBlob, parsePublicKeyBlob(mldsa87_trailing[0 .. mldsa87_blob.len + 1]));

    var mldsa44_priv = PrivKey.testKeyMldsa44Ed25519();
    defer mldsa44_priv.clear();
    var mldsa44_blob_buf: Blob = .{};
    const mldsa44_blob = try mldsa44_priv.publicBlob(&mldsa44_blob_buf);
    try std.testing.expectEqual(@as(usize, 4 + mldsa44_ed25519_name.len + 4 + 1344), mldsa44_blob.len);
    const mldsa44_pub = try parsePublicKeyBlob(mldsa44_blob);
    try std.testing.expectEqual(KeyAlgorithm.Mldsa44Ed25519, mldsa44_pub.algorithm());
    try std.testing.expectError(error.ReaderOutOfDataErr, parsePublicKeyBlob(mldsa44_blob[0 .. mldsa44_blob.len - 1]));
    var mldsa44_trailing: [MaxKeyBlobLen + 1]u8 = @splat(0);
    @memcpy(mldsa44_trailing[0..mldsa44_blob.len], mldsa44_blob);
    try std.testing.expectError(error.InvalidKeyBlob, parsePublicKeyBlob(mldsa44_trailing[0 .. mldsa44_blob.len + 1]));

    var p384_priv = PrivKey.testKeyEcdsaP384();
    defer p384_priv.clear();
    var p384_blob_buf: Blob = .{};
    const p384_blob = try p384_priv.publicBlob(&p384_blob_buf);
    const p384_pub = try parsePublicKeyBlob(p384_blob);
    try std.testing.expectEqual(KeyAlgorithm.EcdsaP384, p384_pub.algorithm());

    var p384_bad = p384_blob_buf;
    p384_bad.buf[p384_bad.len - 1] ^= 0x01; // off-curve point
    try std.testing.expectError(error.InvalidKeyBlob, parsePublicKeyBlob(p384_bad.slice()));
}

test "composite signature tamper rejection for ssh-mldsa87-p384 and ssh-mldsa44-ed25519" {
    const PrivKey = @import("privkey.zig");
    const msg = "sshz composite signature test message";

    // ssh-mldsa87-p384
    {
        var priv = PrivKey.testKeyMldsa87P384();
        defer priv.clear();
        const pub_key = priv.publicKey();

        var sig_blob: SignatureBlob = .{};
        defer sig_blob.clear();
        const sig = try priv.sign(.Mldsa87P384, msg, &sig_blob);
        try verifySignature(pub_key, sig, msg);

        // 1. Flip a byte in mldsa87_sig while keeping ECDSA P-384 r/s valid -> must fail!
        const inner_offset = 4 + mldsa87_p384_name.len + 4;
        var tampered_mldsa = sig_blob;
        tampered_mldsa.buf[inner_offset + 100] ^= 0x01;
        try std.testing.expectError(
            error.InvalidSignature,
            verifySignature(pub_key, tampered_mldsa.slice(), msg),
        );

        // 2. Flip a byte in classical ECDSA P-384 r/s while keeping mldsa87_sig valid -> must fail!
        var tampered_ecdsa = sig_blob;
        tampered_ecdsa.buf[tampered_ecdsa.len - 1] ^= 0x01;
        try std.testing.expectError(
            error.InvalidSignature,
            verifySignature(pub_key, tampered_ecdsa.slice(), msg),
        );

        // 3. Flip a byte in message M -> must fail!
        try std.testing.expectError(
            error.InvalidSignature,
            verifySignature(pub_key, sig, "sshz composite signature test messagf"),
        );
    }

    // ssh-mldsa44-ed25519
    {
        var priv = PrivKey.testKeyMldsa44Ed25519();
        defer priv.clear();
        const pub_key = priv.publicKey();

        var sig_blob: SignatureBlob = .{};
        defer sig_blob.clear();
        const sig = try priv.sign(.Mldsa44Ed25519, msg, &sig_blob);
        try verifySignature(pub_key, sig, msg);

        // 1. Flip a byte in mldsa44_sig while keeping Ed25519 sig valid -> must fail!
        const inner_offset = 4 + mldsa44_ed25519_name.len + 4;
        var tampered_mldsa = sig_blob;
        tampered_mldsa.buf[inner_offset + 100] ^= 0x01;
        try std.testing.expectError(
            error.InvalidSignature,
            verifySignature(pub_key, tampered_mldsa.slice(), msg),
        );

        // 2. Flip a byte in classical Ed25519 sig while keeping mldsa44_sig valid -> must fail!
        var tampered_ed = sig_blob;
        tampered_ed.buf[tampered_ed.len - 1] ^= 0x01;
        try std.testing.expectError(
            error.InvalidSignature,
            verifySignature(pub_key, tampered_ed.slice(), msg),
        );

        // 3. Flip a byte in message M -> must fail!
        try std.testing.expectError(
            error.InvalidSignature,
            verifySignature(pub_key, sig, "sshz composite signature test messagf"),
        );
    }
}

test "parsePublicKeyBlob and verifySignature reject non-canonical mpints, legacy ssh-rsa, and trailing bytes" {
    var modulus_2048: [MinRsaBytes]u8 = @splat(0xff);
    modulus_2048[0] = 0x80;

    // Negative RSA modulus mpint (missing leading 0x00 sign pad byte when high bit is set)
    var neg_n_backing: [MaxRsaPublicKeyBlobLen]u8 = undefined;
    var neg_n_blob = BufferWriter.init(&neg_n_backing, 0);
    try neg_n_blob.writeU32LenString(rsa_key_name);
    try writeMpint(&neg_n_blob, &.{ 1, 0, 1 });
    try neg_n_blob.writeU32LenString(&modulus_2048);
    try std.testing.expectError(error.InvalidKeyBlob, parsePublicKeyBlob(neg_n_blob.active()));

    // Excess leading zero on RSA exponent mpint (0x00, 0x01, 0x00, 0x01)
    var pad_e_backing: [MaxRsaPublicKeyBlobLen]u8 = undefined;
    var pad_e_blob = BufferWriter.init(&pad_e_backing, 0);
    try pad_e_blob.writeU32LenString(rsa_key_name);
    try pad_e_blob.writeU32LenString(&.{ 0x00, 0x01, 0x00, 0x01 });
    try writeMpint(&pad_e_blob, &modulus_2048);
    try std.testing.expectError(error.InvalidKeyBlob, parsePublicKeyBlob(pad_e_blob.active()));

    // Legacy ssh-rsa (SHA-1) signature is rejected
    var legacy_sig_backing: [64]u8 = undefined;
    var legacy_sig = BufferWriter.init(&legacy_sig_backing, 0);
    try legacy_sig.writeU32LenString(rsa_key_name);
    try legacy_sig.writeU32LenString("sha1sig");
    try std.testing.expectError(error.UnsupportedKeyAlgorithm, signatureAlgorithm(legacy_sig.active()));

    // Trailing byte on outer signature is rejected by signatureAlgorithm
    var trailing_sig_backing: [64]u8 = undefined;
    var trailing_sig = BufferWriter.init(&trailing_sig_backing, 0);
    try trailing_sig.writeU32LenString(ed25519_name);
    try trailing_sig.writeU32LenString(&.{ 0, 0, 0, 0 });
    try trailing_sig.writeU8(0x00);
    try std.testing.expectError(error.InvalidSignature, signatureAlgorithm(trailing_sig.active()));

    // Non-canonical ECDSA signature r/s mpints (zero, negative, excess leading zero, trailing bytes)
    const PrivKey = @import("privkey.zig");
    var p384_priv = PrivKey.testKeyEcdsaP384();
    defer p384_priv.clear();
    const p384_pub = p384_priv.publicKey();

    const bad_mpints = [_][]const u8{
        &.{},
        &.{0x00},
        &.{0x80},
        &.{ 0x00, 0x01 },
        &.{ 0x00, 0x00, 0x80 },
    };
    for (bad_mpints) |bad_r| {
        var inner_buf: [128]u8 = undefined;
        var inner_w = BufferWriter.init(&inner_buf, 0);
        try inner_w.writeU32LenString(bad_r);
        try inner_w.writeU32LenString(&.{0x01});

        var outer_buf: [192]u8 = undefined;
        var outer_w = BufferWriter.init(&outer_buf, 0);
        try outer_w.writeU32LenString(ecdsa_p384_name);
        try outer_w.writeU32LenString(inner_w.active());
        try std.testing.expectError(error.InvalidSignature, verifySignature(p384_pub, outer_w.active(), "msg"));
    }
}
