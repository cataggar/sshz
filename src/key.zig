const std = @import("std");
const BufferReader = @import("buffer.zig").BufferReader;
const BufferWriter = @import("buffer.zig").BufferWriter;
const BufferError = @import("buffer.zig").BufferError;

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const ed25519_name = "ssh-ed25519";
pub const ecdsa_p256_name = "ecdsa-sha2-nistp256";
pub const ecdsa_p256_curve_name = "nistp256";
pub const rsa_key_name = "ssh-rsa";
pub const rsa_sha2_256_name = "rsa-sha2-256";
pub const rsa_sha2_512_name = "rsa-sha2-512";

pub const client_hostkey_algorithms = ed25519_name ++ "," ++
    ecdsa_p256_name ++ "," ++
    rsa_sha2_512_name ++ "," ++
    rsa_sha2_256_name;

const client_hostkey_preference = [_]SignatureAlgorithm{ .Ed25519, .EcdsaP256Sha256, .RsaSha512, .RsaSha256 };

pub const MinRsaBits = 2048;
pub const MinRsaBytes = MinRsaBits / 8;
pub const MaxRsaBits = 4096;
pub const MaxRsaBytes = MaxRsaBits / 8;
pub const MaxPublicKeyBlobLen = 4 + ecdsa_p256_name.len + 4 + ecdsa_p256_curve_name.len + 4 + EcdsaP256.PublicKey.uncompressed_sec1_encoded_length;
pub const MaxRsaPublicKeyBlobLen = 4 + rsa_key_name.len + 4 + 8 + 4 + MaxRsaBytes + 1;
pub const MaxKeyBlobLen = @max(MaxPublicKeyBlobLen, MaxRsaPublicKeyBlobLen);
pub const MaxSignatureBlobLen = 4 + rsa_sha2_512_name.len + 4 + MaxRsaBytes;

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
    Ed25519,
    EcdsaP256,
    Rsa,
};

pub const SignatureAlgorithm = enum {
    Ed25519,
    EcdsaP256Sha256,
    RsaSha256,
    RsaSha512,

    pub fn fromName(alg_name: []const u8) ?SignatureAlgorithm {
        if (std.mem.eql(u8, alg_name, ed25519_name)) return .Ed25519;
        if (std.mem.eql(u8, alg_name, ecdsa_p256_name)) return .EcdsaP256Sha256;
        if (std.mem.eql(u8, alg_name, rsa_sha2_256_name)) return .RsaSha256;
        if (std.mem.eql(u8, alg_name, rsa_sha2_512_name)) return .RsaSha512;
        return null;
    }

    pub fn name(self: SignatureAlgorithm) []const u8 {
        return switch (self) {
            .Ed25519 => ed25519_name,
            .EcdsaP256Sha256 => ecdsa_p256_name,
            .RsaSha256 => rsa_sha2_256_name,
            .RsaSha512 => rsa_sha2_512_name,
        };
    }

    pub fn keyAlgorithm(self: SignatureAlgorithm) KeyAlgorithm {
        return switch (self) {
            .Ed25519 => .Ed25519,
            .EcdsaP256Sha256 => .EcdsaP256,
            .RsaSha256, .RsaSha512 => .Rsa,
        };
    }
};

pub const Blob = struct {
    buf: [MaxKeyBlobLen]u8 = undefined,
    len: usize = 0,

    pub fn set(self: *Blob, bytes: []const u8) KeyError!void {
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
    bytes: [MaxRsaBytes]u8 = .{0} ** MaxRsaBytes,
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
    Ed25519: [Ed25519.PublicKey.encoded_length]u8,
    EcdsaP256: [EcdsaP256.PublicKey.uncompressed_sec1_encoded_length]u8,
    Rsa: struct {
        n: RsaComponent,
        e: RsaComponent,
    },

    pub fn algorithm(self: PublicKey) KeyAlgorithm {
        return switch (self) {
            .Ed25519 => .Ed25519,
            .EcdsaP256 => .EcdsaP256,
            .Rsa => .Rsa,
        };
    }

    pub fn validate(self: PublicKey) KeyError!void {
        switch (self) {
            .Ed25519 => |raw| {
                _ = Ed25519.PublicKey.fromBytes(raw) catch return error.InvalidKeyBlob;
            },
            .EcdsaP256 => |sec1| {
                _ = EcdsaP256.PublicKey.fromSec1(&sec1) catch return error.InvalidKeyBlob;
            },
            .Rsa => |rsa| try validateRsaPublicComponents(rsa.n.slice(), rsa.e.slice()),
        }
    }
};

/// Caller-owned private key material; call clear before releasing or replacing it.
pub const PrivateKey = union(KeyAlgorithm) {
    Ed25519: struct {
        public: [Ed25519.PublicKey.encoded_length]u8,
        secret: [Ed25519.SecretKey.encoded_length]u8,
    },
    EcdsaP256: struct {
        public_sec1: [EcdsaP256.PublicKey.uncompressed_sec1_encoded_length]u8,
        secret_scalar: [EcdsaP256.SecretKey.encoded_length]u8,
    },
    Rsa: RsaPrivateKey,

    pub fn algorithm(self: *const PrivateKey) KeyAlgorithm {
        return switch (self.*) {
            .Ed25519 => .Ed25519,
            .EcdsaP256 => .EcdsaP256,
            .Rsa => .Rsa,
        };
    }

    pub fn defaultSignatureAlgorithm(self: *const PrivateKey) SignatureAlgorithm {
        return switch (self.*) {
            .Ed25519 => .Ed25519,
            .EcdsaP256 => .EcdsaP256Sha256,
            .Rsa => .RsaSha512,
        };
    }

    pub fn hostKeyAlgorithms(self: *const PrivateKey) []const u8 {
        return switch (self.*) {
            .Ed25519 => ed25519_name,
            .EcdsaP256 => ecdsa_p256_name,
            .Rsa => rsa_sha2_512_name ++ "," ++ rsa_sha2_256_name,
        };
    }

    pub fn supportsSignatureAlgorithm(self: *const PrivateKey, alg: SignatureAlgorithm) bool {
        return self.algorithm() == alg.keyAlgorithm();
    }

    pub fn publicBlob(self: *const PrivateKey, out: *Blob) KeyError![]const u8 {
        var w = BufferWriter.init(&out.buf, 0);
        switch (self.*) {
            .Ed25519 => |*key| {
                try w.writeU32LenString(ed25519_name);
                try w.writeU32LenString(&key.public);
            },
            .EcdsaP256 => |*key| {
                try w.writeU32LenString(ecdsa_p256_name);
                try w.writeU32LenString(ecdsa_p256_curve_name);
                try w.writeU32LenString(&key.public_sec1);
            },
            .Rsa => |*key| {
                try w.writeU32LenString(rsa_key_name);
                try writeMpint(&w, key.e.slice());
                try writeMpint(&w, key.n.slice());
            },
        }
        out.len = w.active().len;
        return out.slice();
    }

    pub fn publicKey(self: *const PrivateKey) PublicKey {
        return switch (self.*) {
            .Ed25519 => |*key| .{ .Ed25519 = key.public },
            .EcdsaP256 => |*key| .{ .EcdsaP256 = key.public_sec1 },
            .Rsa => |*key| .{ .Rsa = .{ .n = key.n, .e = key.e } },
        };
    }

    pub fn validate(self: *const PrivateKey) KeyError!void {
        switch (self.*) {
            .Ed25519 => |*key| {
                var secret = Ed25519.SecretKey.fromBytes(key.secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
                var keypair = Ed25519.KeyPair.fromSecretKey(secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&keypair));
                if (!std.mem.eql(u8, &keypair.public_key.toBytes(), &key.public)) return error.InvalidKeyBlob;
            },
            .EcdsaP256 => |*key| {
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

        var signature_payload_buf: [MaxRsaBytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &signature_payload_buf);
        var signature_payload: []const u8 = undefined;

        switch (self.*) {
            .Ed25519 => |*key| {
                var secret = Ed25519.SecretKey.fromBytes(key.secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
                var keypair = Ed25519.KeyPair.fromSecretKey(secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&keypair));
                var sig = keypair.sign(msg, null) catch return error.SigningFailed;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&sig));
                var sigbytes = sig.toBytes();
                defer std.crypto.secureZero(u8, &sigbytes);
                @memcpy(signature_payload_buf[0..sigbytes.len], &sigbytes);
                signature_payload = signature_payload_buf[0..sigbytes.len];
            },
            .EcdsaP256 => |*key| {
                var secret = EcdsaP256.SecretKey.fromBytes(key.secret_scalar) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
                var keypair = EcdsaP256.KeyPair.fromSecretKey(secret) catch return error.InvalidKeyBlob;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&keypair));
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
                    .RsaSha256 => try rsaSign(std.crypto.hash.sha2.Sha256, key, msg, &signature_payload_buf),
                    .RsaSha512 => try rsaSign(std.crypto.hash.sha2.Sha512, key, msg, &signature_payload_buf),
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
            .Ed25519 => .{ .Ed25519 = .{
                .public = .{0} ** Ed25519.PublicKey.encoded_length,
                .secret = .{0} ** Ed25519.SecretKey.encoded_length,
            } },
            .EcdsaP256 => .{ .EcdsaP256 = .{
                .public_sec1 = .{0} ** EcdsaP256.PublicKey.uncompressed_sec1_encoded_length,
                .secret_scalar = .{0} ** EcdsaP256.SecretKey.encoded_length,
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
    var ed25519: PrivateKey = .{ .Ed25519 = .{
        .public = .{0xA5} ** Ed25519.PublicKey.encoded_length,
        .secret = .{0x5A} ** Ed25519.SecretKey.encoded_length,
    } };
    ed25519.clear();
    try expectZeroed(&ed25519.Ed25519.public);
    try expectZeroed(&ed25519.Ed25519.secret);

    var ecdsa: PrivateKey = .{ .EcdsaP256 = .{
        .public_sec1 = .{0xA5} ** EcdsaP256.PublicKey.uncompressed_sec1_encoded_length,
        .secret_scalar = .{0x5A} ** EcdsaP256.SecretKey.encoded_length,
    } };
    ecdsa.clear();
    try expectZeroed(&ecdsa.EcdsaP256.public_sec1);
    try expectZeroed(&ecdsa.EcdsaP256.secret_scalar);

    var rsa: PrivateKey = .{ .Rsa = .{} };
    try rsa.Rsa.d.set(&(.{0xA5} ** MaxRsaBytes));
    try rsa.Rsa.p.set(&(.{0x5A} ** MaxRsaBytes));
    rsa.clear();
    try expectZeroed(std.mem.asBytes(&rsa.Rsa));
}

test "private key signing errors clear caller output" {
    var key: PrivateKey = .{ .Ed25519 = .{
        .public = .{0} ** Ed25519.PublicKey.encoded_length,
        .secret = .{0} ** Ed25519.SecretKey.encoded_length,
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
    var oversized: [MaxRsaBytes + 1]u8 = .{0xA5} ** (MaxRsaBytes + 1);
    defer std.crypto.secureZero(u8, &oversized);

    try std.testing.expectError(error.RsaComponentTooLarge, component.set(&oversized));
    try expectZeroed(std.mem.asBytes(&component));
}

pub fn parsePublicKeyBlob(blob: []const u8) KeyError!PublicKey {
    var r = BufferReader.init(blob);
    const alg = try r.readU32LenString();

    if (std.mem.eql(u8, alg, ed25519_name)) {
        const public = try r.readU32LenString();
        if (public.len != Ed25519.PublicKey.encoded_length) return error.InvalidKeyBlob;
        _ = Ed25519.PublicKey.fromBytes(public[0..Ed25519.PublicKey.encoded_length].*) catch return error.InvalidKeyBlob;
        if (r.off != r.payload.len) return error.InvalidKeyBlob;
        return .{ .Ed25519 = public[0..Ed25519.PublicKey.encoded_length].* };
    }

    if (std.mem.eql(u8, alg, ecdsa_p256_name)) {
        const curve = try r.readU32LenString();
        if (!std.mem.eql(u8, curve, ecdsa_p256_curve_name)) return error.UnsupportedKeyAlgorithm;
        const sec1 = try r.readU32LenString();
        if (sec1.len != EcdsaP256.PublicKey.uncompressed_sec1_encoded_length) return error.InvalidKeyBlob;
        _ = EcdsaP256.PublicKey.fromSec1(sec1) catch return error.InvalidKeyBlob;
        if (r.off != r.payload.len) return error.InvalidKeyBlob;
        return .{ .EcdsaP256 = sec1[0..EcdsaP256.PublicKey.uncompressed_sec1_encoded_length].* };
    }

    if (std.mem.eql(u8, alg, rsa_key_name)) {
        var e: RsaComponent = .{};
        var n: RsaComponent = .{};
        try e.set(try r.readU32LenString());
        try n.set(try r.readU32LenString());
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
    if (sig_alg.keyAlgorithm() != public_key.algorithm()) return error.SignatureAlgorithmMismatch;

    switch (public_key) {
        .Ed25519 => |raw_public| {
            if (sig_payload.len != Ed25519.Signature.encoded_length) return error.InvalidSignature;
            const pubkey = Ed25519.PublicKey.fromBytes(raw_public) catch return error.InvalidKeyBlob;
            const sig = Ed25519.Signature.fromBytes(sig_payload[0..Ed25519.Signature.encoded_length].*);
            sig.verify(msg, pubkey) catch return error.InvalidSignature;
        },
        .EcdsaP256 => |sec1| {
            const pubkey = EcdsaP256.PublicKey.fromSec1(&sec1) catch return error.InvalidKeyBlob;
            const sig = try parseEcdsaSignature(sig_payload);
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
    return SignatureAlgorithm.fromName(sig_name) orelse error.UnsupportedKeyAlgorithm;
}

pub fn writePublicKeyBlob(public_key: PublicKey, out: *Blob) KeyError![]const u8 {
    var w = BufferWriter.init(&out.buf, 0);
    switch (public_key) {
        .Ed25519 => |raw| {
            try w.writeU32LenString(ed25519_name);
            try w.writeU32LenString(&raw);
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

fn parseEcdsaSignature(sig_payload: []const u8) KeyError!EcdsaP256.Signature {
    var r = BufferReader.init(sig_payload);
    const r_mpint = trimMpint(try r.readU32LenString());
    const s_mpint = trimMpint(try r.readU32LenString());
    if (r.off != r.payload.len) return error.InvalidSignature;
    if (r_mpint.len > EcdsaP256.SecretKey.encoded_length or s_mpint.len > EcdsaP256.SecretKey.encoded_length) {
        return error.InvalidSignature;
    }

    var raw: [EcdsaP256.Signature.encoded_length]u8 = .{0} ** EcdsaP256.Signature.encoded_length;
    defer std.crypto.secureZero(u8, &raw);
    @memcpy(raw[EcdsaP256.SecretKey.encoded_length - r_mpint.len .. EcdsaP256.SecretKey.encoded_length], r_mpint);
    @memcpy(raw[EcdsaP256.Signature.encoded_length - s_mpint.len ..], s_mpint);
    return EcdsaP256.Signature.fromBytes(raw);
}

fn validateRsaPublicComponents(n: []const u8, e: []const u8) KeyError!void {
    if (n.len < MinRsaBytes) return error.RsaKeyTooSmall;
    if (n.len > MaxRsaBytes) return error.RsaComponentTooLarge;
    const leading_bits: usize = 8 - @clz(n[0]);
    const modulus_bits = (n.len - 1) * 8 + leading_bits;
    if (modulus_bits < MinRsaBits) return error.RsaKeyTooSmall;
    if (e.len == 0 or e.len > 8) return error.InvalidKeyBlob;
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

    var decoded: [MaxRsaBytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &decoded);
    m.toBytes(decoded[0..n.len], .big) catch return error.InvalidSignature;

    var expected: [MaxRsaBytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &expected);
    try pkcs1v15Encode(Hash, msg, expected[0..n.len]);
    if (!constantTimeEql(decoded[0..n.len], expected[0..n.len])) return error.InvalidSignature;
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

fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var acc: u8 = 0;
    for (a, b) |x, y| acc |= x ^ y;
    return acc == 0;
}

test "nameListContains finds algorithm names exactly" {
    try std.testing.expect(nameListContains(client_hostkey_algorithms, rsa_sha2_512_name));
    try std.testing.expect(nameListContains(client_hostkey_algorithms, ed25519_name));
    try std.testing.expect(!nameListContains(client_hostkey_algorithms, "ssh-r"));
}

test "client host key preference favors modern compact keys first" {
    try std.testing.expectEqualStrings(
        "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
        client_hostkey_algorithms,
    );
}

test "host key selection follows advertised client preference" {
    try std.testing.expectEqual(
        SignatureAlgorithm.Ed25519,
        selectHostKeyAlgorithm("rsa-sha2-256,rsa-sha2-512,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519", null).?,
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
    var modulus_2047: [MinRsaBytes]u8 = .{0xff} ** MinRsaBytes;
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

    var modulus_2048: [MinRsaBytes]u8 = .{0xff} ** MinRsaBytes;
    modulus_2048[0] = 0x80;
    try validateRsaPublicComponents(&modulus_2048, &.{3});
    try std.testing.expectError(
        error.InvalidKeyBlob,
        validateRsaPublicComponents(&modulus_2048, &.{1}),
    );

    const oversized: [MaxRsaBytes + 1]u8 = .{0xff} ** (MaxRsaBytes + 1);
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
