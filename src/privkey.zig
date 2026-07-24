const std = @import("std");
const util = @import("util.zig");
const crypto = std.crypto;
const TRACE = util.trace;
const UNSAFE_TRACEDUMP = util.unsafeTracedump;
const AesCtr = @import("aesctr.zig").AesCtr;
const BufferReader = @import("buffer.zig").BufferReader;
const BufferError = @import("buffer.zig").BufferError;
const Key = @import("key.zig");

// cat id_ed25519  | grep -v "^-----" | base64 -d | xxd

const KdfError = crypto.pwhash.KdfError;
const HasherError = crypto.pwhash.HasherError;

pub const PrivKeyError = PrivKeyInternalError || BufferError || Key.KeyError || std.base64.Error || crypto.pwhash.Error || KdfError || HasherError || std.crypto.errors.EncodingError;

pub const PrivKeyInternalError = error{
    PrivKeyOutofSpace,
    BadPrivKey,
    InvalidKeyDecrypt,
    InvalidInput,
    UnsupportedPrivKey,
};

fn decodeAsciiToBinary(keydata_ascii: []const u8, keydata_bin_buf: []u8) PrivKeyError![]u8 {
    const pre_banner = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const post_banner = "-----END OPENSSH PRIVATE KEY-----";

    var b64_slice_opt: ?[]const u8 = null;
    if (std.ascii.indexOfIgnoreCase(keydata_ascii, pre_banner)) |pre_banner_start| {
        if (std.ascii.indexOfIgnoreCase(keydata_ascii, post_banner)) |post_banner_start| {
            b64_slice_opt = keydata_ascii[pre_banner_start + pre_banner.len .. post_banner_start];
        }
    }
    if (b64_slice_opt) |b64_slice| {
        UNSAFE_TRACEDUMP(.Debug, "b64", .{}, b64_slice);
        var decoder = std.base64.Base64DecoderWithIgnore.init(std.base64.standard_alphabet_chars, '=', "\n");
        const decoded_size = decoder.calcSizeUpperBound(b64_slice.len);
        if (decoded_size > keydata_bin_buf.len) {
            return PrivKeyError.PrivKeyOutofSpace;
        }
        const sz = decoder.decode(keydata_bin_buf, b64_slice) catch return PrivKeyError.BadPrivKey;
        return keydata_bin_buf[0..sz];
    } else {
        return PrivKeyError.BadPrivKey;
    }
}

/// Returns caller-owned key material that must be cleared after use.
pub fn decodeOpenSshPrivateKey(keydata_ascii: []const u8, passphrase_opt: ?[]const u8) PrivKeyError!Key.PrivateKey {
    // Input text and the optional passphrase are borrowed; this function owns and
    // scrubs all decoded, KDF, and decrypted scratch that it creates.
    var keydata_bin_buf: [8192]u8 = undefined;
    defer crypto.secureZero(u8, &keydata_bin_buf);
    const bin = try decodeAsciiToBinary(keydata_ascii, &keydata_bin_buf);
    UNSAFE_TRACEDUMP(.Debug, "raw len={d}", .{bin.len}, bin);

    // http://dnaeon.github.io/openssh-private-key-binary-format/
    const AuthMagic = "openssh-key-v1\x00";
    if (bin.len < AuthMagic.len or !std.mem.eql(u8, AuthMagic, bin[0..AuthMagic.len])) {
        return PrivKeyError.BadPrivKey; // Not magical enough
    }

    var buffer = BufferReader.init(bin[AuthMagic.len..]);
    const ciphername = try buffer.readU32LenString();

    const kdfname = try buffer.readU32LenString();
    const kdfoptions_section = try buffer.readU32LenString();
    const n_keys = try buffer.readU32();

    if (n_keys != 1) {
        return PrivKeyError.BadPrivKey; // All known files have a single keypair
    }

    TRACE(.Debug, "ciphername={s} kdfname={s} n_keys={d}\n", .{ ciphername, kdfname, n_keys });

    const pubkey = try buffer.readU32LenString();
    UNSAFE_TRACEDUMP(.Debug, "pubkey", .{}, pubkey);

    var kbuffer = BufferReader.init(pubkey);
    const pkey_algo = try kbuffer.readU32LenString();
    TRACE(.Debug, "pkey_algo={s}\n", .{pkey_algo});
    const pkey_blob = try kbuffer.readU32LenString();
    UNSAFE_TRACEDUMP(.Debug, "pkey_blob", .{}, pkey_blob);

    const enc_section_off = buffer.off + 4 + AuthMagic.len; // current position is before u32 length field, then data blob
    const enc_section = try buffer.readU32LenString();

    if (std.mem.eql(u8, ciphername, "aes256-ctr")) {
        if (std.mem.eql(u8, kdfname, "bcrypt")) {
            if (passphrase_opt) |passphrase| {
                var buffer_kdfopt = BufferReader.init(kdfoptions_section);
                const salt = try buffer_kdfopt.readU32LenString();
                const rounds = try buffer_kdfopt.readU32();
                UNSAFE_TRACEDUMP(.Debug, "salt rounds={d}", .{rounds}, salt);
                if (salt.len != 16) {
                    return PrivKeyError.BadPrivKey;
                }

                const enc_algo = crypto.core.aes.Aes256;
                const AesCtrT = AesCtr(enc_algo);
                var hash: [AesCtrT.key_size + AesCtrT.iv_size]u8 = undefined;
                defer crypto.secureZero(u8, &hash);
                // https://github.com/openssh/openssh-portable/blob/826483d51a9fee60703298bbf839d9ce37943474/sshkey.c#L2880
                // need zig 0.14.0 for this https://github.com/ziglang/zig/pull/22027
                try crypto.pwhash.bcrypt.opensshKdf(passphrase, salt[0..16], &hash, rounds);
                UNSAFE_TRACEDUMP(.Debug, "bcrypt hash", .{}, &hash);
                // https://www.thedigitalcatonline.com/blog/2021/06/03/public-key-cryptography-openssh-private-keys/#a-poorly-documented-format-2ea8
                var aesctr = AesCtrT.init(hash[AesCtrT.key_size..].*, hash[0..AesCtrT.key_size].*);
                defer aesctr.clear();
                var dec: [8192]u8 = undefined;
                defer crypto.secureZero(u8, &dec);
                if (enc_section.len > dec.len) return PrivKeyError.PrivKeyOutofSpace;
                aesctr.encrypt(enc_section, dec[0..enc_section.len]) catch
                    return PrivKeyError.InvalidKeyDecrypt;
                UNSAFE_TRACEDUMP(.Debug, "dec", .{}, dec[0..enc_section.len]);
                // copy decrypted area over original encrypted
                @memcpy(keydata_bin_buf[enc_section_off .. enc_section_off + enc_section.len], dec[0..enc_section.len]);
            } else {
                return PrivKeyError.InvalidKeyDecrypt;
            }
        } else {
            return PrivKeyError.UnsupportedPrivKey;
        }
    } else {
        if (!std.mem.eql(u8, ciphername, "none")) {
            return PrivKeyError.UnsupportedPrivKey; // aes256-ctr/none are only options we support
        }
    }

    UNSAFE_TRACEDUMP(.Debug, "enc_section", .{}, enc_section);
    var encbuffer = BufferReader.init(enc_section);

    const checkint1 = try encbuffer.readU32();
    const checkint2 = try encbuffer.readU32();

    if (checkint1 != checkint2) { // should be same, proving key decryption worked
        return PrivKeyError.InvalidKeyDecrypt;
    }

    TRACE(.Debug, "enc section len = {d}\n", .{enc_section.len});
    TRACE(.Debug, "enc encbuffer local pos={d}\n", .{encbuffer.off});

    const key_algo = try encbuffer.readU32LenString();
    TRACE(.Debug, "key_algo={s}\n", .{key_algo});

    var private_key = try parsePrivateSectionKey(key_algo, &encbuffer);
    errdefer private_key.clear();

    var private_pubkey_blob: Key.Blob = .{};
    const generated_pubkey = try private_key.publicBlob(&private_pubkey_blob);
    if (!std.mem.eql(u8, generated_pubkey, pubkey)) {
        return PrivKeyError.BadPrivKey;
    }

    return private_key;
}

pub fn decodePrivKey(keydata_ascii: []const u8, passphrase_opt: ?[]const u8, privkey_blob: *[std.crypto.sign.Ed25519.SecretKey.encoded_length]u8, pubkey_blob: *[std.crypto.sign.Ed25519.PublicKey.encoded_length]u8) PrivKeyError!void {
    crypto.secureZero(u8, privkey_blob);
    crypto.secureZero(u8, pubkey_blob);
    errdefer crypto.secureZero(u8, privkey_blob);
    errdefer crypto.secureZero(u8, pubkey_blob);

    var private_key = try decodeOpenSshPrivateKey(keydata_ascii, passphrase_opt);
    defer private_key.clear();

    switch (private_key) {
        .Ed25519 => |*key| {
            @memcpy(privkey_blob, &key.secret);
            @memcpy(pubkey_blob, &key.public);
        },
        else => return PrivKeyError.UnsupportedPrivKey,
    }
}

fn parsePrivateSectionKey(key_algo: []const u8, encbuffer: *BufferReader) PrivKeyError!Key.PrivateKey {
    if (std.mem.eql(u8, key_algo, Key.ed25519_name)) {
        const key_blob_pub = try encbuffer.readU32LenString();
        const key_blob_prv = try encbuffer.readU32LenString();
        UNSAFE_TRACEDUMP(.Debug, "ed25519 key_blob_pub", .{}, key_blob_pub);
        UNSAFE_TRACEDUMP(.Debug, "ed25519 key_blob_prv", .{}, key_blob_prv);
        if (key_blob_pub.len != std.crypto.sign.Ed25519.PublicKey.encoded_length or
            key_blob_prv.len != std.crypto.sign.Ed25519.SecretKey.encoded_length)
        {
            return PrivKeyError.BadPrivKey;
        }
        return .{ .Ed25519 = .{
            .public = key_blob_pub[0..std.crypto.sign.Ed25519.PublicKey.encoded_length].*,
            .secret = key_blob_prv[0..std.crypto.sign.Ed25519.SecretKey.encoded_length].*,
        } };
    }

    if (std.mem.eql(u8, key_algo, Key.ecdsa_p256_name)) {
        const curve = try encbuffer.readU32LenString();
        if (!std.mem.eql(u8, curve, Key.ecdsa_p256_curve_name)) return PrivKeyError.UnsupportedPrivKey;
        const sec1 = try encbuffer.readU32LenString();
        if (sec1.len != std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length) {
            return PrivKeyError.BadPrivKey;
        }
        const secret_mpint = try encbuffer.readU32LenString();
        var secret_scalar = try mpintToFixed(std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.encoded_length, secret_mpint);
        defer crypto.secureZero(u8, &secret_scalar);
        var secret_key = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(secret_scalar) catch return PrivKeyError.BadPrivKey;
        defer crypto.secureZero(u8, std.mem.asBytes(&secret_key));
        var keypair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key) catch return PrivKeyError.BadPrivKey;
        defer crypto.secureZero(u8, std.mem.asBytes(&keypair));
        if (!std.mem.eql(u8, &keypair.public_key.toUncompressedSec1(), sec1)) return PrivKeyError.BadPrivKey;
        return .{ .EcdsaP256 = .{
            .public_sec1 = sec1[0..std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length].*,
            .secret_scalar = secret_scalar,
        } };
    }

    if (std.mem.eql(u8, key_algo, Key.rsa_key_name)) {
        var private_key: Key.PrivateKey = .{ .Rsa = .{} };
        errdefer private_key.clear();
        try private_key.Rsa.n.set(try encbuffer.readU32LenString());
        try private_key.Rsa.e.set(try encbuffer.readU32LenString());
        try private_key.Rsa.d.set(try encbuffer.readU32LenString());
        try private_key.Rsa.iqmp.set(try encbuffer.readU32LenString());
        try private_key.Rsa.p.set(try encbuffer.readU32LenString());
        try private_key.Rsa.q.set(try encbuffer.readU32LenString());
        return private_key;
    }

    return PrivKeyError.UnsupportedPrivKey;
}

fn mpintToFixed(comptime len: usize, mpint: []const u8) PrivKeyError![len]u8 {
    const trimmed = Key.trimMpint(mpint);
    if (trimmed.len > len) return PrivKeyError.BadPrivKey;
    var out: [len]u8 = .{0} ** len;
    @memcpy(out[len - trimmed.len ..], trimmed);
    return out;
}

pub const testkey_valid = "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" ++
    "QyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09QAAAJiIu1EaiLtR\n" ++
    "GgAAAAtzc2gtZWQyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09Q\n" ++
    "AAAECmd7pZcmWYhcQO0+7Oj0nfKWUtxISW8PApUuU2mMEo3OiDqOvpA9oyn5+lXqabMcvf\n" ++
    "LwllRYnXugOvYBVw93T1AAAAE3RyakBtdWRkeS5mcml0ei5ib3gBAg==\n" ++
    "-----END OPENSSH PRIVATE KEY-----\n";

const testkey_invalid_bad_preamble = "-----BEGIN sheep PRIVATE KEY-----\n" ++
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" ++
    "QyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09QAAAJiIu1EaiLtR\n" ++
    "GgAAAAtzc2gtZWQyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09Q\n" ++
    "AAAECmd7pZcmWYhcQO0+7Oj0nfKWUtxISW8PApUuU2mMEo3OiDqOvpA9oyn5+lXqabMcvf\n" ++
    "LwllRYnXugOvYBVw93T1AAAAE3RyakBtdWRkeS5mcml0ei5ib3gBAg==\n" ++
    "-----END OPENSSH PRIVATE KEY-----\n";

const testkey_invalid_missing_footer = "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" ++
    "QyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09QAAAJiIu1EaiLtR\n" ++
    "GgAAAAtzc2gtZWQyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09Q\n" ++
    "AAAECmd7pZcmWYhcQO0+7Oj0nfKWUtxISW8PApUuU2mMEo3OiDqOvpA9oyn5+lXqabMcvf\n" ++
    "LwllRYnXugOvYBVw93T1AAAAE3RyakBtdWRkeS5mcml0ei5ib3gBAg==\n";

const testkey_invalid_bad_base64 = "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++
    "!3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" ++
    "QyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09QAAAJiIu1EaiLtR\n" ++
    "GgAAAAtzc2gtZWQyNTUxOQAAACDog6jr6QPaMp+fpV6mmzHL3y8JZUWJ17oDr2AVcPd09Q\n" ++
    "AAAECmd7pZcmWYhcQO0+7Oj0nfKWUtxISW8PApUuU2mMEo3OiDqOvpA9oyn5+lXqabMcvf\n" ++
    "LwllRYnXugOvYBVw93T1AAAAE3RyakBtdWRkeS5mcml0ei5ib3gBAg==\n" ++
    "-----END OPENSSH PRIVATE KEY-----\n";

const testkey_encrypted_valid_passworded = "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++
    "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBbMFVQ8d\n" ++
    "i1La+cBNrgXD80AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIL0bjghULlZAQmP5\n" ++
    "rM/Q04YVwfpVMDn7UYVuQhD0VoL5AAAAoL2DUXL8F88zDCQ3fctyJwJ25+nOwx5wIVKsYX\n" ++
    "HBoLMzX2IfngLErsk4phzQ0NFUyP1m33LkgJE9xTXCd5NjP9jOZvMt9d9OK85CBanVd40L\n" ++
    "HH5xk/jrsrnfEKK5Jp51xgCLWhCwUNVhxU1WpLGnKU+v04XDLRAfvM3Z7J/D6X2QsjHpVc\n" ++
    "g2ILO29XLBcTFbYRCfxSezVzrkURuId+d3WYQ=\n" ++
    "-----END OPENSSH PRIVATE KEY-----\n";

const testkey_encrypted_valid_password = "secretpassword";

pub const testkey_ecdsa_p256 = "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n" ++
    "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQoNzjURTO/Ky+QNRi8TBgDlEqN1Pii\n" ++
    "5uGWIB2kfqd4y9JI4MEcV3GKfdhVGQQxCvMbiy+6FNpWVP5JvMUbyq27AAAAsN8uAk3fLg\n" ++
    "JNAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCg3ONRFM78rL5A1\n" ++
    "GLxMGAOUSo3U+KLm4ZYgHaR+p3jL0kjgwRxXcYp92FUZBDEK8xuLL7oU2lZU/km8xRvKrb\n" ++
    "sAAAAhALqVUmkFwlmnxIndTZ9+/sVOy5pP3A50/dLiNl6DBO0DAAAAEm1pc3Nob2QtZWNk\n" ++
    "c2EtdGVzdAECAwQF\n" ++
    "-----END OPENSSH PRIVATE KEY-----\n";

pub const testkey_rsa_2048 = "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++
    "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\n" ++
    "-----END OPENSSH PRIVATE KEY-----\n";

test "decodepriv" {
    var blob: [std.crypto.sign.Ed25519.SecretKey.encoded_length]u8 = undefined;
    defer crypto.secureZero(u8, &blob);
    var pubblob: [std.crypto.sign.Ed25519.PublicKey.encoded_length]u8 = undefined;
    defer crypto.secureZero(u8, &pubblob);

    try std.testing.expectError(PrivKeyError.BadPrivKey, decodePrivKey(testkey_invalid_bad_preamble, null, &blob, &pubblob));
    try std.testing.expectError(PrivKeyError.BadPrivKey, decodePrivKey(testkey_invalid_missing_footer, null, &blob, &pubblob));
    try std.testing.expectError(PrivKeyError.BadPrivKey, decodePrivKey(testkey_invalid_bad_base64, null, &blob, &pubblob));
    try decodePrivKey(testkey_encrypted_valid_passworded, testkey_encrypted_valid_password, &blob, &pubblob);
    try std.testing.expect(std.mem.eql(u8, &blob, &[_]u8{ 168, 158, 23, 77, 212, 94, 57, 255, 157, 6, 173, 128, 17, 109, 67, 232, 3, 126, 106, 1, 93, 9, 70, 135, 50, 35, 207, 108, 76, 128, 251, 24, 189, 27, 142, 8, 84, 46, 86, 64, 66, 99, 249, 172, 207, 208, 211, 134, 21, 193, 250, 85, 48, 57, 251, 81, 133, 110, 66, 16, 244, 86, 130, 249 }));
    try std.testing.expectError(PrivKeyError.InvalidKeyDecrypt, decodePrivKey(testkey_encrypted_valid_passworded, "notpassword", &blob, &pubblob));
    try std.testing.expectEqualSlices(u8, &(.{0} ** blob.len), &blob);
    try std.testing.expectEqualSlices(u8, &(.{0} ** pubblob.len), &pubblob);
    try decodePrivKey(testkey_valid, null, &blob, &pubblob);
    try std.testing.expect(std.mem.eql(u8, &blob, &[_]u8{ 166, 119, 186, 89, 114, 101, 152, 133, 196, 14, 211, 238, 206, 143, 73, 223, 41, 101, 45, 196, 132, 150, 240, 240, 41, 82, 229, 54, 152, 193, 40, 220, 232, 131, 168, 235, 233, 3, 218, 50, 159, 159, 165, 94, 166, 155, 49, 203, 223, 47, 9, 101, 69, 137, 215, 186, 3, 175, 96, 21, 112, 247, 116, 245 }));
}

test "decode OpenSSH private key algorithms and sign/verify" {
    const cases = .{
        .{ testkey_valid, Key.KeyAlgorithm.Ed25519 },
        .{ testkey_ecdsa_p256, Key.KeyAlgorithm.EcdsaP256 },
        .{ testkey_rsa_2048, Key.KeyAlgorithm.Rsa },
    };

    inline for (cases) |case| {
        var private_key = try decodeOpenSshPrivateKey(case[0], null);
        defer private_key.clear();
        try std.testing.expectEqual(case[1], private_key.algorithm());

        var public_blob: Key.Blob = .{};
        const blob = try private_key.publicBlob(&public_blob);
        const public_key = try Key.parsePublicKeyBlob(blob);

        var sig_blob: Key.SignatureBlob = .{};
        defer sig_blob.clear();
        const sig = try private_key.sign(private_key.defaultSignatureAlgorithm(), "misshod message", &sig_blob);
        try Key.verifySignature(public_key, sig, "misshod message");
        try std.testing.expectError(Key.KeyError.InvalidSignature, Key.verifySignature(public_key, sig, "tampered message"));
    }
}
