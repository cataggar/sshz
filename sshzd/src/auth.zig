const std = @import("std");
const sshz = @import("sshz");

pub const MaxAuthorizedKeysFileBytes = 1024 * 1024;
pub const MaxAuthorizedKeysLineBytes = 8192;
pub const MaxAuthorizedKeys = 4096;
const MaxKeyBlobBytes = 2717;

const mldsa87_p384_name = "ssh-mldsa87-p384";
const mldsa44_ed25519_name = "ssh-mldsa44-ed25519";
const ed25519_name = "ssh-ed25519";
const ecdsa_p384_name = "ecdsa-sha2-nistp384";
const ecdsa_p384_curve_name = "nistp384";
const ecdsa_name = "ecdsa-sha2-nistp256";
const ecdsa_curve_name = "nistp256";
const rsa_name = "ssh-rsa";
const rsa_sha2_256_name = "rsa-sha2-256";
const rsa_sha2_512_name = "rsa-sha2-512";

pub const ParseFailureReason = enum {
    file_too_large,
    line_too_long,
    too_many_keys,
    control_character,
    options_or_markers_unsupported,
    unsupported_key_type,
    missing_key_data,
    invalid_base64,
    key_blob_too_large,
    key_type_mismatch,
    malformed_key_blob,

    pub fn message(self: ParseFailureReason) []const u8 {
        return switch (self) {
            .file_too_large => "file exceeds the 1 MiB limit",
            .line_too_long => "line exceeds the 8192-byte limit",
            .too_many_keys => "file contains more than 4096 keys",
            .control_character => "line contains a control character",
            .options_or_markers_unsupported => "authorized_keys options and markers are not supported",
            .unsupported_key_type => "unsupported key type (supported: ssh-mldsa87-p384, ssh-mldsa44-ed25519, ssh-ed25519, ecdsa-sha2-nistp384, ecdsa-sha2-nistp256, ssh-rsa)",
            .missing_key_data => "missing base64 public-key data",
            .invalid_base64 => "invalid base64 public-key data",
            .key_blob_too_large => "decoded public-key blob is too large",
            .key_type_mismatch => "textual key type does not match the decoded key blob",
            .malformed_key_blob => "malformed or invalid SSH public-key blob",
        };
    }
};

pub const ParseFailure = struct {
    line: usize,
    reason: ParseFailureReason,
};

pub const ParseResult = union(enum) {
    authorized_keys: AuthorizedKeys,
    invalid: ParseFailure,
};

const KeyKind = enum {
    mldsa87_p384,
    mldsa44_ed25519,
    ed25519,
    ecdsa_p384,
    ecdsa_p256,
    rsa,
};

pub const AuthorizedKeys = struct {
    allocator: std.mem.Allocator,
    blobs: []const []const u8,

    pub fn parse(allocator: std.mem.Allocator, contents: []const u8) std.mem.Allocator.Error!ParseResult {
        if (contents.len > MaxAuthorizedKeysFileBytes) {
            return .{ .invalid = .{ .line = 0, .reason = .file_too_large } };
        }

        var key_count: usize = 0;
        var lines = std.mem.splitScalar(u8, contents, '\n');
        var line_number: usize = 1;
        while (lines.next()) |line| : (line_number += 1) {
            var decoded: [MaxKeyBlobBytes]u8 = undefined;
            const entry = decodeEntry(line, &decoded) catch |err| {
                return .{ .invalid = .{ .line = line_number, .reason = parseFailureReason(err) } };
            };
            if (entry != null) {
                key_count += 1;
                if (key_count > MaxAuthorizedKeys) {
                    return .{ .invalid = .{ .line = line_number, .reason = .too_many_keys } };
                }
            }
        }

        const blobs = try allocator.alloc([]const u8, key_count);
        errdefer allocator.free(blobs);

        var initialized: usize = 0;
        errdefer for (blobs[0..initialized]) |blob| allocator.free(blob);

        lines = std.mem.splitScalar(u8, contents, '\n');
        while (lines.next()) |line| {
            var decoded: [MaxKeyBlobBytes]u8 = undefined;
            const entry = decodeEntry(line, &decoded) catch unreachable;
            if (entry) |blob| {
                blobs[initialized] = try allocator.dupe(u8, blob);
                initialized += 1;
            }
        }

        return .{ .authorized_keys = .{ .allocator = allocator, .blobs = blobs } };
    }

    pub fn deinit(self: *AuthorizedKeys) void {
        for (self.blobs) |blob| self.allocator.free(blob);
        self.allocator.free(self.blobs);
        self.* = undefined;
    }

    fn allows(self: AuthorizedKeys, algorithm: []const u8, blob: []const u8) bool {
        const kind = validateKeyBlob(blob, null) catch return false;
        if (!requestAlgorithmMatches(algorithm, kind)) return false;

        var allowed: u8 = 0;
        for (self.blobs) |allowed_blob| {
            const matches = timingSafeAuthorizedValueEql(allowed_blob, blob);
            allowed |= @intFromBool(matches);
        }
        return allowed != 0;
    }
};

fn timingSafeAuthorizedValueEql(expected: []const u8, supplied: []const u8) bool {
    if (expected.len > MaxKeyBlobBytes or supplied.len > MaxKeyBlobBytes) return false;

    var expected_padded: [MaxKeyBlobBytes]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &expected_padded);
    var supplied_padded: [MaxKeyBlobBytes]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &supplied_padded);
    @memcpy(expected_padded[0..expected.len], expected);
    @memcpy(supplied_padded[0..supplied.len], supplied);
    const bytes_eql = std.crypto.timing_safe.eql(
        [MaxKeyBlobBytes]u8,
        expected_padded,
        supplied_padded,
    );
    return bytes_eql and (expected.len == supplied.len);
}

pub const PublicKeyAttempt = struct {
    algorithm: []const u8,
    blob: []const u8,
};

pub const Attempt = union(enum) {
    none,
    password: []const u8,
    public_key: PublicKeyAttempt,
};

pub const Policy = union(enum) {
    deny_all,
    authorized_keys: AuthorizedKeys,
    insecure_demo,

    pub fn deinit(self: *Policy) void {
        switch (self.*) {
            .authorized_keys => |*keys| keys.deinit(),
            .deny_all, .insecure_demo => {},
        }
    }

    pub fn allows(self: Policy, username: []const u8, attempt: Attempt) bool {
        return switch (self) {
            .deny_all => false,
            .authorized_keys => |keys| switch (attempt) {
                .public_key => |key| keys.allows(key.algorithm, key.blob),
                else => false,
            },
            .insecure_demo => switch (attempt) {
                .password => |password| timingSafeAuthorizedValueEql(username, password),
                .public_key => true,
                .none => false,
            },
        };
    }
};

const EntryError = error{
    LineTooLong,
    ControlCharacter,
    OptionsOrMarkersUnsupported,
    UnsupportedKeyType,
    MissingKeyData,
    InvalidBase64,
    KeyBlobTooLarge,
    KeyTypeMismatch,
    MalformedKeyBlob,
};

fn decodeEntry(raw_line: []const u8, output: *[MaxKeyBlobBytes]u8) EntryError!?[]const u8 {
    if (raw_line.len > MaxAuthorizedKeysLineBytes) return error.LineTooLong;

    const line = std.mem.trim(u8, raw_line, " \t\r");
    if (line.len == 0 or line[0] == '#') return null;

    for (line) |byte| {
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return error.ControlCharacter;
    }

    var position: usize = 0;
    const textual_type = nextToken(line, &position) orelse return error.UnsupportedKeyType;
    const expected_kind = keyKindFromAuthorizedKeysName(textual_type) orelse {
        if (isLeadingOptionOrMarker(textual_type, line[position..])) {
            return error.OptionsOrMarkersUnsupported;
        }
        return error.UnsupportedKeyType;
    };
    const encoded = nextToken(line, &position) orelse return error.MissingKeyData;

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch return error.InvalidBase64;
    if (decoded_len > output.len) return error.KeyBlobTooLarge;
    std.base64.standard.Decoder.decode(output[0..decoded_len], encoded) catch return error.InvalidBase64;

    const blob = output[0..decoded_len];
    _ = validateKeyBlob(blob, expected_kind) catch |err| switch (err) {
        error.KeyTypeMismatch => return error.KeyTypeMismatch,
        error.MalformedKeyBlob => return error.MalformedKeyBlob,
    };
    return blob;
}

fn parseFailureReason(err: EntryError) ParseFailureReason {
    return switch (err) {
        error.LineTooLong => .line_too_long,
        error.ControlCharacter => .control_character,
        error.OptionsOrMarkersUnsupported => .options_or_markers_unsupported,
        error.UnsupportedKeyType => .unsupported_key_type,
        error.MissingKeyData => .missing_key_data,
        error.InvalidBase64 => .invalid_base64,
        error.KeyBlobTooLarge => .key_blob_too_large,
        error.KeyTypeMismatch => .key_type_mismatch,
        error.MalformedKeyBlob => .malformed_key_blob,
    };
}

fn nextToken(line: []const u8, position: *usize) ?[]const u8 {
    while (position.* < line.len and (line[position.*] == ' ' or line[position.*] == '\t')) {
        position.* += 1;
    }
    if (position.* == line.len) return null;

    const start = position.*;
    while (position.* < line.len and line[position.*] != ' ' and line[position.*] != '\t') {
        position.* += 1;
    }
    return line[start..position.*];
}

fn keyKindFromAuthorizedKeysName(name: []const u8) ?KeyKind {
    if (std.mem.eql(u8, name, mldsa87_p384_name)) return .mldsa87_p384;
    if (std.mem.eql(u8, name, mldsa44_ed25519_name)) return .mldsa44_ed25519;
    if (std.mem.eql(u8, name, ed25519_name)) return .ed25519;
    if (std.mem.eql(u8, name, ecdsa_p384_name)) return .ecdsa_p384;
    if (std.mem.eql(u8, name, ecdsa_name)) return .ecdsa_p256;
    if (std.mem.eql(u8, name, rsa_name)) return .rsa;
    return null;
}

fn isLeadingOptionOrMarker(first_token: []const u8, remainder: []const u8) bool {
    if (first_token[0] == '@' or
        std.mem.indexOfAny(u8, first_token, "=,\"") != null)
    {
        return true;
    }

    const known_flag_options = [_][]const u8{
        "restrict",
        "cert-authority",
        "no-agent-forwarding",
        "no-port-forwarding",
        "no-pty",
        "no-user-rc",
        "no-X11-forwarding",
        "agent-forwarding",
        "port-forwarding",
        "pty",
        "user-rc",
        "X11-forwarding",
    };
    for (known_flag_options) |opt| {
        if (std.ascii.eqlIgnoreCase(first_token, opt)) return true;
    }

    var pos: usize = 0;
    if (nextToken(remainder, &pos)) |second_token| {
        if (keyKindFromAuthorizedKeysName(second_token) != null) return true;
    }
    return false;
}

const BlobValidationError = error{
    KeyTypeMismatch,
    MalformedKeyBlob,
};

fn validateKeyBlob(blob: []const u8, expected_kind: ?KeyKind) BlobValidationError!KeyKind {
    var position: usize = 0;
    const blob_type = readString(blob, &position) orelse return error.MalformedKeyBlob;
    const kind = keyKindFromAuthorizedKeysName(blob_type) orelse return error.MalformedKeyBlob;
    if (expected_kind) |expected| {
        if (expected != kind) return error.KeyTypeMismatch;
    }

    switch (kind) {
        .mldsa87_p384 => {
            const Mldsa87 = std.crypto.sign.mldsa.MLDSA87;
            const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey;
            const composite = readString(blob, &position) orelse return error.MalformedKeyBlob;
            if (composite.len != Mldsa87.PublicKey.encoded_length + 4 + P384.uncompressed_sec1_encoded_length) {
                return error.MalformedKeyBlob;
            }
            const q_len = std.mem.readInt(u32, composite[Mldsa87.PublicKey.encoded_length..][0..4], .big);
            const q = composite[Mldsa87.PublicKey.encoded_length + 4 ..];
            if (q_len != P384.uncompressed_sec1_encoded_length or q[0] != 0x04) {
                return error.MalformedKeyBlob;
            }
            _ = Mldsa87.PublicKey.fromBytes(composite[0..Mldsa87.PublicKey.encoded_length].*) catch {
                return error.MalformedKeyBlob;
            };
            _ = P384.fromSec1(q) catch {
                return error.MalformedKeyBlob;
            };
        },
        .mldsa44_ed25519 => {
            const Mldsa44 = std.crypto.sign.mldsa.MLDSA44;
            const Ed25519 = std.crypto.sign.Ed25519.PublicKey;
            const composite = readString(blob, &position) orelse return error.MalformedKeyBlob;
            if (composite.len != Mldsa44.PublicKey.encoded_length + Ed25519.encoded_length) {
                return error.MalformedKeyBlob;
            }
            _ = Mldsa44.PublicKey.fromBytes(composite[0..Mldsa44.PublicKey.encoded_length].*) catch {
                return error.MalformedKeyBlob;
            };
            _ = Ed25519.fromBytes(composite[Mldsa44.PublicKey.encoded_length..][0..Ed25519.encoded_length].*) catch {
                return error.MalformedKeyBlob;
            };
        },
        .ed25519 => {
            const public_key = readString(blob, &position) orelse return error.MalformedKeyBlob;
            if (public_key.len != std.crypto.sign.Ed25519.PublicKey.encoded_length) {
                return error.MalformedKeyBlob;
            }
        },
        .ecdsa_p384 => {
            const curve = readString(blob, &position) orelse return error.MalformedKeyBlob;
            if (!std.mem.eql(u8, curve, ecdsa_p384_curve_name)) return error.MalformedKeyBlob;
            const sec1 = readString(blob, &position) orelse return error.MalformedKeyBlob;
            if (sec1.len != std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey.uncompressed_sec1_encoded_length or sec1[0] != 0x04) {
                return error.MalformedKeyBlob;
            }
            _ = std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(sec1) catch {
                return error.MalformedKeyBlob;
            };
        },
        .ecdsa_p256 => {
            const curve = readString(blob, &position) orelse return error.MalformedKeyBlob;
            if (!std.mem.eql(u8, curve, ecdsa_curve_name)) return error.MalformedKeyBlob;
            const sec1 = readString(blob, &position) orelse return error.MalformedKeyBlob;
            if (sec1.len != std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length or sec1[0] != 0x04) {
                return error.MalformedKeyBlob;
            }
            _ = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(sec1) catch {
                return error.MalformedKeyBlob;
            };
        },
        .rsa => {
            const exponent_encoded = readString(blob, &position) orelse return error.MalformedKeyBlob;
            const modulus_encoded = readString(blob, &position) orelse return error.MalformedKeyBlob;
            if (!isCanonicalPositiveMpint(exponent_encoded) or !isCanonicalPositiveMpint(modulus_encoded)) {
                return error.MalformedKeyBlob;
            }
            const exponent = trimMpint(exponent_encoded);
            const modulus = trimMpint(modulus_encoded);
            if (exponent.len == 0 or exponent.len > 8 or modulus.len < 256 or modulus.len > 512) {
                return error.MalformedKeyBlob;
            }
            if ((exponent[exponent.len - 1] & 1) == 0 or (modulus[modulus.len - 1] & 1) == 0) {
                return error.MalformedKeyBlob;
            }
            if (exponent.len == 1 and exponent[0] < 3) {
                return error.MalformedKeyBlob;
            }
        },
    }

    if (position != blob.len) return error.MalformedKeyBlob;
    sshz.validateUserPublicKeyBlob(blob) catch return error.MalformedKeyBlob;
    return kind;
}

fn readString(blob: []const u8, position: *usize) ?[]const u8 {
    if (blob.len - position.* < 4) return null;
    const length: usize = std.mem.readInt(u32, blob[position.*..][0..4], .big);
    position.* += 4;
    if (length > blob.len - position.*) return null;
    const value = blob[position.* .. position.* + length];
    position.* += length;
    return value;
}

fn trimMpint(bytes: []const u8) []const u8 {
    if (bytes.len > 0 and bytes[0] == 0) return bytes[1..];
    return bytes;
}

fn isCanonicalPositiveMpint(bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    if (bytes[0] == 0) {
        return bytes.len > 1 and (bytes[1] & 0x80) != 0;
    }
    return (bytes[0] & 0x80) == 0;
}

fn requestAlgorithmMatches(algorithm: []const u8, kind: KeyKind) bool {
    return switch (kind) {
        .mldsa87_p384 => std.mem.eql(u8, algorithm, mldsa87_p384_name),
        .mldsa44_ed25519 => std.mem.eql(u8, algorithm, mldsa44_ed25519_name),
        .ed25519 => std.mem.eql(u8, algorithm, ed25519_name),
        .ecdsa_p384 => std.mem.eql(u8, algorithm, ecdsa_p384_name),
        .ecdsa_p256 => std.mem.eql(u8, algorithm, ecdsa_name),
        .rsa => std.mem.eql(u8, algorithm, rsa_sha2_256_name) or
            std.mem.eql(u8, algorithm, rsa_sha2_512_name),
    };
}

const allowed_ed25519_line =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER test key\n";
const allowed_ed25519_blob =
    "\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" ++ @as([32]u8, @splat(0x11));
const wrong_ed25519_blob =
    "\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" ++ @as([32]u8, @splat(0x22));

fn parseTestPolicy(contents: []const u8) !Policy {
    const result = try AuthorizedKeys.parse(std.testing.allocator, contents);
    return switch (result) {
        .authorized_keys => |keys| .{ .authorized_keys = keys },
        .invalid => error.InvalidTestFixture,
    };
}

test "authorized key is allowed" {
    var policy = try parseTestPolicy(allowed_ed25519_line);
    defer policy.deinit();

    try std.testing.expect(policy.allows("alice", .{ .public_key = .{
        .algorithm = ed25519_name,
        .blob = allowed_ed25519_blob,
    } }));
}

test "wrong key with the same textual prefix is rejected" {
    var policy = try parseTestPolicy(allowed_ed25519_line);
    defer policy.deinit();

    try std.testing.expect(!policy.allows("alice", .{ .public_key = .{
        .algorithm = ed25519_name,
        .blob = wrong_ed25519_blob,
    } }));
}

test "authorization-sensitive equal-length comparison checks every byte" {
    const expected = "same-length-authorized-value";
    var wrong_first = expected.*;
    wrong_first[0] ^= 1;
    var wrong_last = expected.*;
    wrong_last[wrong_last.len - 1] ^= 1;

    try std.testing.expect(timingSafeAuthorizedValueEql(expected, expected));
    try std.testing.expect(!timingSafeAuthorizedValueEql(expected, &wrong_first));
    try std.testing.expect(!timingSafeAuthorizedValueEql(expected, &wrong_last));
    try std.testing.expect(!timingSafeAuthorizedValueEql(expected, expected[0 .. expected.len - 1]));
}

test "malformed authorized_keys entry is rejected" {
    var result = try AuthorizedKeys.parse(
        std.testing.allocator,
        "ssh-ed25519 not-base64!\n",
    );
    switch (result) {
        .invalid => |failure| {
            try std.testing.expectEqual(@as(usize, 1), failure.line);
            try std.testing.expectEqual(ParseFailureReason.invalid_base64, failure.reason);
        },
        .authorized_keys => |*keys| {
            keys.deinit();
            return error.TestUnexpectedResult;
        },
    }
}

test "authorized_keys parser rejects trailing public-key blob data" {
    var result = try AuthorizedKeys.parse(
        std.testing.allocator,
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERERanVuaw==\n",
    );
    switch (result) {
        .invalid => |failure| {
            try std.testing.expectEqual(ParseFailureReason.malformed_key_blob, failure.reason);
        },
        .authorized_keys => |*keys| {
            keys.deinit();
            return error.TestUnexpectedResult;
        },
    }
}

test "authorized_keys options and markers are explicitly unsupported" {
    const cases = [_][]const u8{
        "from=\"192.0.2.1\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER\n",
        "restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER\n",
        "no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER\n",
        "@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER\n",
    };
    for (cases) |line| {
        var result = try AuthorizedKeys.parse(std.testing.allocator, line);
        switch (result) {
            .invalid => |failure| {
                try std.testing.expectEqual(ParseFailureReason.options_or_markers_unsupported, failure.reason);
            },
            .authorized_keys => |*keys| {
                keys.deinit();
                return error.TestUnexpectedResult;
            },
        }
    }
}

test "ECDSA P-256 and RSA authorized_keys forms are supported" {
    var rsa_blob_buffer: [4 + rsa_name.len + 4 + 3 + 4 + 257]u8 = undefined;
    var offset: usize = 0;
    std.mem.writeInt(u32, rsa_blob_buffer[offset..][0..4], rsa_name.len, .big);
    offset += 4;
    @memcpy(rsa_blob_buffer[offset..][0..rsa_name.len], rsa_name);
    offset += rsa_name.len;
    std.mem.writeInt(u32, rsa_blob_buffer[offset..][0..4], 3, .big);
    offset += 4;
    const exponent = [_]u8{ 0x01, 0x00, 0x01 };
    @memcpy(rsa_blob_buffer[offset..][0..3], &exponent);
    offset += 3;
    std.mem.writeInt(u32, rsa_blob_buffer[offset..][0..4], 257, .big);
    offset += 4;
    rsa_blob_buffer[offset] = 0;
    offset += 1;
    @memset(rsa_blob_buffer[offset..][0..256], 0xff);
    offset += 256;

    var rsa_encoded_buffer: [std.base64.standard.Encoder.calcSize(rsa_blob_buffer.len)]u8 = undefined;
    const rsa_encoded = std.base64.standard.Encoder.encode(&rsa_encoded_buffer, &rsa_blob_buffer);
    var supported_keys_buffer: [2048]u8 = undefined;
    const supported_keys = try std.fmt.bufPrint(
        &supported_keys_buffer,
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPq6tky+pSuLwH9JTUoYPkCsQmMZJIz34KqlegNcnvlVE+mP+MHyKybbp4UNGiSG3QHudy0XZK1FfgRk7e2h1vc= ecdsa\nssh-rsa {s} rsa\n",
        .{rsa_encoded},
    );
    var policy = try parseTestPolicy(supported_keys);
    defer policy.deinit();

    try std.testing.expectEqual(@as(usize, 2), policy.authorized_keys.blobs.len);
    try std.testing.expect(policy.allows("alice", .{ .public_key = .{
        .algorithm = ecdsa_name,
        .blob = policy.authorized_keys.blobs[0],
    } }));
    try std.testing.expect(policy.allows("alice", .{ .public_key = .{
        .algorithm = rsa_sha2_256_name,
        .blob = policy.authorized_keys.blobs[1],
    } }));
    try std.testing.expect(policy.allows("alice", .{ .public_key = .{
        .algorithm = rsa_sha2_512_name,
        .blob = policy.authorized_keys.blobs[1],
    } }));
}

test "authorized_keys rejects RSA keys below the core policy" {
    var result = try AuthorizedKeys.parse(
        std.testing.allocator,
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC8XDzOZcf5QiO121OYvYxBl0dvQ0BeMRfuZtNiIizxgsTbg7uGYITFdv7BeA8cFxWVZ5ZOzxYJR0AZrs8lEpJq9RikrcGz6ATVWH0D2+q3rG7TYo2oX/eVj7O4sxzZnUndVVVe4WbNdACFKXEf6W0IgKugsXryznIX43SQhrBMrQ== weak\n",
    );
    switch (result) {
        .invalid => |failure| {
            try std.testing.expectEqual(ParseFailureReason.malformed_key_blob, failure.reason);
        },
        .authorized_keys => |*keys| {
            keys.deinit();
            return error.TestUnexpectedResult;
        },
    }
}

test "authorized_keys policy rejects unsupported authentication methods" {
    var policy = try parseTestPolicy(allowed_ed25519_line);
    defer policy.deinit();

    try std.testing.expect(!policy.allows("alice", .{ .password = "alice" }));
    try std.testing.expect(!policy.allows("alice", .none));
    try std.testing.expect(!policy.allows("alice", .{ .public_key = .{
        .algorithm = rsa_name,
        .blob = allowed_ed25519_blob,
    } }));
}

test "no policy rejects every authentication method" {
    const policy: Policy = .deny_all;
    try std.testing.expect(!policy.allows("alice", .{ .password = "alice" }));
    try std.testing.expect(!policy.allows("alice", .{ .public_key = .{
        .algorithm = ed25519_name,
        .blob = allowed_ed25519_blob,
    } }));
}

test "explicit insecure demo policy retains legacy behavior" {
    const policy: Policy = .insecure_demo;
    try std.testing.expect(policy.allows("alice", .{ .password = "alice" }));
    try std.testing.expect(!policy.allows("alice", .{ .password = "wrong" }));
    try std.testing.expect(policy.allows("alice", .{ .public_key = .{
        .algorithm = ed25519_name,
        .blob = wrong_ed25519_blob,
    } }));
    try std.testing.expect(!policy.allows("alice", .none));
}

test "ML-DSA composite and ECDSA P-384 authorized_keys forms are supported" {
    const Mldsa87 = std.crypto.sign.mldsa.MLDSA87;
    const Mldsa44 = std.crypto.sign.mldsa.MLDSA44;
    const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
    const Ed25519 = std.crypto.sign.Ed25519;

    const mldsa87_seed: [Mldsa87.seed_length]u8 = @splat(0x31);
    const mldsa87_kp = Mldsa87.newKeyFromSeed(&mldsa87_seed);
    const mldsa87_pub = mldsa87_kp.pk.toBytes();
    const p384_scalar: [P384.SecretKey.encoded_length]u8 = @splat(0x32);
    const p384_kp = try P384.KeyPair.fromSecretKey(try P384.SecretKey.fromBytes(p384_scalar));
    const p384_sec1 = p384_kp.public_key.toUncompressedSec1();

    var mldsa87_blob: [4 + mldsa87_p384_name.len + 4 + Mldsa87.PublicKey.encoded_length + 4 + p384_sec1.len]u8 = undefined;
    var off: usize = 0;
    std.mem.writeInt(u32, mldsa87_blob[off..][0..4], mldsa87_p384_name.len, .big);
    off += 4;
    @memcpy(mldsa87_blob[off..][0..mldsa87_p384_name.len], mldsa87_p384_name);
    off += mldsa87_p384_name.len;
    std.mem.writeInt(u32, mldsa87_blob[off..][0..4], @intCast(Mldsa87.PublicKey.encoded_length + 4 + p384_sec1.len), .big);
    off += 4;
    @memcpy(mldsa87_blob[off..][0..Mldsa87.PublicKey.encoded_length], &mldsa87_pub);
    off += Mldsa87.PublicKey.encoded_length;
    std.mem.writeInt(u32, mldsa87_blob[off..][0..4], p384_sec1.len, .big);
    off += 4;
    @memcpy(mldsa87_blob[off..][0..p384_sec1.len], &p384_sec1);

    const mldsa44_seed: [Mldsa44.seed_length]u8 = @splat(0x41);
    const mldsa44_kp = Mldsa44.newKeyFromSeed(&mldsa44_seed);
    const mldsa44_pub = mldsa44_kp.pk.toBytes();
    const ed_seed: [Ed25519.KeyPair.seed_length]u8 = @splat(0x42);
    const ed_kp = try Ed25519.KeyPair.generateDeterministic(ed_seed);
    const ed_pub = ed_kp.public_key.toBytes();

    var mldsa44_blob: [4 + mldsa44_ed25519_name.len + 4 + Mldsa44.PublicKey.encoded_length + ed_pub.len]u8 = undefined;
    off = 0;
    std.mem.writeInt(u32, mldsa44_blob[off..][0..4], mldsa44_ed25519_name.len, .big);
    off += 4;
    @memcpy(mldsa44_blob[off..][0..mldsa44_ed25519_name.len], mldsa44_ed25519_name);
    off += mldsa44_ed25519_name.len;
    std.mem.writeInt(u32, mldsa44_blob[off..][0..4], @intCast(Mldsa44.PublicKey.encoded_length + ed_pub.len), .big);
    off += 4;
    @memcpy(mldsa44_blob[off..][0..Mldsa44.PublicKey.encoded_length], &mldsa44_pub);
    off += Mldsa44.PublicKey.encoded_length;
    @memcpy(mldsa44_blob[off..][0..ed_pub.len], &ed_pub);

    var p384_blob: [4 + ecdsa_p384_name.len + 4 + ecdsa_p384_curve_name.len + 4 + p384_sec1.len]u8 = undefined;
    off = 0;
    std.mem.writeInt(u32, p384_blob[off..][0..4], ecdsa_p384_name.len, .big);
    off += 4;
    @memcpy(p384_blob[off..][0..ecdsa_p384_name.len], ecdsa_p384_name);
    off += ecdsa_p384_name.len;
    std.mem.writeInt(u32, p384_blob[off..][0..4], ecdsa_p384_curve_name.len, .big);
    off += 4;
    @memcpy(p384_blob[off..][0..ecdsa_p384_curve_name.len], ecdsa_p384_curve_name);
    off += ecdsa_p384_curve_name.len;
    std.mem.writeInt(u32, p384_blob[off..][0..4], p384_sec1.len, .big);
    off += 4;
    @memcpy(p384_blob[off..][0..p384_sec1.len], &p384_sec1);

    var mldsa87_b64_buf: [std.base64.standard.Encoder.calcSize(mldsa87_blob.len)]u8 = undefined;
    const mldsa87_b64 = std.base64.standard.Encoder.encode(&mldsa87_b64_buf, &mldsa87_blob);
    var mldsa44_b64_buf: [std.base64.standard.Encoder.calcSize(mldsa44_blob.len)]u8 = undefined;
    const mldsa44_b64 = std.base64.standard.Encoder.encode(&mldsa44_b64_buf, &mldsa44_blob);
    var p384_b64_buf: [std.base64.standard.Encoder.calcSize(p384_blob.len)]u8 = undefined;
    const p384_b64 = std.base64.standard.Encoder.encode(&p384_b64_buf, &p384_blob);

    var lines_buf: [8192]u8 = undefined;
    const lines = try std.fmt.bufPrint(
        &lines_buf,
        "{s} {s} mldsa87\n{s} {s} mldsa44\n{s} {s} p384\n",
        .{ mldsa87_p384_name, mldsa87_b64, mldsa44_ed25519_name, mldsa44_b64, ecdsa_p384_name, p384_b64 },
    );
    var policy = try parseTestPolicy(lines);
    defer policy.deinit();

    try std.testing.expectEqual(@as(usize, 3), policy.authorized_keys.blobs.len);
    try std.testing.expect(policy.allows("alice", .{ .public_key = .{
        .algorithm = mldsa87_p384_name,
        .blob = &mldsa87_blob,
    } }));
    try std.testing.expect(policy.allows("alice", .{ .public_key = .{
        .algorithm = mldsa44_ed25519_name,
        .blob = &mldsa44_blob,
    } }));
    try std.testing.expect(policy.allows("alice", .{ .public_key = .{
        .algorithm = ecdsa_p384_name,
        .blob = &p384_blob,
    } }));
    try std.testing.expect(!policy.allows("alice", .{ .public_key = .{
        .algorithm = ed25519_name,
        .blob = &mldsa87_blob,
    } }));
}
