const std = @import("std");

pub const max_file_size = 4 * 1024 * 1024;
pub const max_line_length = 64 * 1024;
pub const max_host_field_length = 8 * 1024;
pub const max_endpoint_length = 1024;
pub const max_key_blob_length = 16 * 1024;

pub const Match = enum {
    match,
    unknown,
    changed,
};

pub const AcceptResult = enum {
    already_trusted,
    added,
};

const supported_key_types = [_][]const u8{
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ssh-rsa",
};

const BlobReader = struct {
    bytes: []const u8,
    index: usize = 0,

    fn readString(self: *BlobReader) ![]const u8 {
        if (self.bytes.len - self.index < 4) return error.MalformedKeyBlob;
        const len = std.mem.readInt(u32, self.bytes[self.index..][0..4], .big);
        self.index += 4;
        if (len > self.bytes.len - self.index) return error.MalformedKeyBlob;
        const result = self.bytes[self.index..][0..len];
        self.index += len;
        return result;
    }

    fn atEnd(self: *const BlobReader) bool {
        return self.index == self.bytes.len;
    }
};

fn isSupportedKeyType(key_type: []const u8) bool {
    for (supported_key_types) |supported| {
        if (std.mem.eql(u8, key_type, supported)) return true;
    }
    return false;
}

fn validatePositiveMpint(value: []const u8) !void {
    if (value.len == 0) return error.MalformedKeyBlob;
    if (value[0] & 0x80 != 0) return error.MalformedKeyBlob;
    if (value.len > 1 and value[0] == 0 and value[1] & 0x80 == 0) {
        return error.MalformedKeyBlob;
    }
}

pub fn keyType(raw_key: []const u8) ![]const u8 {
    if (raw_key.len == 0 or raw_key.len > max_key_blob_length) {
        return error.MalformedKeyBlob;
    }

    var reader: BlobReader = .{ .bytes = raw_key };
    const key_type = try reader.readString();
    if (!isSupportedKeyType(key_type)) return error.UnsupportedKeyType;

    if (std.mem.eql(u8, key_type, "ssh-ed25519")) {
        const public_key = try reader.readString();
        if (public_key.len != 32 or !reader.atEnd()) return error.MalformedKeyBlob;
    } else if (std.mem.eql(u8, key_type, "ecdsa-sha2-nistp256")) {
        const curve = try reader.readString();
        const public_key = try reader.readString();
        if (!std.mem.eql(u8, curve, "nistp256") or
            public_key.len != 65 or
            public_key[0] != 4 or
            !reader.atEnd())
        {
            return error.MalformedKeyBlob;
        }
    } else {
        const exponent = try reader.readString();
        const modulus = try reader.readString();
        try validatePositiveMpint(exponent);
        try validatePositiveMpint(modulus);
        if (!reader.atEnd()) return error.MalformedKeyBlob;
    }

    return key_type;
}

fn validateOrdinaryHost(host: []const u8) !void {
    if (host.len == 0) return error.MalformedHostPattern;
    for (host) |c| {
        if (!(std.ascii.isAlphanumeric(c) or
            c == '.' or c == '-' or c == '_' or c == ':' or c == '%'))
        {
            return error.MalformedHostPattern;
        }
    }
}

fn validateHostPattern(pattern: []const u8) !void {
    if (pattern.len == 0) return error.MalformedHostPattern;
    if (pattern[0] == '|') return error.UnsupportedHashedHost;
    if (pattern[0] == '!') return error.UnsupportedNegatedHost;
    if (std.mem.indexOfAny(u8, pattern, "*?") != null) {
        return error.UnsupportedWildcardHost;
    }

    if (pattern[0] == '[') {
        const separator = std.mem.lastIndexOf(u8, pattern, "]:") orelse
            return error.MalformedHostPattern;
        if (separator <= 1 or separator + 2 >= pattern.len) {
            return error.MalformedHostPattern;
        }
        if (std.mem.indexOfScalar(u8, pattern[1..separator], ']') != null) {
            return error.MalformedHostPattern;
        }
        try validateOrdinaryHost(pattern[1..separator]);
        const port_text = pattern[separator + 2 ..];
        for (port_text) |c| {
            if (!std.ascii.isDigit(c)) return error.MalformedHostPattern;
        }
        const port = std.fmt.parseInt(u16, port_text, 10) catch
            return error.MalformedHostPattern;
        if (port == 0) return error.MalformedHostPattern;
        return;
    }

    if (std.mem.indexOfAny(u8, pattern, "[]") != null) {
        return error.MalformedHostPattern;
    }
    try validateOrdinaryHost(pattern);
}

fn hostFieldMatches(host_field: []const u8, endpoint: []const u8) !bool {
    if (host_field.len == 0 or host_field.len > max_host_field_length) {
        return error.HostFieldTooLong;
    }

    var matched = false;
    var patterns = std.mem.splitScalar(u8, host_field, ',');
    while (patterns.next()) |pattern| {
        try validateHostPattern(pattern);
        if (std.ascii.eqlIgnoreCase(pattern, endpoint)) matched = true;
    }
    return matched;
}

pub fn formatEndpoint(buffer: []u8, host: []const u8, port: u16) ![]const u8 {
    try validateOrdinaryHost(host);
    if (port == 0) return error.InvalidPort;
    const endpoint = if (port == 22)
        try std.fmt.bufPrint(buffer, "{s}", .{host})
    else
        try std.fmt.bufPrint(buffer, "[{s}]:{d}", .{ host, port });
    if (endpoint.len > max_endpoint_length) return error.EndpointTooLong;
    return endpoint;
}

pub fn checkContents(
    contents: []const u8,
    endpoint: []const u8,
    raw_key: []const u8,
) !Match {
    if (contents.len > max_file_size) return error.KnownHostsFileTooLarge;
    if (endpoint.len == 0 or endpoint.len > max_endpoint_length) {
        return error.EndpointTooLong;
    }
    try validateHostPattern(endpoint);
    const presented_key_type = try keyType(raw_key);

    var matched_key = false;
    var matched_endpoint = false;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |untrimmed_line| {
        if (untrimmed_line.len > max_line_length) return error.KnownHostsLineTooLong;
        const line = std.mem.trim(u8, untrimmed_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        var fields = std.mem.tokenizeAny(u8, line, " \t");
        const host_field = fields.next() orelse return error.MalformedKnownHostsLine;
        if (host_field[0] == '@') return error.UnsupportedMarker;
        const declared_key_type = fields.next() orelse return error.MalformedKnownHostsLine;
        const encoded_key = fields.next() orelse return error.MalformedKnownHostsLine;

        if (!isSupportedKeyType(declared_key_type)) return error.UnsupportedKeyType;
        const endpoint_on_line = try hostFieldMatches(host_field, endpoint);

        if (encoded_key.len > std.base64.standard.Encoder.calcSize(max_key_blob_length)) {
            return error.EncodedKeyTooLong;
        }
        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encoded_key) catch
            return error.MalformedBase64;
        if (decoded_len == 0 or decoded_len > max_key_blob_length) {
            return error.EncodedKeyTooLong;
        }
        var decoded_buffer: [max_key_blob_length]u8 = undefined;
        const decoded_key = decoded_buffer[0..decoded_len];
        std.base64.standard.Decoder.decode(decoded_key, encoded_key) catch
            return error.MalformedBase64;
        const decoded_key_type = try keyType(decoded_key);
        if (!std.mem.eql(u8, declared_key_type, decoded_key_type)) {
            return error.KeyTypeMismatch;
        }

        if (endpoint_on_line) {
            matched_endpoint = true;
            if (std.mem.eql(u8, raw_key, decoded_key) and
                std.mem.eql(u8, presented_key_type, decoded_key_type))
            {
                matched_key = true;
            }
        }
    }

    if (matched_key) return .match;
    if (matched_endpoint) return .changed;
    return .unknown;
}

fn readLockedFile(
    io: std.Io,
    allocator: std.mem.Allocator,
    file: std.Io.File,
) ![]u8 {
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.NotRegularFile;
    if (stat.size > max_file_size) return error.KnownHostsFileTooLarge;
    const size: usize = @intCast(stat.size);
    const contents = try allocator.alloc(u8, size);
    errdefer allocator.free(contents);
    const read_len = try file.readPositionalAll(io, contents, 0);
    if (read_len != contents.len) return error.KnownHostsChangedDuringRead;
    return contents;
}

fn checkFileAt(
    io: std.Io,
    allocator: std.mem.Allocator,
    dir: std.Io.Dir,
    path: []const u8,
    endpoint: []const u8,
    raw_key: []const u8,
) !Match {
    var file = dir.openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .lock = .shared,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return .unknown,
        else => |other| return other,
    };
    defer file.close(io);

    const contents = try readLockedFile(io, allocator, file);
    defer allocator.free(contents);
    return checkContents(contents, endpoint, raw_key);
}

pub fn checkFile(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    endpoint: []const u8,
    raw_key: []const u8,
) !Match {
    return checkFileAt(io, allocator, .cwd(), path, endpoint, raw_key);
}

fn ensureSshDirectoryAt(io: std.Io, parent: std.Io.Dir, path: []const u8) !void {
    parent.createDir(io, path, .fromMode(0o700)) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => |other| return other,
    };
    var ssh_dir = try parent.openDir(io, path, .{ .follow_symlinks = false });
    defer ssh_dir.close(io);
    try parent.setFilePermissions(
        io,
        path,
        .fromMode(0o700),
        .{ .follow_symlinks = false },
    );
}

pub fn ensureDefaultSshDirectory(io: std.Io, path: []const u8) !void {
    return ensureSshDirectoryAt(io, .cwd(), path);
}

fn openLockedForUpdate(io: std.Io, dir: std.Io.Dir, path: []const u8) !std.Io.File {
    var attempts: usize = 0;
    while (attempts < 4) : (attempts += 1) {
        return dir.createFile(io, path, .{
            .read = true,
            .truncate = false,
            .exclusive = true,
            .lock = .exclusive,
            .permissions = .fromMode(0o600),
        }) catch |create_err| switch (create_err) {
            error.PathAlreadyExists => dir.openFile(io, path, .{
                .mode = .read_write,
                .allow_directory = false,
                .lock = .exclusive,
                .follow_symlinks = false,
            }) catch |open_err| switch (open_err) {
                error.FileNotFound => continue,
                else => |other| return other,
            },
            else => |other| return other,
        };
    }
    return error.KnownHostsChangedDuringOpen;
}

fn encodeEntry(buffer: []u8, endpoint: []const u8, raw_key: []const u8) ![]const u8 {
    const key_type = try keyType(raw_key);
    const encoded_len = std.base64.standard.Encoder.calcSize(raw_key.len);
    if (encoded_len > std.base64.standard.Encoder.calcSize(max_key_blob_length)) {
        return error.EncodedKeyTooLong;
    }
    if (endpoint.len + 1 + key_type.len + 1 + encoded_len + 1 > buffer.len) {
        return error.KnownHostsLineTooLong;
    }

    var offset: usize = 0;
    @memcpy(buffer[offset..][0..endpoint.len], endpoint);
    offset += endpoint.len;
    buffer[offset] = ' ';
    offset += 1;
    @memcpy(buffer[offset..][0..key_type.len], key_type);
    offset += key_type.len;
    buffer[offset] = ' ';
    offset += 1;
    _ = std.base64.standard.Encoder.encode(buffer[offset..][0..encoded_len], raw_key);
    offset += encoded_len;
    buffer[offset] = '\n';
    offset += 1;
    return buffer[0..offset];
}

fn acceptNewAt(
    io: std.Io,
    allocator: std.mem.Allocator,
    dir: std.Io.Dir,
    path: []const u8,
    endpoint: []const u8,
    raw_key: []const u8,
) !AcceptResult {
    // The exclusive lock covers both the recheck and append so concurrent
    // mssh processes cannot add duplicates or replace a key that just changed.
    var file = try openLockedForUpdate(io, dir, path);
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o600));

    const contents = try readLockedFile(io, allocator, file);
    defer allocator.free(contents);
    switch (try checkContents(contents, endpoint, raw_key)) {
        .match => return .already_trusted,
        .changed => return error.HostKeyChanged,
        .unknown => {},
    }

    var append_buffer: [max_line_length + 1]u8 = undefined;
    var offset: usize = 0;
    if (contents.len != 0 and contents[contents.len - 1] != '\n') {
        append_buffer[0] = '\n';
        offset = 1;
    }
    const entry = try encodeEntry(append_buffer[offset..], endpoint, raw_key);
    const append_data = append_buffer[0 .. offset + entry.len];
    if (contents.len + append_data.len > max_file_size) {
        return error.KnownHostsFileTooLarge;
    }
    try file.writePositionalAll(io, append_data, contents.len);
    try file.sync(io);
    return .added;
}

pub fn acceptNew(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    endpoint: []const u8,
    raw_key: []const u8,
) !AcceptResult {
    return acceptNewAt(io, allocator, .cwd(), path, endpoint, raw_key);
}

const test_ed25519_key =
    "\x00\x00\x00\x0bssh-ed25519" ++
    "\x00\x00\x00\x20" ++
    "0123456789abcdef0123456789abcdef";

const test_ecdsa_key =
    "\x00\x00\x00\x13ecdsa-sha2-nistp256" ++
    "\x00\x00\x00\x08nistp256" ++
    "\x00\x00\x00\x41\x04" ++
    "0123456789abcdef0123456789abcdef" ++
    "fedcba9876543210fedcba9876543210";

const test_rsa_key =
    "\x00\x00\x00\x07ssh-rsa" ++
    "\x00\x00\x00\x03\x01\x00\x01" ++
    "\x00\x00\x00\x02\x00\x80";

fn testLine(
    buffer: []u8,
    hosts: []const u8,
    declared_key_type: []const u8,
    raw_key: []const u8,
) ![]const u8 {
    var encoded_buffer: [std.base64.standard.Encoder.calcSize(max_key_blob_length)]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&encoded_buffer, raw_key);
    return std.fmt.bufPrint(buffer, "{s} {s} {s}", .{ hosts, declared_key_type, encoded });
}

test "matches supported key types and host field forms" {
    const cases = [_]struct {
        key_type: []const u8,
        raw_key: []const u8,
    }{
        .{ .key_type = "ssh-ed25519", .raw_key = test_ed25519_key },
        .{ .key_type = "ecdsa-sha2-nistp256", .raw_key = test_ecdsa_key },
        .{ .key_type = "ssh-rsa", .raw_key = test_rsa_key },
    };

    for (cases) |case| {
        var line_buffer: [max_line_length]u8 = undefined;
        const line = try testLine(
            &line_buffer,
            "example.com,192.0.2.1,[example.com]:2222",
            case.key_type,
            case.raw_key,
        );
        try std.testing.expectEqual(Match.match, try checkContents(line, "example.com", case.raw_key));
        try std.testing.expectEqual(Match.match, try checkContents(line, "192.0.2.1", case.raw_key));
        try std.testing.expectEqual(Match.match, try checkContents(line, "[example.com]:2222", case.raw_key));
        try std.testing.expectEqual(Match.unknown, try checkContents(line, "other.example", case.raw_key));
    }
}

test "ignores blank lines and comments and matches case-insensitively" {
    var line_buffer: [max_line_length]u8 = undefined;
    const entry = try testLine(&line_buffer, "Example.COM", "ssh-ed25519", test_ed25519_key);
    var contents_buffer: [max_line_length]u8 = undefined;
    const contents = try std.fmt.bufPrint(
        &contents_buffer,
        " \r\n\t# generated by a test\r\n{s} key comment\r\n",
        .{entry},
    );
    try std.testing.expectEqual(Match.match, try checkContents(contents, "example.com", test_ed25519_key));
}

test "distinguishes changed and unknown host keys" {
    var line_buffer: [max_line_length]u8 = undefined;
    const line = try testLine(&line_buffer, "example.com", "ssh-ed25519", test_ed25519_key);
    var changed_key = test_ed25519_key.*;
    changed_key[changed_key.len - 1] ^= 1;

    try std.testing.expectEqual(Match.changed, try checkContents(line, "example.com", &changed_key));
    try std.testing.expectEqual(Match.unknown, try checkContents(line, "other.example", &changed_key));
}

test "rejects markers and unsupported host patterns" {
    var encoded_buffer: [std.base64.standard.Encoder.calcSize(max_key_blob_length)]u8 = undefined;
    const key = std.base64.standard.Encoder.encode(&encoded_buffer, test_ed25519_key);
    var contents_buffer: [max_line_length]u8 = undefined;

    const marker = try std.fmt.bufPrint(&contents_buffer, "@cert-authority example.com ssh-ed25519 {s}", .{key});
    try std.testing.expectError(error.UnsupportedMarker, checkContents(marker, "example.com", test_ed25519_key));

    const wildcard = try std.fmt.bufPrint(&contents_buffer, "*.example.com ssh-ed25519 {s}", .{key});
    try std.testing.expectError(error.UnsupportedWildcardHost, checkContents(wildcard, "example.com", test_ed25519_key));

    const negated = try std.fmt.bufPrint(&contents_buffer, "!bad.example ssh-ed25519 {s}", .{key});
    try std.testing.expectError(error.UnsupportedNegatedHost, checkContents(negated, "example.com", test_ed25519_key));

    const hashed = try std.fmt.bufPrint(&contents_buffer, "|1|salt|hash ssh-ed25519 {s}", .{key});
    try std.testing.expectError(error.UnsupportedHashedHost, checkContents(hashed, "example.com", test_ed25519_key));

    const empty_pattern = try std.fmt.bufPrint(&contents_buffer, "example.com, ssh-ed25519 {s}", .{key});
    try std.testing.expectError(error.MalformedHostPattern, checkContents(empty_pattern, "example.com", test_ed25519_key));
}

test "rejects malformed lines, base64, blobs, and key type mismatches" {
    try std.testing.expectError(
        error.MalformedKnownHostsLine,
        checkContents("example.com ssh-ed25519", "example.com", test_ed25519_key),
    );
    try std.testing.expectError(
        error.MalformedBase64,
        checkContents("example.com ssh-ed25519 !!!=", "example.com", test_ed25519_key),
    );
    try std.testing.expectError(
        error.UnsupportedKeyType,
        checkContents("example.com ssh-dss AAAA", "example.com", test_ed25519_key),
    );

    var line_buffer: [max_line_length]u8 = undefined;
    const wrong_type = try testLine(&line_buffer, "example.com", "ssh-rsa", test_ed25519_key);
    try std.testing.expectError(
        error.KeyTypeMismatch,
        checkContents(wrong_type, "example.com", test_ed25519_key),
    );

    var encoded_buffer: [32]u8 = undefined;
    const malformed = std.base64.standard.Encoder.encode(&encoded_buffer, "not an ssh key");
    const malformed_line = try std.fmt.bufPrint(
        &line_buffer,
        "example.com ssh-ed25519 {s}",
        .{malformed},
    );
    try std.testing.expectError(
        error.MalformedKeyBlob,
        checkContents(malformed_line, "example.com", test_ed25519_key),
    );
}

test "enforces file and line bounds" {
    const allocator = std.testing.allocator;
    const oversized_file = try allocator.alloc(u8, max_file_size + 1);
    defer allocator.free(oversized_file);
    @memset(oversized_file, '\n');
    try std.testing.expectError(
        error.KnownHostsFileTooLarge,
        checkContents(oversized_file, "example.com", test_ed25519_key),
    );

    const oversized_line = try allocator.alloc(u8, max_line_length + 1);
    defer allocator.free(oversized_line);
    @memset(oversized_line, 'x');
    try std.testing.expectError(
        error.KnownHostsLineTooLong,
        checkContents(oversized_line, "example.com", test_ed25519_key),
    );
}

test "formats default and nondefault endpoints" {
    var buffer: [max_endpoint_length]u8 = undefined;
    try std.testing.expectEqualStrings("example.com", try formatEndpoint(&buffer, "example.com", 22));
    try std.testing.expectEqualStrings("2001:db8::1", try formatEndpoint(&buffer, "2001:db8::1", 22));
    try std.testing.expectEqualStrings("[example.com]:2222", try formatEndpoint(&buffer, "example.com", 2222));
    try std.testing.expectEqualStrings("[2001:db8::1]:2222", try formatEndpoint(&buffer, "2001:db8::1", 2222));
}

test "accept-new appends once, locks down permissions, and refuses changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    try std.testing.expectEqual(
        AcceptResult.added,
        try acceptNewAt(io, allocator, tmp.dir, "known_hosts", "example.com", test_ed25519_key),
    );
    try std.testing.expectEqual(
        AcceptResult.already_trusted,
        try acceptNewAt(io, allocator, tmp.dir, "known_hosts", "example.com", test_ed25519_key),
    );

    var changed_key = test_ed25519_key.*;
    changed_key[changed_key.len - 1] ^= 1;
    try std.testing.expectError(
        error.HostKeyChanged,
        acceptNewAt(io, allocator, tmp.dir, "known_hosts", "example.com", &changed_key),
    );

    var file = try tmp.dir.openFile(io, "known_hosts", .{});
    defer file.close(io);
    const stat = try file.stat(io);
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o777);
    const contents = try tmp.dir.readFileAlloc(io, "known_hosts", allocator, .limited(max_file_size));
    defer allocator.free(contents);
    try std.testing.expectEqual(Match.match, try checkContents(contents, "example.com", test_ed25519_key));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, contents, "\n"));
}

test "default SSH directory is created with private permissions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    try ensureSshDirectoryAt(io, tmp.dir, ".ssh");
    var ssh_dir = try tmp.dir.openDir(io, ".ssh", .{ .follow_symlinks = false });
    defer ssh_dir.close(io);
    const stat = try ssh_dir.stat(io);
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o700), stat.permissions.toMode() & 0o777);
}
