//! `known_hosts`, backed by a file.
//!
//! The parsing, matching, and entry encoding are `sshz.known_hosts`, which
//! does no I/O. This adds the part that is specific to storing the database
//! in `~/.ssh/known_hosts`: locking, bounded reads, and creating the file and
//! its directory without a window in which either is world-readable.
//!
//! Re-exports the pure names so a caller has one import rather than two.
//!
//! ## Windows
//!
//! This compiles on Windows but `acceptNew` does not work there, for a reason
//! outside this repository. `Io.Dir.createFile` with `.lock` returns a handle
//! Windows has opened asynchronously, and `Io.Threaded`'s Windows file reads
//! assume a synchronous one: the positional path reaches
//! `.PENDING => unreachable` and panics, and the streaming path passes a null
//! `ByteOffset` and gets `INVALID_PARAMETER`. Reading is done streaming here
//! because failing is better than panicking, not because it succeeds.
//!
//! `checkFile` is unaffected -- it takes a shared lock on an existing file --
//! and every pure operation works everywhere. An embedder that wants
//! `known_hosts` on Windows should use `sshz.known_hosts` against bytes it
//! read itself.

const std = @import("std");
const builtin = @import("builtin");
const sshz = @import("sshz");

const known_hosts = sshz.known_hosts;

pub const Match = known_hosts.Match;
pub const max_file_size = known_hosts.max_file_size;
pub const max_line_length = known_hosts.max_line_length;
pub const max_endpoint_length = known_hosts.max_endpoint_length;
pub const max_key_blob_length = known_hosts.max_key_blob_length;
pub const keyType = known_hosts.keyType;
pub const formatEndpoint = known_hosts.formatEndpoint;
pub const checkContents = known_hosts.checkContents;
pub const encodeEntry = known_hosts.encodeEntry;

pub const AcceptResult = enum {
    already_trusted,
    added,
};

/// `0o600`, where that means anything.
///
/// Windows has no POSIX mode bits, and `Io.File.Permissions` there is a set
/// of file attributes with no way to express an owner-only file. A file
/// created under the user profile already inherits an ACL that grants only
/// the owner and administrators, so the platform default is what "private"
/// means; asking for a mode is what fails to compile, not what fails to
/// protect.
const private_file: std.Io.File.Permissions = if (@hasDecl(std.Io.File.Permissions, "fromMode"))
    .fromMode(0o600)
else
    .default_file;

/// `0o700`, on the same terms as `private_file`.
const private_dir: std.Io.File.Permissions = if (@hasDecl(std.Io.File.Permissions, "fromMode"))
    .fromMode(0o700)
else
    .default_dir;

/// Whether the platform has mode bits for a test to assert on.
const has_modes = @hasDecl(std.Io.File.Permissions, "fromMode");

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

    // Streaming rather than positional: `Io.Threaded`'s Windows positional
    // read reaches `.PENDING => unreachable` on a handle opened with a lock,
    // so a positional read of this file panics there rather than failing.
    // The position is left at end of file, which is where the append wants
    // it anyway.
    var buffer: [4096]u8 = undefined;
    var file_reader = file.readerStreaming(io, &buffer);
    file_reader.interface.readSliceAll(contents) catch |err| switch (err) {
        error.EndOfStream => return error.KnownHostsChangedDuringRead,
        else => |other| return other,
    };
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
    parent.createDir(io, path, private_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => |other| return other,
    };
    var ssh_dir = try parent.openDir(io, path, .{ .follow_symlinks = false });
    defer ssh_dir.close(io);
    // Only where mode bits exist. `createDir` above already applied them, and
    // this second call closes the window in which an existing directory was
    // left with looser ones -- a POSIX concern with no Windows counterpart,
    // where `Io.Threaded.dirSetFilePermissions` is unimplemented and a
    // directory under the user profile inherits a private ACL regardless.
    if (has_modes) {
        try parent.setFilePermissions(
            io,
            path,
            private_dir,
            .{ .follow_symlinks = false },
        );
    }
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
            .permissions = private_file,
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
    try file.setPermissions(io, private_file);

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

/// A well-formed ed25519 host key blob, for the file-handling tests. The
/// library's own tests cover every key type; these only need one that parses.
const test_ed25519_key =
    "\x00\x00\x00\x0bssh-ed25519" ++
    "\x00\x00\x00\x20" ++
    "0123456789abcdef0123456789abcdef";

test "accept-new appends once, locks down permissions, and refuses changes" {
    // See the Windows note at the top of this file: the locked handle cannot
    // be read through `Io.Threaded` there.
    if (builtin.os.tag == .windows) return error.SkipZigTest;
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
    // Only where mode bits exist. On Windows the file inherits a private ACL
    // and there is no mode to compare against.
    if (has_modes) {
        try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o777);
    }
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
    if (has_modes) {
        try std.testing.expectEqual(@as(std.posix.mode_t, 0o700), stat.permissions.toMode() & 0o777);
    }
}
