const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("sshz_build_options");
const BufferReader = @import("buffer.zig").BufferReader;
const BufferWriter = @import("buffer.zig").BufferWriter;

/// What a call site asks for, and -- with `Off` -- what the build can allow.
///
/// `Off` sorts below `Info` so the existing `trace_level >= level` test
/// suppresses everything: no call site passes `Off`, so nothing can clear it.
const TraceLevel = enum {
    Off,
    Info,
    Debug,
};

/// Set by `-Dtrace`, and `Off` unless asked for.
///
/// A library does not get to decide that its host writes to stderr. `.Info`
/// fires during entirely successful sessions -- stock OpenSSH sends a global
/// request sshz does not handle, every time -- and an application that
/// owns the terminal has its screen corrupted by it. `sshz` and `sshzd` ask
/// for `info` in their own `build.zig`, so their output is unchanged.
const trace_level: TraceLevel = blk: {
    const name = build_options.trace_level;
    if (std.mem.eql(u8, name, "off")) break :blk .Off;
    if (std.mem.eql(u8, name, "info")) break :blk .Info;
    if (std.mem.eql(u8, name, "debug")) break :blk .Debug;
    @compileError("unknown trace level: " ++ name);
};

pub const unsafe_secret_tracing = build_options.unsafe_secret_tracing;

/// The version this build reports.
///
/// Set by `-Dversion`, which a release build feeds from the tag, so a
/// tagged artifact stamps its own tag rather than whatever was last
/// committed. Untagged builds fall back to the version declared in
/// `build.zig.zon`.
pub const version = build_options.version;

/// Whether any call site can reach `std.debug.print`.
///
/// Exposed so a build can assert that the default one stays silent.
pub const traces_are_printed = trace_level != .Off;

pub fn zeroizeBytes(buf: []u8) void {
    std.crypto.secureZero(u8, buf);
}

/// Sanitizes untrusted peer text before writing to a terminal or log.
///
/// Printable ASCII (`0x20..0x7e`) is preserved. When `allow_newlines` is true,
/// `\n` and `\t` are preserved and `\r\n` is normalized to `\n`, while bare `\r`
/// is escaped as `\r` to prevent line-overwrite attacks. All other C0/C1 control
/// bytes (`0x00..0x1f`, `0x7f..0x9f`, including `\x1b` ESC, `\x9b` CSI, `\x07` BEL)
/// and non-ASCII bytes (`0x80..0xff`) are escaped as `\r`, `\n`, `\t`, or `\xHH`.
/// Never writes a partial escape sequence if `out` fills up.
pub fn sanitizeControlChars(input: []const u8, out: []u8, allow_newlines: bool) []const u8 {
    const hex = "0123456789abcdef";
    var pos: usize = 0;
    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        const b = input[i];
        if (allow_newlines and b == '\r' and i + 1 < input.len and input[i + 1] == '\n') {
            continue;
        }
        if (allow_newlines and (b == '\n' or b == '\t')) {
            if (pos + 1 > out.len) break;
            out[pos] = b;
            pos += 1;
            continue;
        }
        if (b >= 0x20 and b <= 0x7e) {
            if (pos + 1 > out.len) break;
            out[pos] = b;
            pos += 1;
            continue;
        }
        const esc: ?[]const u8 = switch (b) {
            '\r' => "\\r",
            '\n' => "\\n",
            '\t' => "\\t",
            else => null,
        };
        if (esc) |seq| {
            if (pos + seq.len > out.len) break;
            @memcpy(out[pos .. pos + seq.len], seq);
            pos += seq.len;
        } else {
            if (pos + 4 > out.len) break;
            out[pos] = '\\';
            out[pos + 1] = 'x';
            out[pos + 2] = hex[b >> 4];
            out[pos + 3] = hex[b & 0x0f];
            pos += 4;
        }
    }
    return out[0..pos];
}

pub fn trace(level: TraceLevel, comptime fmt: []const u8, args: anytype) void {
    if (builtin.os.tag != .freestanding) {
        if (@backingInt(trace_level) >= @backingInt(level)) {
            var raw_buf: [1024]u8 = undefined;
            var safe_buf: [1024]u8 = undefined;
            const formatted = std.fmt.bufPrint(&raw_buf, fmt, args) catch raw_buf[0..];
            const trimmed = std.mem.trimEnd(u8, formatted, "\r\n");
            const sanitized = sanitizeControlChars(trimmed, &safe_buf, false);
            std.debug.print("{s}\n", .{sanitized});
        }
    }
}

pub inline fn unsafeTracedump(level: TraceLevel, comptime fmt: []const u8, args: anytype, data: []const u8) void {
    if (comptime unsafe_secret_tracing) {
        if (builtin.os.tag != .freestanding) {
            if (@backingInt(trace_level) >= @backingInt(level)) {
                std.debug.print(fmt ++ "\n", args);
                dumpStderr(data);
            }
        }
    }
}

// remove newline from end if present
pub fn chomp(s: []const u8) []const u8 {
    if (s.len < 2) {
        return s;
    }
    var i: usize = s.len;
    while (i >= 2) {
        if ((s[i - 2] == '\r' and s[i - 1] == '\n')) {
            i -= 2;
        } else {
            break;
        }
    }
    return s[0..i];
}

// std.mem.asBytes(), but returning only the bytes needed for a packed struct
pub fn asPackedBytes(T: type, ptr: anytype) []u8 {
    return std.mem.asBytes(ptr)[0 .. @bitSizeOf(T) / 8];
}

fn dumpStderr(data: []const u8) void {
    const bytes_per_line = 16;
    std.debug.assert(bytes_per_line % 2 == 0);
    var off: usize = 0;

    while (off < data.len) : (off += bytes_per_line) {
        std.debug.print("{x:0>8}: ", .{off});
        const bytes_to_show = if (off + bytes_per_line > data.len) data.len - off else bytes_per_line;
        for (0..bytes_per_line) |n| {
            if (n < bytes_to_show) {
                std.debug.print("{x:0>2}", .{data[off + n]});
            } else {
                std.debug.print("  ", .{});
            }
            if (n % 2 == 1) {
                std.debug.print(" ", .{});
            }
        }
        std.debug.print(" ", .{});
        for (0..bytes_per_line) |n| {
            if (n < bytes_to_show) {
                std.debug.print("{c}", .{if (std.ascii.isPrint(data[off + n])) data[off + n] else '.'});
            }
        }
        std.debug.print("\n", .{});
    }
}

// xxd style hexdump
pub fn dump(writer: anytype, data: []const u8) !void {
    const bytes_per_line = 16;
    std.debug.assert(bytes_per_line % 2 == 0);
    var off: usize = 0;

    while (off < data.len) : (off += bytes_per_line) {
        const bytes_to_show = if (off + bytes_per_line > data.len) data.len - off else bytes_per_line;
        try writer.print("{x:0>8}: ", .{off});
        for (0..bytes_per_line) |n| {
            if (n < bytes_to_show) {
                try writer.print("{x:0>2}", .{data[off + n]});
            } else {
                try writer.print("  ", .{});
            }
            if (n % 2 == 1) {
                try writer.print(" ", .{});
            }
        }
        try writer.print(" ", .{});
        for (0..bytes_per_line) |n| {
            if (n < bytes_to_show) {
                try writer.print("{c}", .{if (std.ascii.isPrint(data[off + n])) data[off + n] else '.'});
            }
        }
        try writer.print("\n", .{});
    }
}

// Convencience for splitting comma separated values
pub const NameListTokenizer = struct {
    const Self = @This();
    pub fn init(namelist: []const u8) std.mem.SplitIterator(u8, .sequence) {
        return std.mem.splitSequence(u8, namelist, ",");
    }
};

// server host key comes as two U32LenStrings, name and binary blob
// convenience function to extract these parts in either order
pub const NamedBlob = struct {
    const Self = @This();
    nameblob: []const u8,

    pub fn init(nameblob: []const u8) Self {
        return Self{
            .nameblob = nameblob,
        };
    }

    pub fn getName(self: *Self) ![]const u8 {
        var buffer = BufferReader.init(self.nameblob);
        return try buffer.readU32LenString();
    }

    pub fn getBlob(self: *Self) ![]const u8 {
        var buffer = BufferReader.init(self.nameblob);
        try buffer.skipU32LenString();
        return try buffer.readU32LenString();
    }
};

test "chomp" {
    try std.testing.expect(std.mem.eql(u8, chomp(""), ""));
    try std.testing.expect(std.mem.eql(u8, chomp("\r\n"), ""));
    try std.testing.expect(std.mem.eql(u8, chomp("\r\n\r\n"), ""));
    try std.testing.expect(std.mem.eql(u8, chomp("a"), "a"));
    try std.testing.expect(std.mem.eql(u8, chomp("a\r"), "a\r"));
    try std.testing.expect(std.mem.eql(u8, chomp("a\r\n"), "a"));
    try std.testing.expect(std.mem.eql(u8, chomp("abc"), "abc"));
    try std.testing.expect(std.mem.eql(u8, chomp("abc\n"), "abc\n"));
    try std.testing.expect(std.mem.eql(u8, chomp("abc\r\n"), "abc"));
    try std.testing.expect(std.mem.eql(u8, chomp("\r\nabc\r\n"), "\r\nabc"));
}

test "namedblob" {
    var backing: [128]u8 = undefined;
    var buffer = BufferWriter.init(&backing, 0);
    // write str
    try buffer.writeU32LenString("MOOF");
    try buffer.writeU32LenString("blah");

    var nb = NamedBlob.init(buffer.active());
    try std.testing.expect(std.mem.eql(u8, try nb.getName(), "MOOF"));
    try std.testing.expect(std.mem.eql(u8, try nb.getBlob(), "blah"));
}

test "zeroizeBytes clears secret buffer" {
    var secret = [_]u8{ 's', 'e', 'c', 'r', 'e', 't', 0x42, 0xff };
    zeroizeBytes(&secret);
    for (secret) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "sanitizeControlChars neutralizes ANSI/OSC escapes and C0/C1 control characters" {
    var out: [256]u8 = undefined;

    // Single-line mode: escapes ESC, CSI (0x9b), BEL, CR, LF, TAB, NUL, DEL
    const single = sanitizeControlChars(
        "prompt\x1b]52;c;evil\x07\rFake:\n\t\x00\x7f\x9b2J",
        &out,
        false,
    );
    try std.testing.expectEqualStrings(
        "prompt\\x1b]52;c;evil\\x07\\rFake:\\n\\t\\x00\\x7f\\x9b2J",
        single,
    );

    // Multi-line mode: preserves LF and TAB, normalizes CRLF -> LF, but escapes bare CR and ESC/BEL/CSI
    const multi = sanitizeControlChars(
        "Banner line 1\r\n\tLine 2\rOverwrite\x1b[31mRed\x07\x9b0m",
        &out,
        true,
    );
    try std.testing.expectEqualStrings(
        "Banner line 1\n\tLine 2\\rOverwrite\\x1b[31mRed\\x07\\x9b0m",
        multi,
    );

    // Bounded output buffer never emits a partial escape sequence
    var tiny: [5]u8 = undefined;
    const bounded = sanitizeControlChars("ab\x1b", &tiny, false);
    try std.testing.expectEqualStrings("ab", bounded);
}
