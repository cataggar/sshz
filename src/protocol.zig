const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const Misshod = @import("misshod.zig").Misshod;
const MisshodError = @import("misshod.zig").MisshodError;
const IoError = @import("misshod.zig").IoError;
const BufferWriter = @import("buffer.zig").BufferWriter;
const BufferError = @import("buffer.zig").BufferError;
const BufferReader = @import("buffer.zig").BufferReader;
const Hasher = @import("hasher.zig").Hasher;
const AesCtr = @import("aesctr.zig").AesCtr;
const decodePrivKey = @import("privkey.zig").decodePrivKey;
const PrivKeyError = @import("privkey.zig").PrivKeyError;
const zlib = @cImport({
    @cInclude("zlib.h");
});

pub const CommDir = enum {
    ClientToServer,
    ServerToClient,
};

// https://datatracker.ietf.org/doc/html/rfc4250#section-4.1.2
pub const MsgId = enum(u8) {
    SSH_MSG_DISCONNECT = 1,
    SSH_MSG_IGNORE = 2,
    SSH_MSG_UNIMPLEMENTED = 3,
    SSH_MSG_DEBUG = 4,
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT = 6,
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,
    SSH_MSG_KEX_ECDH_INIT = 30,
    SSH_MSG_KEX_ECDH_REPLY = 31,
    SSH_MSG_USERAUTH_REQUEST = 50,
    SSH_MSG_USERAUTH_FAILURE = 51,
    SSH_MSG_USERAUTH_SUCCESS = 52,
    SSH_MSG_USERAUTH_BANNER = 53,
    SSH_MSG_USERAUTH_PK_OK = 60, // also SSH_MSG_USERAUTH_INFO_REQUEST per RFC 4256
    SSH_MSG_USERAUTH_INFO_RESPONSE = 61,
    SSH_MSG_GLOBAL_REQUEST = 80,
    SSH_MSG_REQUEST_SUCCESS = 81,
    SSH_MSG_REQUEST_FAILURE = 82,
    SSH_MSG_CHANNEL_OPEN = 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
    SSH_MSG_CHANNEL_OPEN_FAILURE = 92,
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
    SSH_MSG_CHANNEL_DATA = 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
    SSH_MSG_CHANNEL_EOF = 96,
    SSH_MSG_CHANNEL_CLOSE = 97,
    SSH_MSG_CHANNEL_REQUEST = 98,
    SSH_MSG_CHANNEL_SUCCESS = 99,
};

// SSH packet header, appears before payload
// https://datatracker.ietf.org/doc/html/rfc4253#section-6
pub const PktHdr = packed struct {
    packet_length: u32,
    padding_length: u8,
};

// Number of bytes used by PktHdr
// https://datatracker.ietf.org/doc/html/rfc4253#section-6
pub const sizeof_PktHdr = @bitSizeOf(PktHdr) / 8;

pub fn readPktHdr(packet: []const u8) PktHdr {
    std.debug.assert(packet.len >= sizeof_PktHdr);
    return .{
        .packet_length = std.mem.readInt(u32, packet[0..4], .big),
        .padding_length = packet[4],
    };
}

fn writePktHdr(packet: []u8, hdr: PktHdr) void {
    std.debug.assert(packet.len >= sizeof_PktHdr);
    std.mem.writeInt(u32, packet[0..4], hdr.packet_length, .big);
    packet[4] = hdr.padding_length;
}

// order in which items must be hashed to produce kex hash, H
// The key exchange hash is built up piecemeal through several states
// Calling check to advance to the next state asserts if it's done in the wrong order
pub const KexHashOrder = enum { // https://datatracker.ietf.org/doc/html/rfc5656#section-4
    Init,
    V_C, // client's identification string (CR and LF excluded)
    V_S, // server's identification string (CR and LF excluded)
    I_C, // payload of the client's SSH_MSG_KEXINIT
    I_S, // payload of the server's SSH_MSG_KEXINIT
    K_S, // server's public host key
    Q_C, // client's ephemeral public key octet string
    Q_S, // server's ephemeral public key octet string
    K, // shared secret

    // calling myorder = myorder.check(next) will assert if done in the wrong order
    pub fn check(self: *const KexHashOrder, next: KexHashOrder) KexHashOrder {
        TRACE(.Debug, "KexHashOrder {any} -> {any}", .{ self, next });
        std.debug.assert(@intFromEnum(self.*) + 1 == @intFromEnum(next));
        return next;
    }
};

pub const MaxSSHPacket = 4096; // Can be smaller https://datatracker.ietf.org/doc/html/rfc4253#section-5.3
pub const MaxPayload = (MaxSSHPacket - (sizeof_PktHdr + 255 + mac_algo.key_length));
// Max channel data: MaxPayload minus channel data framing (msgid:1 + channel:4 + string_len:4)
pub const MaxChannelDataLen = MaxPayload - 9;
pub const MaxIVLen = 20; // number of bytes to generate for IVs
pub const MaxKeyLen = 64; // number of bytes to generate for keys
pub const MaxIdentificationLineLen = 255;
pub const MaxPreIdentificationLines = 50;

// https://datatracker.ietf.org/doc/html/rfc4253#section-4.2
pub const version = "SSH-2.0-SSH_ZS_0.0.1";

pub fn isValidIdentification(identification: []const u8) bool {
    const prefix = if (std.mem.startsWith(u8, identification, "SSH-2.0-"))
        "SSH-2.0-"
    else if (std.mem.startsWith(u8, identification, "SSH-1.99-"))
        "SSH-1.99-"
    else
        return false;

    const remainder = identification[prefix.len..];
    const comments_separator = std.mem.indexOfScalar(u8, remainder, ' ');
    const software_version = if (comments_separator) |index| remainder[0..index] else remainder;
    if (software_version.len == 0) return false;
    for (software_version) |byte| {
        const valid = (byte >= 0x21 and byte <= 0x2c) or (byte >= 0x2e and byte <= 0x7e);
        if (!valid) return false;
    }

    if (comments_separator) |index| {
        const comments = remainder[index + 1 ..];
        for (comments) |byte| {
            if (byte == 0 or byte == '\r' or byte == '\n') return false;
        }
        if (!std.unicode.utf8ValidateSlice(comments)) return false;
    }
    return true;
}

pub const hash_algo = std.crypto.hash.sha2.Sha256;
pub const hash_algo_name = "hmac-sha2-256";

pub const kex_algo = std.crypto.dh.X25519;
pub const kex_algo_name = "curve25519-sha256";

pub const srv_hostkey_algo = std.crypto.sign.Ed25519;
pub const srv_hostkey_algo_name = "ssh-ed25519";

pub const mac_algo = std.crypto.auth.hmac.sha2.HmacSha256;
pub const mac_algo_name = "hmac-sha2-256";

pub const enc_algo = std.crypto.core.aes.Aes256;
pub const enc_algo_name = "aes256-ctr";
pub const AesCtrT = AesCtr(enc_algo);

pub const compression_none = "none";
pub const compression_zlib_openssh = "zlib@openssh.com";
pub const compression_algorithms = compression_zlib_openssh ++ "," ++ compression_none;

pub const channel_type_session = "session";
pub const channel_type_auth_agent_openssh = "auth-agent@openssh.com";
pub const channel_type_auth_agent = "auth-agent";
pub const channel_request_auth_agent = "auth-agent-req@openssh.com";

pub fn isAgentChannelType(channel_type: []const u8) bool {
    return std.mem.eql(u8, channel_type, channel_type_auth_agent_openssh) or
        std.mem.eql(u8, channel_type, channel_type_auth_agent);
}

// Note, the buffers are not used for storage, they're just passed forward to signal to receiver where the data can be found
pub const IoSessionState = union(enum) {
    Init,
    Idle,
    VersionWrite,
    VersionReadLine,
    VersionReadLineChar: []const u8,
    VersionReadLineCompletion: []const u8,
    ReadPktHdr,
    ReadPktBody: []const u8,
    ReadPktCompletion: []const u8,
};

pub const CompressionAlgorithm = enum {
    None,
    ZlibOpenSsh,

    pub fn name(self: CompressionAlgorithm) []const u8 {
        return switch (self) {
            .None => compression_none,
            .ZlibOpenSsh => compression_zlib_openssh,
        };
    }

    pub fn fromName(name_bytes: []const u8) ?CompressionAlgorithm {
        if (std.mem.eql(u8, name_bytes, compression_none)) return .None;
        if (std.mem.eql(u8, name_bytes, compression_zlib_openssh)) return .ZlibOpenSsh;
        return null;
    }
};

pub fn selectCompressionAlgorithm(client_namelist: []const u8, server_namelist: []const u8) ?CompressionAlgorithm {
    var client_iter = util.NameListTokenizer.init(client_namelist);
    while (client_iter.next()) |client_name| {
        const algorithm = CompressionAlgorithm.fromName(client_name) orelse continue;
        var server_iter = util.NameListTokenizer.init(server_namelist);
        while (server_iter.next()) |server_name| {
            if (std.mem.eql(u8, client_name, server_name)) return algorithm;
        }
    }
    return null;
}

pub const CompressionState = struct {
    const Self = @This();

    algorithm: CompressionAlgorithm = .None,
    pending_algorithm: ?CompressionAlgorithm = null,
    active: bool = false,
    deflate_initialized: bool = false,
    inflate_initialized: bool = false,
    deflate_stream: zlib.z_stream = std.mem.zeroes(zlib.z_stream),
    inflate_stream: zlib.z_stream = std.mem.zeroes(zlib.z_stream),

    pub fn queueAlgorithm(self: *Self, algorithm: CompressionAlgorithm) void {
        self.pending_algorithm = algorithm;
    }

    pub fn applyPendingAlgorithm(self: *Self) void {
        if (self.pending_algorithm) |algorithm| {
            self.endStreams();
            self.algorithm = algorithm;
            self.active = false;
            self.pending_algorithm = null;
        }
    }

    pub fn activateDeflate(self: *Self) MisshodError!void {
        switch (self.algorithm) {
            .None => {},
            .ZlibOpenSsh => {
                if (!self.deflate_initialized) {
                    try self.initDeflate();
                }
                self.active = true;
            },
        }
    }

    pub fn activateInflate(self: *Self) MisshodError!void {
        switch (self.algorithm) {
            .None => {},
            .ZlibOpenSsh => {
                if (!self.inflate_initialized) {
                    try self.initInflate();
                }
                self.active = true;
            },
        }
    }

    pub fn compressPayload(self: *Self, input: []const u8, output: []u8) MisshodError![]const u8 {
        if (!self.active or self.algorithm == .None) return input;
        if (input.len > MaxPayload or output.len == 0) return IoError.tooBig;

        switch (self.algorithm) {
            .None => return input,
            .ZlibOpenSsh => {
                if (!self.deflate_initialized) {
                    try self.initDeflate();
                }
                self.deflate_stream.next_in = @ptrCast(@constCast(input.ptr));
                self.deflate_stream.avail_in = @intCast(input.len);
                self.deflate_stream.next_out = @ptrCast(output.ptr);
                self.deflate_stream.avail_out = @intCast(output.len);

                const rc = zlib.deflate(&self.deflate_stream, zlib.Z_SYNC_FLUSH);
                if (rc != zlib.Z_OK) return IoError.UnexpectedResponse;
                if (self.deflate_stream.avail_in != 0 or self.deflate_stream.avail_out == 0) return IoError.tooBig;

                return output[0 .. output.len - self.deflate_stream.avail_out];
            },
        }
    }

    pub fn decompressPayload(self: *Self, input: []const u8, output: []u8) MisshodError![]const u8 {
        if (!self.active or self.algorithm == .None) return input;
        if (output.len == 0) return IoError.tooBig;

        switch (self.algorithm) {
            .None => return input,
            .ZlibOpenSsh => {
                if (!self.inflate_initialized) {
                    try self.initInflate();
                }
                self.inflate_stream.next_in = @ptrCast(@constCast(input.ptr));
                self.inflate_stream.avail_in = @intCast(input.len);
                self.inflate_stream.next_out = @ptrCast(output.ptr);
                self.inflate_stream.avail_out = @intCast(output.len);

                const rc = zlib.inflate(&self.inflate_stream, zlib.Z_SYNC_FLUSH);
                if (rc != zlib.Z_OK) {
                    if (rc == zlib.Z_BUF_ERROR and self.inflate_stream.avail_out == 0) return IoError.tooBig;
                    return IoError.InvalidPacketSize;
                }
                if (self.inflate_stream.avail_in != 0) return IoError.tooBig;

                return output[0 .. output.len - self.inflate_stream.avail_out];
            },
        }
    }

    pub fn deinit(self: *Self) void {
        self.endStreams();
        self.algorithm = .None;
        self.pending_algorithm = null;
        self.active = false;
    }

    fn initDeflate(self: *Self) MisshodError!void {
        self.deflate_stream = std.mem.zeroes(zlib.z_stream);
        const rc = zlib.deflateInit_(&self.deflate_stream, zlib.Z_DEFAULT_COMPRESSION, zlib.ZLIB_VERSION, @sizeOf(zlib.z_stream));
        if (rc != zlib.Z_OK) return IoError.UnexpectedResponse;
        self.deflate_initialized = true;
    }

    fn initInflate(self: *Self) MisshodError!void {
        self.inflate_stream = std.mem.zeroes(zlib.z_stream);
        const rc = zlib.inflateInit_(&self.inflate_stream, zlib.ZLIB_VERSION, @sizeOf(zlib.z_stream));
        if (rc != zlib.Z_OK) return IoError.UnexpectedResponse;
        self.inflate_initialized = true;
    }

    fn endStreams(self: *Self) void {
        if (self.deflate_initialized) {
            _ = zlib.deflateEnd(&self.deflate_stream);
            self.deflate_initialized = false;
        }
        if (self.inflate_initialized) {
            _ = zlib.inflateEnd(&self.inflate_stream);
            self.inflate_initialized = false;
        }
        self.deflate_stream = std.mem.zeroes(zlib.z_stream);
        self.inflate_stream = std.mem.zeroes(zlib.z_stream);
    }
};

pub const KeyDataUni = struct {
    iv: [MaxIVLen]u8 = undefined,
    key: [MaxKeyLen]u8 = undefined,
    mackey: [MaxKeyLen]u8 = undefined,
    seq: u32,
    aesctr: AesCtrT = undefined,
    compression: CompressionState = .{},

    pub fn clear(self: *KeyDataUni) void {
        std.crypto.secureZero(u8, &self.iv);
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.mackey);
        self.compression.deinit();
        self.seq = 0;
    }
};

pub const KeyDataBi = struct {
    const Self = @This();

    c2s: KeyDataUni,
    s2c: KeyDataUni,

    pub fn init() Self {
        return Self{
            .c2s = .{ .seq = 0 },
            .s2c = .{ .seq = 0 },
        };
    }

    pub fn clear(self: *Self) void {
        self.c2s.clear();
        self.s2c.clear();
    }

    // generate session keys from shared secret
    pub fn genKeys(self: *Self, H: [hash_algo.digest_length]u8, shared_secret_k: [kex_algo.shared_length]u8, session_id: [hash_algo.digest_length]u8) !void {

        // https://datatracker.ietf.org/doc/html/rfc4253#section-7.2

        var hasher: Hasher(hash_algo) = undefined;

        // prepare contact(K,H) = K:mpint concat H:raw
        var backing: [4 + kex_algo.shared_length + 1 + hash_algo.digest_length]u8 = undefined; // 4 for len, 1 for possible padding
        var khbuf = BufferWriter.init(&backing, 0);
        try khbuf.writeMpint(&shared_secret_k); // K
        try khbuf.writeBytes(&H); // H
        const data_kh = khbuf.payload;

        // c2s.iv
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('A'); // "A"
        hasher.writeBytes(&session_id); // session_id
        hasher.final(&self.c2s.iv, data_kh);
        TRACEDUMP(.Debug, "c2s.iv", .{}, &self.c2s.iv);

        // s2c.iv
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('B'); // "B"
        hasher.writeBytes(&session_id); // session_id
        hasher.final(&self.s2c.iv, data_kh);
        TRACEDUMP(.Debug, "s2c.iv", .{}, &self.s2c.iv);

        // c2s.key
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('C'); // "C"
        hasher.writeBytes(&session_id); // session_id
        hasher.final(&self.c2s.key, data_kh);
        TRACEDUMP(.Debug, "c2s.key", .{}, &self.c2s.key);

        // s2c.key
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('D'); // "D"
        hasher.writeBytes(&session_id); // session_id
        hasher.final(&self.s2c.key, data_kh);
        TRACEDUMP(.Debug, "s2c.key", .{}, &self.s2c.key);

        // c2s.mackey
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('E'); // "E"
        hasher.writeBytes(&session_id); // session_id
        hasher.final(&self.c2s.mackey, data_kh);
        TRACEDUMP(.Debug, "c2s.mackey", .{}, &self.c2s.mackey);

        // s2c.mackey
        hasher = Hasher(hash_algo).init();
        hasher.writeBytes(data_kh);
        hasher.writeU8('F'); // "F"
        hasher.writeBytes(&session_id); // session_id
        hasher.final(&self.s2c.mackey, data_kh);
        TRACEDUMP(.Debug, "s2c.mackey", .{}, &self.s2c.mackey);

        // setup aesctrs
        self.c2s.aesctr = AesCtrT.init(self.c2s.iv[0..AesCtrT.iv_size].*, self.c2s.key[0..AesCtrT.key_size].*);
        self.s2c.aesctr = AesCtrT.init(self.s2c.iv[0..AesCtrT.iv_size].*, self.s2c.key[0..AesCtrT.key_size].*);
    }
};

pub fn wrapPkt(rand: *std.Random, encrypted: bool, keysuni: *KeyDataUni, buffer: *BufferWriter, iobuf: []u8) MisshodError![]const u8 {
    return wrapPayload(rand, encrypted, keysuni, buffer.active(), iobuf);
}

pub fn wrapPayload(rand: *std.Random, encrypted: bool, keysuni: *KeyDataUni, payload: []const u8, iobuf: []u8) MisshodError![]const u8 {
    // https://datatracker.ietf.org/doc/html/rfc4253#section-6
    if (payload.len > MaxPayload) return IoError.tooBig;

    var compressed_payload_buf: [MaxPayload]u8 = undefined;
    const packet_payload = try keysuni.compression.compressPayload(payload, &compressed_payload_buf);
    if (packet_payload.len > MaxPayload) return IoError.tooBig;

    // pad such that whole packet (payload + hdr) is multiple of block_size
    const buffer_len = packet_payload.len;
    var padding_length: u8 = @intCast(AesCtrT.block_size - (buffer_len + sizeof_PktHdr) % AesCtrT.block_size);
    if (padding_length < 4) {
        padding_length += @intCast(AesCtrT.block_size);
    }
    const packet_len = sizeof_PktHdr + buffer_len + padding_length;
    if (packet_len > MaxSSHPacket or packet_len > iobuf.len) return IoError.tooBig;

    // construct header
    const hdr: PktHdr = .{
        .packet_length = @intCast(buffer_len + padding_length + 1),
        .padding_length = @intCast(padding_length),
    };
    writePktHdr(iobuf[0..sizeof_PktHdr], hdr);
    std.mem.copyForwards(u8, iobuf[sizeof_PktHdr .. sizeof_PktHdr + packet_payload.len], packet_payload);

    var rndbuf: [255]u8 = undefined; // block_size would do
    rand.bytes(rndbuf[0..padding_length]);
    @memcpy(iobuf[sizeof_PktHdr + packet_payload.len .. packet_len], rndbuf[0..padding_length]);

    if (encrypted) {
        if (packet_len + mac_algo.key_length > iobuf.len) return IoError.tooBig;
        var out: [MaxSSHPacket]u8 = undefined;

        TRACEDUMP(.Debug, "sendbuffer enc:plaintext", .{}, iobuf[0..packet_len]);
        keysuni.aesctr.encrypt(iobuf[0..packet_len], out[0..packet_len]);

        var mac: [mac_algo.key_length]u8 = undefined;
        var m = mac_algo.init(keysuni.mackey[0..mac_algo.key_length]);
        const seq = std.mem.nativeTo(u32, keysuni.seq, .big);
        m.update(std.mem.asBytes(&seq));
        m.update(iobuf[0..packet_len]); // plaintext
        m.final(&mac);

        TRACEDUMP(.Debug, "mackey", .{}, keysuni.mackey[0..mac_algo.key_length]);
        TRACEDUMP(.Debug, "macseq", .{}, std.mem.asBytes(&seq));
        TRACEDUMP(.Debug, "macdata", .{}, iobuf[0..packet_len]);

        @memcpy(out[packet_len .. packet_len + mac_algo.key_length], &mac);
        const out_len = packet_len + mac_algo.key_length;

        // Copy encrypted packet plus MAC back to the caller's output buffer.
        @memcpy(iobuf[0..out_len], out[0..out_len]);

        TRACEDUMP(.Debug, "enc send", .{}, iobuf[0..out_len]);

        keysuni.seq +%= 1;
        return iobuf[0..out_len];
    } else {
        keysuni.seq +%= 1;
        return iobuf[0..packet_len];
    }
}

test "identification accepts valid UTF-8 comments" {
    try std.testing.expect(isValidIdentification("SSH-2.0-server café 🚀"));
}

test "identification accepts SSH 1.99 compatibility version" {
    try std.testing.expect(isValidIdentification("SSH-1.99-server compatibility"));
}

test "identification rejects hyphen in softwareversion" {
    try std.testing.expect(!isValidIdentification("SSH-2.0-server-name comment"));
}

test "identification rejects invalid UTF-8 and forbidden comment bytes" {
    try std.testing.expect(!isValidIdentification("SSH-2.0-server \x80"));
    try std.testing.expect(!isValidIdentification("SSH-2.0-server comment\x00text"));
    try std.testing.expect(!isValidIdentification("SSH-2.0-server comment\rtext"));
    try std.testing.expect(!isValidIdentification("SSH-2.0-server comment\ntext"));
}

test "MsgId enum values match SSH RFC" {
    // RFC 4253 transport layer messages
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(MsgId.SSH_MSG_DISCONNECT));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(MsgId.SSH_MSG_IGNORE));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(MsgId.SSH_MSG_UNIMPLEMENTED));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(MsgId.SSH_MSG_DEBUG));

    // RFC 4254 channel messages
    try std.testing.expectEqual(@as(u8, 80), @intFromEnum(MsgId.SSH_MSG_GLOBAL_REQUEST));
    try std.testing.expectEqual(@as(u8, 81), @intFromEnum(MsgId.SSH_MSG_REQUEST_SUCCESS));
    try std.testing.expectEqual(@as(u8, 82), @intFromEnum(MsgId.SSH_MSG_REQUEST_FAILURE));
    try std.testing.expectEqual(@as(u8, 90), @intFromEnum(MsgId.SSH_MSG_CHANNEL_OPEN));
    try std.testing.expectEqual(@as(u8, 94), @intFromEnum(MsgId.SSH_MSG_CHANNEL_DATA));
    try std.testing.expectEqual(@as(u8, 96), @intFromEnum(MsgId.SSH_MSG_CHANNEL_EOF));
    try std.testing.expectEqual(@as(u8, 97), @intFromEnum(MsgId.SSH_MSG_CHANNEL_CLOSE));
}

test "MaxPayload is reasonable" {
    try std.testing.expect(MaxPayload > 0);
    try std.testing.expect(MaxPayload < MaxSSHPacket);
}

test "MaxChannelDataLen accounts for framing overhead" {
    // Channel data framing: msgid(1) + channel(4) + string_len(4) = 9 bytes
    try std.testing.expectEqual(MaxPayload - 9, MaxChannelDataLen);
    try std.testing.expect(MaxChannelDataLen > 0);
    try std.testing.expect(MaxChannelDataLen > 64); // must be larger than old hardcoded value
}

test "agent forwarding channel type aliases" {
    try std.testing.expect(isAgentChannelType(channel_type_auth_agent_openssh));
    try std.testing.expect(isAgentChannelType(channel_type_auth_agent));
    try std.testing.expect(!isAgentChannelType(channel_type_session));
}

test "compression algorithm selection follows client preference" {
    try std.testing.expectEqual(CompressionAlgorithm.ZlibOpenSsh, selectCompressionAlgorithm(compression_algorithms, compression_algorithms).?);
    try std.testing.expectEqual(CompressionAlgorithm.None, selectCompressionAlgorithm("none,zlib@openssh.com", compression_algorithms).?);
    try std.testing.expectEqual(CompressionAlgorithm.None, selectCompressionAlgorithm(compression_algorithms, "none").?);
    try std.testing.expect(selectCompressionAlgorithm("zstd@openssh.com", compression_algorithms) == null);
}

test "zlib openssh compression streams round trip flushed packets" {
    var compressor = CompressionState{ .algorithm = .ZlibOpenSsh };
    defer compressor.deinit();
    var decompressor = CompressionState{ .algorithm = .ZlibOpenSsh };
    defer decompressor.deinit();

    try compressor.activateDeflate();
    try decompressor.activateInflate();

    var compressed: [MaxPayload]u8 = undefined;
    var decompressed: [MaxPayload]u8 = undefined;

    const payload1 = "hello hello hello hello hello";
    const compressed1 = try compressor.compressPayload(payload1, &compressed);
    const decompressed1 = try decompressor.decompressPayload(compressed1, &decompressed);
    try std.testing.expectEqualStrings(payload1, decompressed1);

    const payload2 = "second packet reuses the same zlib stream";
    const compressed2 = try compressor.compressPayload(payload2, &compressed);
    const decompressed2 = try decompressor.decompressPayload(compressed2, &decompressed);
    try std.testing.expectEqualStrings(payload2, decompressed2);
}

test "zlib openssh decompression rejects invalid data" {
    var decompressor = CompressionState{ .algorithm = .ZlibOpenSsh };
    defer decompressor.deinit();
    try decompressor.activateInflate();

    var output: [MaxPayload]u8 = undefined;
    try std.testing.expectError(IoError.InvalidPacketSize, decompressor.decompressPayload("not a zlib stream", &output));
}

test "wrapPayload preserves uncompressed payload with none compression" {
    var prng = std.Random.DefaultPrng.init(42);
    var keys = KeyDataUni{ .seq = 0 };
    defer keys.clear();
    var rand = prng.random();

    var iobuf: [MaxSSHPacket]u8 = undefined;
    const payload = "plain ssh payload";
    const packet = try wrapPayload(&rand, false, &keys, payload, &iobuf);

    const hdr = readPktHdr(packet[0..sizeof_PktHdr]);
    const payload_len = hdr.packet_length - hdr.padding_length - 1;
    try std.testing.expectEqualStrings(payload, packet[sizeof_PktHdr .. sizeof_PktHdr + payload_len]);
}

test "wrapPayload compresses active zlib openssh payloads" {
    var prng = std.Random.DefaultPrng.init(42);
    var sender = KeyDataUni{ .seq = 0, .compression = .{ .algorithm = .ZlibOpenSsh } };
    defer sender.clear();
    var receiver = KeyDataUni{ .seq = 0, .compression = .{ .algorithm = .ZlibOpenSsh } };
    defer receiver.clear();
    try sender.compression.activateDeflate();
    try receiver.compression.activateInflate();
    var rand = prng.random();

    var iobuf: [MaxSSHPacket]u8 = undefined;
    const payload = "compressed ssh payload compressed ssh payload compressed ssh payload";
    const packet = try wrapPayload(&rand, false, &sender, payload, &iobuf);

    const hdr = readPktHdr(packet[0..sizeof_PktHdr]);
    const compressed_len = hdr.packet_length - hdr.padding_length - 1;
    const compressed_payload = packet[sizeof_PktHdr .. sizeof_PktHdr + compressed_len];
    try std.testing.expect(!std.mem.eql(u8, payload, compressed_payload));

    var decompressed: [MaxPayload]u8 = undefined;
    const restored = try receiver.compression.decompressPayload(compressed_payload, &decompressed);
    try std.testing.expectEqualStrings(payload, restored);
}

test "KeyDataBi.clear zeros all key material" {
    var kd = KeyDataBi.init();
    // fill with non-zero data
    @memset(&kd.c2s.iv, 0xAA);
    @memset(&kd.c2s.key, 0xBB);
    @memset(&kd.c2s.mackey, 0xCC);
    @memset(&kd.s2c.iv, 0xDD);
    @memset(&kd.s2c.key, 0xEE);
    @memset(&kd.s2c.mackey, 0xFF);

    kd.clear();

    const zero_iv: [MaxIVLen]u8 = .{0} ** MaxIVLen;
    const zero_key: [MaxKeyLen]u8 = .{0} ** MaxKeyLen;
    try std.testing.expectEqualSlices(u8, &zero_iv, &kd.c2s.iv);
    try std.testing.expectEqualSlices(u8, &zero_key, &kd.c2s.key);
    try std.testing.expectEqualSlices(u8, &zero_key, &kd.c2s.mackey);
    try std.testing.expectEqualSlices(u8, &zero_iv, &kd.s2c.iv);
    try std.testing.expectEqualSlices(u8, &zero_key, &kd.s2c.key);
    try std.testing.expectEqualSlices(u8, &zero_key, &kd.s2c.mackey);
}
