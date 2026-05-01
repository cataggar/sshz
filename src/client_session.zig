const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const MisshodClient = @import("misshod.zig").MisshodClient;
const MisshodError = @import("misshod.zig").MisshodError;
const IoError = @import("misshod.zig").IoError;
const native_endian = @import("builtin").target.cpu.arch.endian();
const BufferWriter = @import("buffer.zig").BufferWriter;
const BufferError = @import("buffer.zig").BufferError;
const BufferReader = @import("buffer.zig").BufferReader;
const Hasher = @import("hasher.zig").Hasher;
const AesCtr = @import("aesctr.zig").AesCtr;
const decodePrivKey = @import("privkey.zig").decodePrivKey;
const PrivKeyError = @import("privkey.zig").PrivKeyError;
const Protocol = @import("protocol.zig");

pub const SessionState = enum {
    Init,
    KexInitWrite,
    KexInitRead,
    EcdhInitWrite,
    EcdhReply,
    CheckHostKey,
    CheckHostKeyCompleted,
    NewKeysRead,
    NewKeysWrite,
    AuthServReq,
    AuthServRsp,
    AuthStart,
    GetPrivateKeyCompleted,
    PubkeyAuthDecodeKeyPasswordless,
    PubkeyAuthDecodeKeyPassword,
    PubkeyAuthReq,
    AuthRsp,
    PasswordAuthReq,
    ChannelOpenReq,
    ChannelOpenRsp,
    ChannelPtyReq,
    ChannelPtyRsp,
    ChannelExecReq,
    ChannelExecRsp,
    ChannelShellReq,
    ChannelShellRsp,
    ChannelConnected,
    ChannelData,
    ChannelDataRxAdjustWindow,
    ChannelDataRx,
    ChannelDataTx,
    ChannelDataTxComplete,
    ChannelWindowChange,
};

fn initPtyTerm(term: []const u8) [64]u8 {
    var buf: [64]u8 = .{0} ** 64;
    @memcpy(buf[0..term.len], term);
    return buf;
}

pub const Session = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    ioSessionState: Protocol.IoSessionState,
    sessionState: SessionState,

    ecdh_ephem_keypair: Protocol.kex_algo.KeyPair = undefined,
    // In form U32LenString("ssh-ed25519"), U32LenString(secret)
    hostkey_ks: ?[]u8 = undefined, // K_S, slice of hostkey_ks_buf, allocated
    shared_secret_k: [Protocol.kex_algo.shared_length]u8 = undefined, // K
    kex_hasher: Hasher(Protocol.hash_algo) = undefined, // for building H
    kex_hash_order: Protocol.KexHashOrder = .Init,
    session_id: [Protocol.hash_algo.digest_length]u8 = undefined,
    keydata: Protocol.KeyDataBi,
    username: []const u8,
    rand: std.Random = undefined,
    encrypted: bool,
    local_channel: u32,
    remote_channel: u32,
    channel_write_buf: [1024]u8 = undefined,
    channel_write_buf_nbytes: usize,
    pty_term: [64]u8 = undefined,
    pty_term_len: usize,
    pty_cols: u32,
    pty_rows: u32,
    pty_width_px: u32,
    pty_height_px: u32,
    resize_pending: bool,
    exec_command: ?[]u8,

    privkey_ascii: ?[]u8, // allocated  // FIXME deinit properly and clear
    privkey_passphrase: ?[]u8, //allocated
    auth_passphrase: ?[]u8, //allocated
    privkey_blob: [Protocol.srv_hostkey_algo.SecretKey.encoded_length]u8 = undefined,
    pubkey_blob: [Protocol.srv_hostkey_algo.PublicKey.encoded_length]u8 = undefined,

    pub fn init(rand: std.Random, username: []const u8, allocator: std.mem.Allocator) !Self {
        return .{
            .ioSessionState = .Init,
            .sessionState = .Init,
            .rand = rand,
            .allocator = allocator,
            .username = username,
            .encrypted = false,
            .local_channel = 0,
            .remote_channel = 0,
            .keydata = Protocol.KeyDataBi.init(),
            .kex_hasher = Hasher(Protocol.hash_algo).init(), // for hashing H
            .privkey_ascii = null,
            .privkey_passphrase = null,
            .auth_passphrase = null,
            .channel_write_buf_nbytes = 0,
            .pty_term = initPtyTerm("xterm-color"),
            .pty_term_len = "xterm-color".len,
            .pty_cols = 80,
            .pty_rows = 24,
            .pty_width_px = 640,
            .pty_height_px = 480,
            .resize_pending = false,
            .exec_command = null,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.exec_command) |command| {
            allocator.free(command);
            self.exec_command = null;
        }
        if (self.privkey_ascii) |key| {
            allocator.free(key);
            self.privkey_ascii = null;
        }
        if (self.privkey_passphrase) |passphrase| {
            allocator.free(passphrase);
            self.privkey_passphrase = null;
        }
        if (self.auth_passphrase) |passphrase| {
            allocator.free(passphrase);
            self.auth_passphrase = null;
        }
    }

    pub fn setIoSessionState(self: *Self, newState: Protocol.IoSessionState) void {
        TRACE(.Debug, "ioSessionState {any} -> {any}", .{ self.ioSessionState, newState });
        self.ioSessionState = newState;
    }

    pub fn setSessionState(self: *Self, newState: SessionState) void {
        TRACE(.Debug, "sessionState {any} -> {any}", .{ self.sessionState, newState });
        self.sessionState = newState;
    }

    pub fn advanceSession(self: *Self, misshod: *MisshodClient) MisshodError!void {
        const outkeys = &self.keydata.c2s;

        switch (self.sessionState) {
            .Init => {
                self.setSessionState(.KexInitWrite);
            },
            .KexInitWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT));
                var cookie: [16]u8 = undefined;
                self.rand.bytes(&cookie);
                try pkt.writeBytes(&cookie);

                try pkt.writeU32LenString(Protocol.kex_algo_name); // kex
                try pkt.writeU32LenString(Protocol.srv_hostkey_algo_name); // hostkey verification
                try pkt.writeU32LenString(Protocol.enc_algo_name); // enc c2s
                try pkt.writeU32LenString(Protocol.enc_algo_name); // enc s2c
                try pkt.writeU32LenString(Protocol.mac_algo_name); // mac c2s
                try pkt.writeU32LenString(Protocol.mac_algo_name); // mac s2c
                try pkt.writeU32LenString("none"); // compression c2s
                try pkt.writeU32LenString("none"); // compression s2c
                try pkt.writeU32LenString(""); // lang c2s
                try pkt.writeU32LenString(""); // lang s2c

                const first_kex_packet_follows = false;
                try pkt.writeBoolean(first_kex_packet_follows);
                try pkt.writeU32(0); // reserved

                self.kex_hash_order = self.kex_hash_order.check(.I_C);
                self.kex_hasher.writeU32LenString(pkt.active());

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.KexInitRead);
            },
            .KexInitRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .EcdhInitWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_INIT));

                // Zig 0.16's X25519 KeyPair.generate wants std.Io; keep
                // misshod's caller-provided CSPRNG and feed X25519 a fresh
                // seed for each key exchange.
                var seed: [Protocol.kex_algo.seed_length]u8 = undefined;
                self.rand.bytes(&seed);
                self.ecdh_ephem_keypair = try Protocol.kex_algo.KeyPair.generateDeterministic(seed);
                var q_c = self.ecdh_ephem_keypair.public_key;
                try pkt.writeU32LenString(&q_c);

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.EcdhReply);
            },
            .EcdhReply => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .CheckHostKey => {
                misshod.requestEvent(.{ .CheckHostKey = self.hostkey_ks }, .Idle);
                self.setSessionState(.CheckHostKeyCompleted);
            },
            .CheckHostKeyCompleted => {
                self.setSessionState(.NewKeysRead);
                self.setIoSessionState(.ReadPktHdr);
            },
            .NewKeysRead => {
                //std.debug.assert(false);
                // FIXME explain why empty
            },
            .NewKeysWrite => {
                // https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS));
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.AuthServReq);
                self.encrypted = true; // have read and written SSH_MSG_NEWKEYS, encrypted from now on
            },
            .AuthServReq => {
                // https://datatracker.ietf.org/doc/html/rfc4253
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_SERVICE_REQUEST));
                try pkt.writeU32LenString("ssh-userauth");
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.AuthServRsp);
            },
            .AuthServRsp => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .AuthStart => {
                // if we have no private key yet, ask for one
                // triggers caller to call setPrivateKey(), but they may not
                if (self.privkey_ascii == null) {
                    misshod.requestEvent(.GetPrivateKey, .Idle);
                    self.setSessionState(.GetPrivateKeyCompleted);
                }
            },
            .GetPrivateKeyCompleted => {
                TRACE(.Debug, "self.privkey_ascii = {any}", .{self.privkey_ascii});
                if (self.privkey_ascii != null) {
                    self.setSessionState(.PubkeyAuthDecodeKeyPasswordless);
                } else {
                    misshod.requestEvent(.GetAuthPassphrase, .Idle);
                    self.setSessionState(.PasswordAuthReq);
                }
            },
            .PubkeyAuthDecodeKeyPasswordless => {
                if (self.privkey_ascii) |privkey_ascii| { // have private key
                    // attempt passwordless
                    decodePrivKey(privkey_ascii, null, &self.privkey_blob, &self.pubkey_blob) catch |err| {
                        switch (err) {
                            PrivKeyError.InvalidKeyDecrypt => {
                                // need a passphrase to decode key
                                misshod.requestEvent(.GetKeyPassphrase, .Idle);
                                self.setSessionState(.PubkeyAuthDecodeKeyPassword);
                                return;
                            },
                            else => {
                                self.allocator.free(privkey_ascii);
                                self.privkey_ascii = null;
                                misshod.requestEvent(.GetAuthPassphrase, .Idle);
                                self.setSessionState(.PasswordAuthReq);
                                return;
                            },
                        }
                    };
                    // key decoded ok, so must have been passwordless
                    self.setSessionState(.PubkeyAuthReq);
                } else {
                    // no key available
                    // try password auth
                    misshod.requestEvent(.GetAuthPassphrase, .Idle);
                    self.setSessionState(.PasswordAuthReq);
                }
            },
            .PubkeyAuthReq => {
                // https://datatracker.ietf.org/doc/html/rfc4252#section-7
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                //https://datatracker.ietf.org/doc/html/rfc4252#section-8

                const secretkey = try Protocol.srv_hostkey_algo.SecretKey.fromBytes(self.privkey_blob);
                const keypair = try Protocol.srv_hostkey_algo.KeyPair.fromSecretKey(secretkey);

                var backing_pubkey_buf: [256]u8 = undefined;
                var typed_pubkey_buf = BufferWriter.init(&backing_pubkey_buf, 0);
                try typed_pubkey_buf.writeU32LenString(Protocol.srv_hostkey_algo_name);
                try typed_pubkey_buf.writeU32LenString(&keypair.public_key.bytes);

                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("publickey");
                try pkt.writeBoolean(true);
                try pkt.writeU32LenString(Protocol.srv_hostkey_algo_name);
                try pkt.writeU32LenString(typed_pubkey_buf.active());

                var backing_sigbuffer_buf: [512]u8 = undefined;
                var sigbuffer = BufferWriter.init(&backing_sigbuffer_buf, 0);
                try sigbuffer.writeU32LenString(&self.session_id);
                try sigbuffer.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                try sigbuffer.writeU32LenString(self.username);
                try sigbuffer.writeU32LenString("ssh-connection");
                try sigbuffer.writeU32LenString("publickey");
                try sigbuffer.writeBoolean(true);
                try sigbuffer.writeU32LenString(Protocol.srv_hostkey_algo_name);
                try sigbuffer.writeU32LenString(typed_pubkey_buf.active());

                // gen signature
                const sig = try keypair.sign(sigbuffer.active(), null);
                const sigbytes = sig.toBytes();
                TRACEDUMP(.Debug, "sigbytes", .{}, &sigbytes);

                var backing_typed_sig_buf: [256]u8 = undefined;
                var typed_sig_buf = BufferWriter.init(&backing_typed_sig_buf, 0);
                try typed_sig_buf.writeU32LenString(Protocol.srv_hostkey_algo_name);
                try typed_sig_buf.writeU32LenString(&sigbytes);
                try pkt.writeU32LenString(typed_sig_buf.active());

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.AuthRsp);
            },
            .PubkeyAuthDecodeKeyPassword => {
                // attempt decode with passphrase
                // if this fails, drop to password auth
                decodePrivKey(self.privkey_ascii.?, self.privkey_passphrase, &self.privkey_blob, &self.pubkey_blob) catch {
                    if (self.auth_passphrase == null) {
                        misshod.requestEvent(.GetAuthPassphrase, .Idle);
                    }
                    self.setSessionState(.PasswordAuthReq);
                    return;
                };
                // key decode ok, continue with pubkey
                self.setSessionState(.PubkeyAuthReq);
            },
            .PasswordAuthReq => {
                std.debug.assert(self.auth_passphrase != null);
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                //https://datatracker.ietf.org/doc/html/rfc4252#section-8
                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("password");
                try pkt.writeBoolean(false);
                try pkt.writeU32LenString(self.auth_passphrase.?);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.AuthRsp);
            },
            .AuthRsp => { // for password or pubkey
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelOpenReq => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
                try pkt.writeU32LenString("session"); // https://datatracker.ietf.org/doc/html/rfc4250#section-4.9.1
                try pkt.writeU32(self.local_channel); // sender channel
                try pkt.writeU32(Protocol.ChannelWindowSize); // initial window size
                try pkt.writeU32(Protocol.ChannelMaxPacket); // maximum packet size
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelOpenRsp);
            },
            .ChannelOpenRsp => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelPtyReq => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
                // https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
                try pkt.writeU32(self.remote_channel);
                try pkt.writeU32LenString("pty-req");
                try pkt.writeBoolean(true); // want reply
                try pkt.writeU32LenString(self.pty_term[0..self.pty_term_len]);
                try pkt.writeU32(self.pty_cols);
                try pkt.writeU32(self.pty_rows);
                try pkt.writeU32(self.pty_width_px);
                try pkt.writeU32(self.pty_height_px);

                try pkt.writeU32LenString(&.{});

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelPtyRsp);
            },
            .ChannelPtyRsp => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelExecReq => {
                const command = self.exec_command orelse return IoError.UnexpectedResponse;
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
                // https://datatracker.ietf.org/doc/html/rfc4254#section-6.5
                try pkt.writeU32(self.remote_channel);
                try pkt.writeU32LenString("exec");
                try pkt.writeBoolean(true); // want reply
                try pkt.writeU32LenString(command);

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelExecRsp);
            },
            .ChannelExecRsp => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelShellReq => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
                // https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
                try pkt.writeU32(self.remote_channel);
                try pkt.writeU32LenString("shell");
                try pkt.writeBoolean(true); // want reply

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelShellRsp);
            },
            .ChannelShellRsp => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelConnected => {
                misshod.requestEvent(.Connected, .Idle);
                self.setSessionState(.ChannelData);
            },
            .ChannelData => {
                if (self.resize_pending) {
                    self.setSessionState(.ChannelWindowChange);
                } else if (self.channel_write_buf_nbytes > 0) { // something to send
                    self.setSessionState(.ChannelDataTx);
                } else { // wait for incoming
                    self.setSessionState(.ChannelDataRxAdjustWindow);
                }
            },
            .ChannelDataRxAdjustWindow => {
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.2
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST));
                try pkt.writeU32(self.remote_channel); // channel
                try pkt.writeU32(Protocol.ChannelWindowSize); // bytes to add
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelDataRx);
            },
            .ChannelDataRx => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelDataTx => {
                // request tx, FIXME need to honour window adjustments from the other side
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
                // https://datatracker.ietf.org/doc/html/rfc4250#section-3.3
                try pkt.writeU32(self.remote_channel);
                try pkt.writeU32LenString(self.channel_write_buf[0..self.channel_write_buf_nbytes]);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelDataTxComplete);
            },
            .ChannelDataTxComplete => {
                self.channel_write_buf_nbytes = 0;
                self.setSessionState(.ChannelData);
            },
            .ChannelWindowChange => {
                var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
                try pkt.writeU32(self.remote_channel);
                try pkt.writeU32LenString("window-change");
                try pkt.writeBoolean(false);
                try pkt.writeU32(self.pty_cols);
                try pkt.writeU32(self.pty_rows);
                try pkt.writeU32(self.pty_width_px);
                try pkt.writeU32(self.pty_height_px);
                self.resize_pending = false;
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf), .Idle);
                self.setSessionState(.ChannelData);
            },
        }
    }

    pub fn setPty(self: *Self, term: []const u8, cols: u16, rows: u16) MisshodError!void {
        if (term.len > self.pty_term.len) return IoError.tooBig;
        @memset(&self.pty_term, 0);
        @memcpy(self.pty_term[0..term.len], term);
        self.pty_term_len = term.len;
        self.setWindowSize(cols, rows);
        self.resize_pending = false;
    }

    pub fn setWindowSize(self: *Self, cols: u16, rows: u16) void {
        self.pty_cols = cols;
        self.pty_rows = rows;
        self.pty_width_px = @as(u32, cols) * 8;
        self.pty_height_px = @as(u32, rows) * 16;
        self.resize_pending = self.sessionState == .ChannelData or
            self.sessionState == .ChannelDataRxAdjustWindow or
            self.sessionState == .ChannelDataRx or
            self.sessionState == .ChannelDataTx or
            self.sessionState == .ChannelDataTxComplete or
            self.sessionState == .ChannelWindowChange;
    }

    pub fn interruptIdleChannelRead(self: *Self) bool {
        if (self.sessionState == .ChannelDataRx and self.ioSessionState == .ReadPktHdr) {
            self.setSessionState(.ChannelData);
            self.setIoSessionState(.Idle);
            return true;
        }
        return false;
    }

    pub fn getChannelWriteBuffer(self: *Self) MisshodError![]u8 {
        if (self.channel_write_buf_nbytes > 0) {
            return &.{}; // not able to write
        } else {
            return &self.channel_write_buf;
        }
    }

    pub fn channelWriteComplete(self: *Self, nbytes: usize) MisshodError!void {
        TRACEDUMP(.Debug, "channelWriteComplete nbytes={d} sessionState={any} ioState={any}", .{ nbytes, self.sessionState, self.ioSessionState }, self.channel_write_buf[0..nbytes]);
        if (nbytes > self.channel_write_buf.len) {
            return IoError.tooBig;
        } else {
            self.channel_write_buf_nbytes = nbytes; // will be picked up for send in next .ChannelData -> .ChannelDataTx
        }

        if (self.sessionState == .ChannelDataRx) { // waiting to receive
            if (self.ioSessionState == .ReadPktHdr) { // nothing actually happening
                self.setSessionState(.ChannelDataTx);
                self.setIoSessionState(.Idle);
            }
        }
        // FIXME, if read is idling, cancel it - need to assume main's poll() is going to trip due to character write too though, FIXME

    }

    pub fn setPrivateKey(self: *Self, keydata_ascii: []const u8) MisshodError!void {
        if (self.privkey_ascii) |old| {
            self.allocator.free(old);
            self.privkey_ascii = null;
        }
        std.debug.assert(self.privkey_ascii == null);
        self.privkey_ascii = try self.allocator.dupe(u8, keydata_ascii);
    }

    pub fn setPrivateKeyPassphrase(self: *Self, data: []const u8) MisshodError!void {
        if (self.privkey_passphrase) |old| {
            self.allocator.free(old);
            self.privkey_passphrase = null;
        }
        std.debug.assert(self.privkey_passphrase == null);
        self.privkey_passphrase = try self.allocator.dupe(u8, data);
    }

    pub fn setAuthPassphrase(self: *Self, data: []const u8) MisshodError!void {
        if (self.auth_passphrase) |old| {
            self.allocator.free(old);
            self.auth_passphrase = null;
        }
        std.debug.assert(self.auth_passphrase == null);
        self.auth_passphrase = try self.allocator.dupe(u8, data);
    }

    pub fn setExecCommand(self: *Self, command: []const u8) MisshodError!void {
        if (self.exec_command) |old| {
            self.allocator.free(old);
            self.exec_command = null;
        }
        self.exec_command = try self.allocator.dupe(u8, command);
    }

    // special case as we write direct to stream before entering binary pkt mode
    pub fn writeProtocolVersion(self: *Self, buf: []u8) []const u8 {
        const vers = std.fmt.bufPrint(buf, "{s}\r\n", .{Protocol.version}) catch unreachable;
        TRACE(.Debug, "TX: version '{s}'", .{Protocol.version});
        self.kex_hash_order = self.kex_hash_order.check(.V_C);
        self.kex_hasher.writeU32LenString(Protocol.version);
        return vers;
    }

    pub fn handlePacket(self: *Self, buf: []const u8, misshod: *MisshodClient) MisshodError!void {
        var rdr = try misshod.getRecvBuffer(misshod.iobuf[0..buf.len], &self.keydata.s2c);

        const msgid = try rdr.readU8();

        TRACE(.Debug, "handlePacket msgId={d}", .{msgid});
        TRACEDUMP(.Debug, "handlePacket", .{}, buf);

        switch (msgid) {
            @intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT) => {
                TRACE(.Debug, "{any}", .{@as(Protocol.MsgId, @enumFromInt(msgid))});

                self.kex_hash_order = self.kex_hash_order.check(.I_S);
                self.kex_hasher.writeU32LenString(rdr.payload[(rdr.off - 1)..]); // from before the msgid

                // https://datatracker.ietf.org/doc/html/rfc4253#section-7.1
                // https://datatracker.ietf.org/doc/html/rfc4251#section-5
                const cookie = try rdr.readBytes(16);
                TRACEDUMP(.Debug, "cookie", .{}, cookie);

                const listnames = [_][]const u8{
                    "Protocol.kex_algorithms",
                    "server_host_key_algorithms",
                    "encryption_algorithms_client_to_server",
                    "encryption_algorithms_server_to_client",
                    "Protocol.mac_algorithms_client_to_server",
                    "Protocol.mac_algorithms_server_to_client",
                    "compression_algorithms_client_to_server",
                    "compression_algorithms_server_to_client",
                    "languages_client_to_server",
                    "languages_server_to_client",
                };

                for (listnames) |listname| {
                    TRACE(.Debug, "{s}: ", .{listname});
                    var iter = util.NameListTokenizer.init(try rdr.readU32LenString());
                    while (iter.next()) |name| {
                        TRACE(.Debug, "  '{s}' ", .{name});
                    }
                }

                const first_kex_packet_follows = try rdr.readBoolean();
                TRACE(.Debug, "first_kex_packet_follows = {any}\n", .{first_kex_packet_follows});
                _ = try rdr.readU32(); // reserved, ignore

                if (self.sessionState == .KexInitRead) {
                    self.setSessionState(.EcdhInitWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    // go read another packet
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_REPLY) => {
                if (self.sessionState == .EcdhReply) {
                    TRACE(.Debug, "{any}", .{@as(Protocol.MsgId, @enumFromInt(msgid))});

                    // server's public host key, store so we can ask user to ok it
                    self.hostkey_ks = try self.allocator.dupe(u8, try rdr.readU32LenString());
                    TRACEDUMP(.Debug, "hostkey_ks", .{}, self.hostkey_ks.?);

                    const srv_pub_ephem = try rdr.readU32LenString();
                    TRACEDUMP(.Debug, "srv_pub_ephem: (len={d})", .{srv_pub_ephem.len}, srv_pub_ephem);

                    // In form U32LenString("ssh-ed25519"), U32LenString(hash)
                    const sig_exch_hash = try rdr.readU32LenString();
                    TRACEDUMP(.Debug, "sig_exch_hash: (len={d})", .{sig_exch_hash.len}, sig_exch_hash);

                    self.kex_hash_order = self.kex_hash_order.check(.K_S);
                    self.kex_hasher.writeU32LenString(self.hostkey_ks.?);

                    self.kex_hash_order = self.kex_hash_order.check(.Q_C);
                    self.kex_hasher.writeU32LenString(&self.ecdh_ephem_keypair.public_key);

                    self.kex_hash_order = self.kex_hash_order.check(.Q_S);
                    self.kex_hasher.writeU32LenString(srv_pub_ephem);

                    // generate shared secret
                    @memcpy(&self.shared_secret_k, &try Protocol.kex_algo.scalarmult(self.ecdh_ephem_keypair.secret_key, srv_pub_ephem[0..self.ecdh_ephem_keypair.secret_key.len].*));

                    TRACEDUMP(.Debug, "shared secret len={d}", .{self.shared_secret_k.len}, &self.shared_secret_k);

                    self.kex_hash_order = self.kex_hash_order.check(.K);
                    self.kex_hasher.writeMpint(&self.shared_secret_k);

                    // Produce H/session_id/key exchange hash
                    // Both sides now have this
                    var kexhash: [Protocol.hash_algo.digest_length]u8 = undefined; // session_id, H
                    self.kex_hasher.final(&kexhash, null);
                    TRACEDUMP(.Debug, "kexhash: (len={d})", .{kexhash.len}, &kexhash);

                    @memcpy(&self.session_id, &kexhash); // store as session_id

                    // verify server's signature on the hash
                    var nb = util.NamedBlob.init(self.hostkey_ks.?);
                    const rawpubkey = try nb.getBlob();
                    const pubkey = try Protocol.srv_hostkey_algo.PublicKey.fromBytes(rawpubkey[0..Protocol.srv_hostkey_algo.PublicKey.encoded_length].*);

                    nb = util.NamedBlob.init(sig_exch_hash);
                    const rawsig = try nb.getBlob();
                    const sig = Protocol.srv_hostkey_algo.Signature.fromBytes(rawsig[0..Protocol.srv_hostkey_algo.Signature.encoded_length].*);

                    try sig.verify(&kexhash, pubkey);

                    // generate keys
                    try self.keydata.genKeys(kexhash, self.shared_secret_k, self.session_id);

                    self.setSessionState(.CheckHostKey);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS) => {
                if (self.sessionState == .NewKeysRead) {
                    self.setSessionState(.NewKeysWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_SERVICE_ACCEPT) => {
                if (self.sessionState == .AuthServRsp) {
                    self.setSessionState(.AuthStart);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_BANNER) => {
                TRACE(.Debug, "Protocol.MsgId.SSH_MSG_USERAUTH_BANNER", .{});
                const banner = try rdr.readU32LenString();
                TRACE(.Info, "Server banner '{s}'", .{util.chomp(banner)});
                const lang = try rdr.readU32LenString();
                TRACE(.Debug, "Server banner language '{s}'", .{lang});
                // do another read
                self.setIoSessionState(.ReadPktHdr);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_SUCCESS) => {
                // don't care what state we were in, we've been let in
                self.setIoSessionState(.Idle);
                self.setSessionState(.ChannelOpenReq);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_FAILURE) => {
                misshod.requestEvent(.{ .EndSession = .AuthFailure }, .Idle);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                // uint32    recipient channel
                // uint32    sender channel
                // uint32    initial window size
                // uint32    maximum packet size
                const recipient_channel = try rdr.readU32();
                if (recipient_channel != self.local_channel) return IoError.UnexpectedResponse;
                self.remote_channel = try rdr.readU32();
                _ = try rdr.readU32();
                _ = try rdr.readU32();
                self.setIoSessionState(.Idle);
                self.setSessionState(.ChannelPtyReq);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA) => {
                TRACE(.Debug, "Protocol.MsgId.SSH_MSG_CHANNEL_DATA", .{});
                const channelnum = try rdr.readU32();
                const s = try rdr.readU32LenString();
                TRACE(.Debug, "got data chan={d} '{s}'\n", .{ channelnum, s });

                misshod.requestEvent(.{ .RxData = s }, .Idle);
                self.setSessionState(.ChannelData);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EXTENDED_DATA) => {
                TRACE(.Debug, "Protocol.MsgId.SSH_MSG_CHANNEL_EXTENDED_DATA", .{});
                const channelnum = try rdr.readU32();
                const data_type = try rdr.readU32();
                const s = try rdr.readU32LenString();
                TRACE(.Debug, "got extended data chan={d} type={d} '{s}'\n", .{ channelnum, data_type, s });

                misshod.requestEvent(.{ .RxData = s }, .Idle);
                self.setSessionState(.ChannelData);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_DISCONNECT),
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EOF),
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE),
            => {
                misshod.requestEvent(.{ .EndSession = .Disconnect }, .Idle); // FIXME reason code
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST) => {
                // TBD
                self.setIoSessionState(.ReadPktHdr); // read again
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_SUCCESS) => {
                if (self.sessionState == .ChannelPtyRsp) {
                    self.setSessionState(if (self.exec_command != null) .ChannelExecReq else .ChannelShellReq);
                    self.setIoSessionState(.Idle);
                } else if (self.sessionState == .ChannelExecRsp or self.sessionState == .ChannelShellRsp) {
                    self.setSessionState(.ChannelConnected);
                    self.setIoSessionState(.Idle);
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_FAILURE) => {
                misshod.requestEvent(.{ .EndSession = .Disconnect }, .Idle);
            },
            else => {
                // unhandled packet type
                TRACE(.Info, "Unhandled msg id={d}", .{msgid});
                self.setIoSessionState(.ReadPktHdr); // read again
            },
        }
    }
};

fn clearPacketPayload(packet: []const u8) []const u8 {
    const hdr = Protocol.readPktHdr(packet[0..Protocol.sizeof_PktHdr]);
    const payload_len: usize = @as(usize, hdr.packet_length) - @as(usize, hdr.padding_length) - 1;
    return packet[Protocol.sizeof_PktHdr .. Protocol.sizeof_PktHdr + payload_len];
}

fn producedPacket(misshod: *MisshodClient) ![]const u8 {
    switch (misshod.iostate) {
        .Active => |step| switch (step.action) {
            .Producing => |nbytes| return misshod.iobuf[0..nbytes],
            else => {},
        },
        else => {},
    }
    try std.testing.expect(false);
    unreachable;
}

fn singleMessagePacket(misshod: *MisshodClient, msgid: Protocol.MsgId) MisshodError![]const u8 {
    var pkt = BufferWriter.init(&misshod.iobuf, Protocol.sizeof_PktHdr);
    try pkt.writeU8(@intFromEnum(msgid));
    return try Protocol.wrapPkt(&misshod.session.rand, misshod.session.encrypted, &misshod.session.keydata.s2c, &pkt, &misshod.iobuf);
}

test "client sends exec channel request" {
    var prng = std.Random.DefaultPrng.init(0);
    var misshod = try MisshodClient.init(prng.random(), "alice", std.testing.allocator);
    defer misshod.deinit(std.testing.allocator);

    try misshod.setExecCommand("printf hi");
    misshod.session.sessionState = .ChannelExecReq;
    misshod.session.remote_channel = 42;

    try misshod.session.advanceSession(&misshod);

    var rdr = BufferReader.init(clearPacketPayload(try producedPacket(&misshod)));
    try std.testing.expect(try rdr.readU8() == @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
    try std.testing.expect(try rdr.readU32() == 42);
    try std.testing.expect(std.mem.eql(u8, try rdr.readU32LenString(), "exec"));
    try std.testing.expect(try rdr.readBoolean());
    try std.testing.expect(std.mem.eql(u8, try rdr.readU32LenString(), "printf hi"));
    try std.testing.expect(rdr.off == rdr.payload.len);
    try std.testing.expect(misshod.session.sessionState == .ChannelExecRsp);
}

test "client channel success after pty selects exec when configured" {
    var prng = std.Random.DefaultPrng.init(0);
    var misshod = try MisshodClient.init(prng.random(), "alice", std.testing.allocator);
    defer misshod.deinit(std.testing.allocator);

    try misshod.setExecCommand("uptime");
    misshod.session.sessionState = .ChannelPtyRsp;

    const packet = try singleMessagePacket(&misshod, .SSH_MSG_CHANNEL_SUCCESS);
    try misshod.session.handlePacket(packet, &misshod);

    try std.testing.expect(misshod.session.sessionState == .ChannelExecReq);
    try std.testing.expect(misshod.session.ioSessionState == .Idle);
}

test "client channel success after pty selects shell without exec command" {
    var prng = std.Random.DefaultPrng.init(0);
    var misshod = try MisshodClient.init(prng.random(), "alice", std.testing.allocator);
    defer misshod.deinit(std.testing.allocator);

    misshod.session.sessionState = .ChannelPtyRsp;

    const packet = try singleMessagePacket(&misshod, .SSH_MSG_CHANNEL_SUCCESS);
    try misshod.session.handlePacket(packet, &misshod);

    try std.testing.expect(misshod.session.sessionState == .ChannelShellReq);
    try std.testing.expect(misshod.session.ioSessionState == .Idle);
}
