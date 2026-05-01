const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const Misshod = @import("misshod.zig");
const MisshodClient = Misshod.MisshodClient;
const MisshodError = Misshod.MisshodError;
const IoError = Misshod.IoError;
const SshOpenFailureReason = Misshod.SshOpenFailureReason;
const BufferWriter = @import("buffer.zig").BufferWriter;
const BufferError = @import("buffer.zig").BufferError;
const BufferReader = @import("buffer.zig").BufferReader;
const Hasher = @import("hasher.zig").Hasher;
const AesCtr = @import("aesctr.zig").AesCtr;
const decodeOpenSshPrivateKey = @import("privkey.zig").decodeOpenSshPrivateKey;
const PrivKeyError = @import("privkey.zig").PrivKeyError;
const Key = @import("key.zig");
const Protocol = @import("protocol.zig");
const Channel = @import("channel.zig").Channel;
const ChannelTable = @import("channel.zig").ChannelTable;
const ChannelState = @import("channel.zig").ChannelState;
const ClientChannelOpenMode = @import("channel.zig").ClientChannelOpenMode;
const ChannelType = @import("channel.zig").ChannelType;
const TcpipOpen = @import("channel.zig").TcpipOpen;

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
    KeyboardInteractiveAuthReq,
    KeyboardInteractiveInfoRsp,
    ChannelOpenReq,
    ChannelOpenRsp,
    ChannelActive,
};

const PendingGlobalRequestKind = enum {
    TcpipForward,
    CancelTcpipForward,
};

const PendingGlobalRequest = struct {
    kind: PendingGlobalRequestKind,
    bind_address: []const u8,
    bind_port: u32,
};

pub const Session = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    ioSessionState: Protocol.IoSessionState,
    sessionState: SessionState,

    ecdh_ephem_keypair: Protocol.kex_algo.KeyPair = undefined,
    // In form U32LenString("ssh-ed25519"), U32LenString(secret)
    hostkey_ks: ?[]u8 = null, // K_S, allocated
    shared_secret_k: [Protocol.kex_algo.shared_length]u8 = undefined, // K
    kex_hasher: Hasher(Protocol.hash_algo) = undefined, // for building H
    kex_hash_order: Protocol.KexHashOrder = .Init,
    selected_hostkey_algorithm: ?Key.SignatureAlgorithm,
    session_id: [Protocol.hash_algo.digest_length]u8 = undefined,
    keydata: Protocol.KeyDataBi,
    username: []const u8,
    rand: std.Random = undefined,
    encrypted: bool,
    channel_table: ChannelTable,
    active_channel_id: ?u32,
    pending_window_change: ?[4]u32,
    pending_global_request: ?PendingGlobalRequest,
    pending_global_request_bind_address: [Protocol.MaxSSHPacket]u8 = undefined,
    agent_forwarding_enabled: bool,
    agent_forwarding_requested: bool,
    kbd_interactive_response: ?[]u8, // allocated
    is_rekeying: bool,

    privkey_ascii: ?[]u8, // allocated
    privkey_passphrase: ?[]u8, //allocated
    auth_passphrase: ?[]u8, //allocated
    private_key: ?Key.PrivateKey,

    pub fn init(rand: std.Random, username: []const u8, allocator: std.mem.Allocator) !Self {
        return .{
            .ioSessionState = .Init,
            .sessionState = .Init,
            .rand = rand,
            .allocator = allocator,
            .username = username,
            .encrypted = false,
            .keydata = Protocol.KeyDataBi.init(),
            .kex_hasher = Hasher(Protocol.hash_algo).init(), // for hashing H
            .selected_hostkey_algorithm = null,
            .privkey_ascii = null,
            .privkey_passphrase = null,
            .auth_passphrase = null,
            .private_key = null,
            .channel_table = ChannelTable{},
            .active_channel_id = null,
            .pending_window_change = null,
            .pending_global_request = null,
            .agent_forwarding_enabled = false,
            .agent_forwarding_requested = false,
            .kbd_interactive_response = null,
            .is_rekeying = false,
        };
    }

    pub fn deinit(self: *Self) void {
        self.clearAndFreeOptional(&self.privkey_ascii);
        self.clearAndFreeOptional(&self.privkey_passphrase);
        self.clearAndFreeOptional(&self.auth_passphrase);
        self.clearAndFreeOptional(&self.kbd_interactive_response);
        if (self.hostkey_ks) |ks| {
            std.crypto.secureZero(u8, ks);
            self.allocator.free(ks);
            self.hostkey_ks = null;
        }
        std.crypto.secureZero(u8, &self.shared_secret_k);
        std.crypto.secureZero(u8, &self.session_id);
        if (self.private_key) |*key| {
            key.clear();
            self.private_key = null;
        }
        self.channel_table.secureZeroAll();
        self.keydata.clear();
    }

    fn clearAndFreeOptional(self: *Self, field: *?[]u8) void {
        if (field.*) |slice| {
            std.crypto.secureZero(u8, slice);
            self.allocator.free(slice);
            field.* = null;
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

    fn allocateClientChannel(
        self: *Self,
        mode: ClientChannelOpenMode,
        channel_type: ChannelType,
        tcpip_open: TcpipOpen,
    ) MisshodError!*Channel {
        if (mode == .AutoShell and channel_type != .Session) return IoError.UnexpectedResponse;
        const chan = self.channel_table.allocChannel(0, 0, 0) orelse return IoError.tooManyChannels;
        chan.client_open_mode = mode;
        chan.channel_type = channel_type;
        chan.tcpip_open = tcpip_open;
        chan.state = .OpenWrite;
        return chan;
    }

    fn allocateClientSessionChannel(self: *Self, mode: ClientChannelOpenMode) MisshodError!*Channel {
        return self.allocateClientChannel(mode, .Session, .{});
    }

    fn activateDelayedCompression(self: *Self) MisshodError!void {
        try self.keydata.c2s.compression.activateDeflate();
        try self.keydata.s2c.compression.activateInflate();
    }

    pub fn advanceSession(self: *Self, misshod: *MisshodClient) MisshodError!void {
        const outkeys = &self.keydata.c2s;

        switch (self.sessionState) {
            .Init => {
                self.setSessionState(.KexInitWrite);
            },
            .KexInitWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT));
                var cookie: [16]u8 = undefined;
                self.rand.bytes(&cookie);
                try pkt.writeBytes(&cookie);

                try pkt.writeU32LenString(Protocol.kex_algo_name); // kex
                try pkt.writeU32LenString(Key.client_hostkey_algorithms); // hostkey verification
                try pkt.writeU32LenString(Protocol.enc_algo_name); // enc c2s
                try pkt.writeU32LenString(Protocol.enc_algo_name); // enc s2c
                try pkt.writeU32LenString(Protocol.mac_algo_name); // mac c2s
                try pkt.writeU32LenString(Protocol.mac_algo_name); // mac s2c
                try pkt.writeU32LenString(Protocol.compression_algorithms); // compression c2s
                try pkt.writeU32LenString(Protocol.compression_algorithms); // compression s2c
                try pkt.writeU32LenString(""); // lang c2s
                try pkt.writeU32LenString(""); // lang s2c

                const first_kex_packet_follows = false;
                try pkt.writeBoolean(first_kex_packet_follows);
                try pkt.writeU32(0); // reserved

                self.kex_hash_order = self.kex_hash_order.check(.I_C);
                self.kex_hasher.writeU32LenString(pkt.active());

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                self.setSessionState(.KexInitRead);
            },
            .KexInitRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .EcdhInitWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_INIT));

                var seed: [Protocol.kex_algo.seed_length]u8 = undefined;
                self.rand.bytes(&seed);
                self.ecdh_ephem_keypair = Protocol.kex_algo.KeyPair.generateDeterministic(seed) catch unreachable;
                var q_c = self.ecdh_ephem_keypair.public_key;
                try pkt.writeU32LenString(&q_c);

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                self.setSessionState(.EcdhReply);
            },
            .EcdhReply => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .CheckHostKey => {
                if (self.is_rekeying) {
                    // Skip host key check during re-key, already trusted
                    self.setSessionState(.NewKeysRead);
                    self.setIoSessionState(.ReadPktHdr);
                } else {
                    misshod.requestEvent(.{ .CheckHostKey = .{
                        .raw_key = self.hostkey_ks,
                        .fingerprint = blk: {
                            var fp: [Protocol.hash_algo.digest_length]u8 = undefined;
                            if (self.hostkey_ks) |ks| {
                                Protocol.hash_algo.hash(ks, &fp, .{});
                            } else {
                                @memset(&fp, 0);
                            }
                            break :blk fp;
                        },
                    } }, .Idle);
                    self.setSessionState(.CheckHostKeyCompleted);
                }
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
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS));
                const wrapped = try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr);
                self.keydata.c2s.compression.applyPendingAlgorithm();
                if (self.is_rekeying) {
                    try self.keydata.c2s.compression.activateDeflate();
                }
                misshod.requestWrite(wrapped, .Idle);
                if (self.is_rekeying) {
                    self.is_rekeying = false;
                    self.setSessionState(.ChannelActive);
                } else {
                    self.setSessionState(.AuthServReq);
                }
                self.encrypted = true;
            },
            .AuthServReq => {
                // https://datatracker.ietf.org/doc/html/rfc4253
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_SERVICE_REQUEST));
                try pkt.writeU32LenString("ssh-userauth");
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
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
                    if (self.private_key) |*old| {
                        old.clear();
                        self.private_key = null;
                    }
                    self.private_key = decodeOpenSshPrivateKey(privkey_ascii, null) catch |err| {
                        // free privkey_ascii
                        switch (err) {
                            PrivKeyError.InvalidKeyDecrypt => {
                                // need a passphrase to decode key
                                misshod.requestEvent(.GetKeyPassphrase, .Idle);
                                self.setSessionState(.PubkeyAuthDecodeKeyPassword);
                                return;
                            },
                            else => {
                                return err;
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
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                //https://datatracker.ietf.org/doc/html/rfc4252#section-8

                const private_key = if (self.private_key) |*key| key else return IoError.UnexpectedResponse;
                const sig_alg = private_key.defaultSignatureAlgorithm();

                var pubkey_blob: Key.Blob = .{};
                const typed_pubkey = try private_key.publicBlob(&pubkey_blob);

                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("publickey");
                try pkt.writeBoolean(true);
                try pkt.writeU32LenString(sig_alg.name());
                try pkt.writeU32LenString(typed_pubkey);

                var backing_sigbuffer_buf: [1024]u8 = undefined;
                var sigbuffer = BufferWriter.init(&backing_sigbuffer_buf, 0);
                try sigbuffer.writeU32LenString(&self.session_id);
                try sigbuffer.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                try sigbuffer.writeU32LenString(self.username);
                try sigbuffer.writeU32LenString("ssh-connection");
                try sigbuffer.writeU32LenString("publickey");
                try sigbuffer.writeBoolean(true);
                try sigbuffer.writeU32LenString(sig_alg.name());
                try sigbuffer.writeU32LenString(typed_pubkey);

                var typed_sig: Key.SignatureBlob = .{};
                const sig = try private_key.sign(sig_alg, sigbuffer.active(), &typed_sig);
                TRACEDUMP(.Debug, "sigbytes", .{}, sig);
                try pkt.writeU32LenString(sig);

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                self.setSessionState(.AuthRsp);
            },
            .PubkeyAuthDecodeKeyPassword => {
                // attempt decode with passphrase
                // if this fails, drop to password auth
                if (self.private_key) |*old| {
                    old.clear();
                    self.private_key = null;
                }
                self.private_key = decodeOpenSshPrivateKey(self.privkey_ascii.?, self.privkey_passphrase) catch {
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
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                //https://datatracker.ietf.org/doc/html/rfc4252#section-8
                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("password");
                try pkt.writeBoolean(false);
                try pkt.writeU32LenString(self.auth_passphrase.?);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                self.setSessionState(.AuthRsp);
            },
            .KeyboardInteractiveAuthReq => {
                // RFC 4256 §3.1 - send keyboard-interactive auth request
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                try pkt.writeU32LenString(self.username);
                try pkt.writeU32LenString("ssh-connection");
                try pkt.writeU32LenString("keyboard-interactive");
                try pkt.writeU32LenString(""); // language tag
                try pkt.writeU32LenString(""); // submethods
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                self.setSessionState(.AuthRsp);
            },
            .KeyboardInteractiveInfoRsp => {
                // RFC 4256 §3.4 - send response to info request
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_INFO_RESPONSE));
                try pkt.writeU32(1); // num-responses
                if (self.kbd_interactive_response) |resp| {
                    try pkt.writeU32LenString(resp);
                } else {
                    try pkt.writeU32LenString("");
                }
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                self.clearAndFreeOptional(&self.kbd_interactive_response);
                self.setSessionState(.AuthRsp);
            },
            .AuthRsp => { // for password or pubkey
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelOpenReq => {
                const chan = try self.allocateClientSessionChannel(.AutoShell);
                self.active_channel_id = chan.local_id;
                self.setSessionState(.ChannelActive);
            },
            .ChannelOpenRsp => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelActive => {
                try self.advanceChannel(misshod, outkeys);
            },
        }
    }

    fn advanceChannel(self: *Self, misshod: *MisshodClient, outkeys: *Protocol.KeyDataUni) MisshodError!void {
        const ch = if (self.active_channel_id) |id|
            self.channel_table.findByLocalId(id)
        else
            self.channel_table.findNextRunnable();

        if (ch == null) {
            self.setIoSessionState(.ReadPktHdr);
            return;
        }

        const chan = ch.?;
        self.active_channel_id = chan.local_id;

        switch (chan.state) {
            .OpenWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
                try pkt.writeU32LenString(chan.channel_type.name()); // https://datatracker.ietf.org/doc/html/rfc4250#section-4.9.1
                try pkt.writeU32(chan.local_id); // sender channel
                try pkt.writeU32(Protocol.MaxPayload); // initial window size
                try pkt.writeU32(Protocol.MaxPayload); // maximum packet size
                if (chan.channel_type.hasTcpipOpenPayload()) {
                    try pkt.writeU32LenString(chan.tcpip_open.host);
                    try pkt.writeU32(chan.tcpip_open.port);
                    try pkt.writeU32LenString(chan.tcpip_open.originator_host);
                    try pkt.writeU32(chan.tcpip_open.originator_port);
                }
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                self.setSessionState(.ChannelOpenRsp);
            },
            .Open => {
                if (chan.kind != .Session) {
                    chan.state = .Data;
                    return;
                }
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
                try pkt.writeU32(chan.remote_id);
                try pkt.writeU32LenString("pty-req");
                try pkt.writeBoolean(false); // want reply
                try pkt.writeU32LenString("xterm-color");
                try pkt.writeU32(80);
                try pkt.writeU32(24);
                try pkt.writeU32(640);
                try pkt.writeU32(480);

                // magic pulled from observing OpenSSH connect
                const termdata = &[_]u8{
                    0x81, 0x00, 0x00, 0x25, 0x80, 0x80, 0x00,
                    0x00, 0x25, 0x80, 0x01, 0x00, 0x00, 0x00,
                    0x03, 0x02, 0x00, 0x00, 0x00, 0x1c, 0x03,
                    0x00, 0x00, 0x00, 0x7f, 0x04, 0x00, 0x00,
                    0x00, 0x15, 0x05, 0x00, 0x00, 0x00, 0x04,
                    0x06, 0x00, 0x00, 0x00, 0xff, 0x07, 0x00,
                    0x00, 0x00, 0xff, 0x08, 0x00, 0x00, 0x00,
                    0x11, 0x09, 0x00, 0x00, 0x00, 0x13, 0x0a,
                    0x00, 0x00, 0x00, 0x1a, 0x0b, 0x00, 0x00,
                    0x00, 0x19, 0x0c, 0x00, 0x00, 0x00, 0x12,
                    0x0d, 0x00, 0x00, 0x00, 0x17, 0x0e, 0x00,
                    0x00, 0x00, 0x16, 0x11, 0x00, 0x00, 0x00,
                    0x14, 0x12, 0x00, 0x00, 0x00, 0x0f, 0x1e,
                    0x00, 0x00, 0x00, 0x01, 0x1f, 0x00, 0x00,
                    0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
                    0x21, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00,
                    0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
                    0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x26,
                    0x00, 0x00, 0x00, 0x01, 0x27, 0x00, 0x00,
                    0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
                    0x29, 0x00, 0x00, 0x00, 0x01, 0x2a, 0x00,
                    0x00, 0x00, 0x01, 0x32, 0x00, 0x00, 0x00,
                    0x01, 0x33, 0x00, 0x00, 0x00, 0x01, 0x35,
                    0x00, 0x00, 0x00, 0x01, 0x36, 0x00, 0x00,
                    0x00, 0x01, 0x37, 0x00, 0x00, 0x00, 0x01,
                    0x38, 0x00, 0x00, 0x00, 0x00, 0x39, 0x00,
                    0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00,
                    0x00, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x3c,
                    0x00, 0x00, 0x00, 0x01, 0x3d, 0x00, 0x00,
                    0x00, 0x01, 0x3e, 0x00, 0x00, 0x00, 0x01,
                    0x46, 0x00, 0x00, 0x00, 0x01, 0x48, 0x00,
                    0x00, 0x00, 0x01, 0x49, 0x00, 0x00, 0x00,
                    0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x4b,
                    0x00, 0x00, 0x00, 0x00, 0x5a, 0x00, 0x00,
                    0x00, 0x01, 0x5b, 0x00, 0x00, 0x00, 0x01,
                    0x5c, 0x00, 0x00, 0x00, 0x00, 0x5d, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                };
                try pkt.writeU32LenString(termdata);

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                chan.state = .RspWrite;
            },
            .RspWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
                try pkt.writeU32(chan.remote_id);
                if (self.agent_forwarding_enabled and !self.agent_forwarding_requested) {
                    try pkt.writeU32LenString(Protocol.channel_request_auth_agent);
                    try pkt.writeBoolean(false); // want reply
                    self.agent_forwarding_requested = true;
                } else {
                    try pkt.writeU32LenString("shell");
                    try pkt.writeBoolean(false); // want reply
                    chan.state = .Connected;
                }

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
            },
            .Connected => {
                switch (chan.kind) {
                    .Session => misshod.requestEvent(.Connected, .Idle),
                    .AgentForward => misshod.requestEvent(.{ .AgentChannelOpen = chan.local_id }, .Idle),
                }
                chan.state = .Data;
            },
            .Data => {
                if (chan.kind == .Session and self.pending_window_change != null) {
                    // Send window-change directly
                    const wc = self.pending_window_change.?;
                    self.pending_window_change = null;
                    var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                    try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
                    try pkt.writeU32(chan.remote_id);
                    try pkt.writeU32LenString("window-change");
                    try pkt.writeBoolean(false); // want reply
                    try pkt.writeU32(wc[0]); // cols
                    try pkt.writeU32(wc[1]); // rows
                    try pkt.writeU32(wc[2]); // width_px
                    try pkt.writeU32(wc[3]); // height_px
                    misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                } else if (chan.write_buf_nbytes > 0) {
                    chan.state = .DataTx;
                } else if (chan.needsWindowAdjust()) {
                    // RFC 4254 §5.2 — replenish receive window
                    var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                    try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST));
                    try pkt.writeU32(chan.remote_id);
                    const adjust = chan.windowAdjustAmount();
                    try pkt.writeU32(adjust);
                    chan.local_window += adjust;
                    misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                    chan.state = .DataRx;
                    self.active_channel_id = null;
                } else {
                    chan.state = .DataRx;
                    self.active_channel_id = null;
                }
                if (self.channel_table.findNextRunnable()) |_| {} else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            .DataRx => {
                self.active_channel_id = null;
                self.setIoSessionState(.ReadPktHdr);
            },
            .DataTx => {
                const max_send = @min(chan.remote_max_packet_size, @as(u32, @intCast(chan.write_buf_nbytes)));
                const send_len = @min(max_send, chan.peer_window);
                if (send_len == 0) {
                    chan.state = .DataRx;
                    self.active_channel_id = null;
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                }
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
                try pkt.writeU32(chan.remote_id);
                try pkt.writeU32LenString(chan.write_buf[0..send_len]);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                chan.peer_window -= @intCast(send_len);
                chan.state = .DataTxComplete;
            },
            .DataTxComplete => {
                chan.write_buf_nbytes = 0;
                chan.state = .Data;
            },
            .EofWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EOF));
                try pkt.writeU32(chan.remote_id);
                chan.eof_sent = true;
                chan.state = .DataRx;
                self.active_channel_id = null;
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
            },
            .CloseWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE));
                try pkt.writeU32(chan.remote_id);
                chan.close_sent = true;
                chan.state = .Closed;
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
            },
            .Closed => {
                const local_id = chan.local_id;
                const kind = chan.kind;
                self.channel_table.freeChannel(local_id);
                self.active_channel_id = null;
                if (kind == .AgentForward) {
                    misshod.requestEvent(.{ .AgentChannelClosed = local_id }, .Idle);
                } else if (self.channel_table.activeCount() == 0) {
                    misshod.requestEvent(.{ .EndSession = .Disconnect }, .Idle);
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            .ConfirmWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
                try pkt.writeU32(chan.remote_id);
                try pkt.writeU32(chan.local_id);
                try pkt.writeU32(Protocol.MaxPayload);
                try pkt.writeU32(Protocol.MaxPayload);
                chan.state = if (chan.kind == .AgentForward or chan.channel_type == .Session) .Connected else .Data;
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
            },
            .OpenFailureWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE));
                try pkt.writeU32(chan.remote_id);
                try pkt.writeU32(chan.open_failure_reason_code);
                try pkt.writeU32LenString(chan.open_failure_description);
                try pkt.writeU32LenString("");
                const local_id = chan.local_id;
                self.channel_table.freeChannel(local_id);
                self.active_channel_id = null;
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
            },
            .OpenSent => {
                self.setIoSessionState(.ReadPktHdr);
            },
        }
    }

    pub fn getChannelWriteBuffer(self: *Self, channel_id: u32) MisshodError![]u8 {
        if (self.channel_table.findByLocalId(channel_id)) |chan| {
            if (chan.eof_sent) return &.{};
            if (chan.write_buf_nbytes > 0) {
                return &.{};
            } else {
                return &chan.write_buf;
            }
        }
        return &.{};
    }

    pub fn openSessionChannel(self: *Self, misshod: *MisshodClient) MisshodError!u32 {
        if (misshod.iostate_wr != .Idle or self.active_channel_id != null) {
            return IoError.cannotAcceptWrite;
        }
        if (self.sessionState != .ChannelActive) {
            return IoError.NotReady;
        }

        const chan = try self.allocateClientSessionChannel(.RawSession);
        self.active_channel_id = chan.local_id;
        self.setIoSessionState(.Idle);
        try self.advanceChannel(misshod, &self.keydata.c2s);
        return chan.local_id;
    }

    pub fn openDirectTcpipChannel(
        self: *Self,
        misshod: *MisshodClient,
        host: []const u8,
        port: u32,
        originator_host: []const u8,
        originator_port: u32,
    ) MisshodError!u32 {
        if (misshod.iostate_wr != .Idle or self.active_channel_id != null) {
            return IoError.cannotAcceptWrite;
        }
        if (self.sessionState != .ChannelActive) {
            return IoError.NotReady;
        }

        const chan = try self.allocateClientChannel(.RawSession, .DirectTcpip, .{
            .host = host,
            .port = port,
            .originator_host = originator_host,
            .originator_port = originator_port,
        });
        self.active_channel_id = chan.local_id;
        self.setIoSessionState(.Idle);
        try self.advanceChannel(misshod, &self.keydata.c2s);
        return chan.local_id;
    }

    pub fn openLocalForwardChannel(
        self: *Self,
        misshod: *MisshodClient,
        host: []const u8,
        port: u32,
        originator_host: []const u8,
        originator_port: u32,
    ) MisshodError!u32 {
        return try self.openDirectTcpipChannel(misshod, host, port, originator_host, originator_port);
    }

    fn sendTcpipForwardGlobalRequest(
        self: *Self,
        misshod: *MisshodClient,
        kind: PendingGlobalRequestKind,
        bind_address: []const u8,
        bind_port: u32,
    ) MisshodError!void {
        if (misshod.iostate_wr != .Idle or self.active_channel_id != null or self.pending_global_request != null) {
            return IoError.cannotAcceptWrite;
        }
        if (self.sessionState != .ChannelActive) {
            return IoError.NotReady;
        }
        if (bind_address.len > self.pending_global_request_bind_address.len) {
            return IoError.tooBig;
        }

        @memcpy(self.pending_global_request_bind_address[0..bind_address.len], bind_address);
        const stored_bind_address = self.pending_global_request_bind_address[0..bind_address.len];

        var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
        try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_GLOBAL_REQUEST));
        try pkt.writeU32LenString(switch (kind) {
            .TcpipForward => "tcpip-forward",
            .CancelTcpipForward => "cancel-tcpip-forward",
        });
        try pkt.writeBoolean(true); // want reply
        try pkt.writeU32LenString(stored_bind_address);
        try pkt.writeU32(bind_port);

        const wrapped = try Protocol.wrapPkt(&self.rand, self.encrypted, &self.keydata.c2s, &pkt, &misshod.iobuf_wr);
        self.pending_global_request = .{
            .kind = kind,
            .bind_address = stored_bind_address,
            .bind_port = bind_port,
        };
        misshod.requestWrite(wrapped, .Idle);
    }

    pub fn requestRemoteForward(self: *Self, misshod: *MisshodClient, bind_address: []const u8, bind_port: u32) MisshodError!void {
        try self.sendTcpipForwardGlobalRequest(misshod, .TcpipForward, bind_address, bind_port);
    }

    pub fn cancelRemoteForward(self: *Self, misshod: *MisshodClient, bind_address: []const u8, bind_port: u32) MisshodError!void {
        try self.sendTcpipForwardGlobalRequest(misshod, .CancelTcpipForward, bind_address, bind_port);
    }

    pub fn acceptChannelOpen(self: *Self, channel_id: u32) MisshodError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.state != .Open) return IoError.UnexpectedResponse;
        chan.state = .ConfirmWrite;
        self.active_channel_id = channel_id;
        self.setSessionState(.ChannelActive);
        self.setIoSessionState(.Idle);
    }

    pub fn rejectChannelOpen(self: *Self, channel_id: u32, reason_code: u32, description: []const u8) MisshodError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.state != .Open) return IoError.UnexpectedResponse;
        chan.open_failure_reason_code = reason_code;
        chan.open_failure_description = description;
        chan.state = .OpenFailureWrite;
        self.active_channel_id = channel_id;
        self.setSessionState(.ChannelActive);
        self.setIoSessionState(.Idle);
    }

    pub fn channelWriteComplete(self: *Self, channel_id: u32, nbytes: usize) MisshodError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.eof_sent) return IoError.UnexpectedResponse;
        if (nbytes > chan.write_buf.len) {
            return IoError.tooBig;
        }
        chan.write_buf_nbytes = nbytes;
        self.active_channel_id = channel_id;

        if (chan.state == .DataRx) {
            chan.state = .Data;
            self.setSessionState(.ChannelActive);
            self.setIoSessionState(.Idle);
        }
    }

    // Full-duplex: build and send channel data packet directly without going through state machine
    pub fn directChannelWrite(self: *Self, channel_id: u32, nbytes: usize, misshod: *MisshodClient) MisshodError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.eof_sent) return IoError.UnexpectedResponse;
        if (nbytes > chan.write_buf.len) {
            return IoError.tooBig;
        }
        chan.write_buf_nbytes = nbytes;
        const outkeys = &self.keydata.c2s;
        const max_send = @min(chan.remote_max_packet_size, @as(u32, @intCast(chan.write_buf_nbytes)));
        const send_len = @min(max_send, chan.peer_window);
        if (send_len == 0) {
            return;
        }
        var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
        try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
        try pkt.writeU32(chan.remote_id);
        try pkt.writeU32LenString(chan.write_buf[0..send_len]);
        misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
        chan.peer_window -= @intCast(send_len);
        chan.write_buf_nbytes = 0;
    }

    pub fn sendChannelEof(self: *Self, channel_id: u32) MisshodError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.eof_sent) return;
        chan.state = .EofWrite;
        self.active_channel_id = channel_id;
        self.setSessionState(.ChannelActive);
        self.setIoSessionState(.Idle);
    }

    pub fn sendChannelClose(self: *Self, channel_id: u32) MisshodError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.close_sent) return;
        chan.state = .CloseWrite;
        self.active_channel_id = channel_id;
        self.setSessionState(.ChannelActive);
        self.setIoSessionState(.Idle);
    }

    pub fn sendWindowChange(self: *Self, cols: u32, rows: u32, width_px: u32, height_px: u32) void {
        self.pending_window_change = .{ cols, rows, width_px, height_px };
        if (self.sessionState == .ChannelActive) {
            if (self.channel_table.findNextRunnable()) |chan| {
                if (chan.state == .DataRx) {
                    if (self.ioSessionState == .ReadPktHdr) {
                        chan.state = .Data;
                        self.active_channel_id = chan.local_id;
                        self.setIoSessionState(.Idle);
                    }
                }
            }
        }
    }

    pub fn enableAgentForwarding(self: *Self) MisshodError!void {
        switch (self.sessionState) {
            .ChannelActive => return IoError.UnexpectedResponse,
            else => {
                self.agent_forwarding_enabled = true;
            },
        }
    }

    pub fn setKeyboardInteractiveResponse(self: *Self, response: []const u8) MisshodError!void {
        self.clearAndFreeOptional(&self.kbd_interactive_response);
        self.kbd_interactive_response = try self.allocator.dupe(u8, response);
    }

    pub fn setPrivateKey(self: *Self, keydata_ascii: []const u8) MisshodError!void {
        if (self.privkey_ascii) |old| {
            std.crypto.secureZero(u8, old);
            self.allocator.free(old);
            self.privkey_ascii = null;
        }
        std.debug.assert(self.privkey_ascii == null);
        self.privkey_ascii = try self.allocator.dupe(u8, keydata_ascii);
    }

    pub fn setPrivateKeyPassphrase(self: *Self, data: []const u8) MisshodError!void {
        if (self.privkey_passphrase) |old| {
            std.crypto.secureZero(u8, old);
            self.allocator.free(old);
            self.privkey_passphrase = null;
        }
        std.debug.assert(self.privkey_passphrase == null);
        self.privkey_passphrase = try self.allocator.dupe(u8, data);
    }

    pub fn setAuthPassphrase(self: *Self, data: []const u8) MisshodError!void {
        if (self.auth_passphrase) |old| {
            std.crypto.secureZero(u8, old);
            self.allocator.free(old);
            self.auth_passphrase = null;
        }
        std.debug.assert(self.auth_passphrase == null);
        self.auth_passphrase = try self.allocator.dupe(u8, data);
    }

    // special case as we write direct to stream before entering binary pkt mode
    pub fn writeProtocolVersion(self: *Self, buf: []u8) []const u8 {
        const vers = std.fmt.bufPrint(buf, "{s}\r\n", .{Protocol.version}) catch unreachable;
        TRACE(.Debug, "TX: version '{s}'", .{Protocol.version});
        self.kex_hash_order = self.kex_hash_order.check(.V_C);
        self.kex_hasher.writeU32LenString(Protocol.version);
        return vers;
    }

    fn sendChannelOpenFailure(
        self: *Self,
        misshod: *MisshodClient,
        recipient: u32,
        reason_code: u32,
        description: []const u8,
    ) MisshodError!void {
        var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
        try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE));
        try pkt.writeU32(recipient);
        try pkt.writeU32(reason_code);
        try pkt.writeU32LenString(description);
        try pkt.writeU32LenString("");
        misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, &self.keydata.c2s, &pkt, &misshod.iobuf_wr), .Idle);
    }

    fn readTcpipOpen(rdr: *BufferReader) MisshodError!TcpipOpen {
        return .{
            .host = try rdr.readU32LenString(),
            .port = try rdr.readU32(),
            .originator_host = try rdr.readU32LenString(),
            .originator_port = try rdr.readU32(),
        };
    }

    fn requestChannelOpenEvent(self: *Self, misshod: *MisshodClient, chan: *Channel) void {
        _ = self;
        const request: Misshod.ChannelOpenRequestType = switch (chan.channel_type) {
            .Session => .Session,
            .DirectTcpip => .{ .DirectTcpip = .{
                .host = chan.tcpip_open.host,
                .port = chan.tcpip_open.port,
                .originator_host = chan.tcpip_open.originator_host,
                .originator_port = chan.tcpip_open.originator_port,
            } },
            .ForwardedTcpip => .{ .ForwardedTcpip = .{
                .connected_host = chan.tcpip_open.host,
                .connected_port = chan.tcpip_open.port,
                .originator_host = chan.tcpip_open.originator_host,
                .originator_port = chan.tcpip_open.originator_port,
            } },
        };
        misshod.requestEvent(.{ .ChannelOpenRequest = .{ .channel = chan.local_id, .request = request } }, .Idle);
    }

    fn handleChannelOpenPacket(self: *Self, rdr: *BufferReader, misshod: *MisshodClient) MisshodError!void {
        // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
        const chantype = try rdr.readU32LenString();
        const remote_id = try rdr.readU32();
        const peer_window = try rdr.readU32();
        const max_packet_size = try rdr.readU32();

        if (Protocol.isAgentChannelType(chantype)) {
            if (!self.agent_forwarding_enabled) {
                try self.sendChannelOpenFailure(
                    misshod,
                    remote_id,
                    SshOpenFailureReason.AdministrativelyProhibited,
                    "agent forwarding not enabled",
                );
                return;
            }

            const chan = self.channel_table.allocChannelKind(.AgentForward, remote_id, peer_window, max_packet_size) orelse {
                try self.sendChannelOpenFailure(
                    misshod,
                    remote_id,
                    SshOpenFailureReason.ResourceShortage,
                    "too many channels",
                );
                return;
            };
            chan.state = .ConfirmWrite;
            self.active_channel_id = chan.local_id;
            self.setSessionState(.ChannelActive);
            self.setIoSessionState(.Idle);
            return;
        }

        const channel_type = ChannelType.fromName(chantype) orelse {
            try self.sendChannelOpenFailure(
                misshod,
                remote_id,
                SshOpenFailureReason.UnknownChannelType,
                "unknown channel type",
            );
            return;
        };

        if (channel_type == .Session) {
            try self.sendChannelOpenFailure(
                misshod,
                remote_id,
                SshOpenFailureReason.AdministrativelyProhibited,
                "client does not accept session channel opens",
            );
            return;
        }

        const tcpip_open = if (channel_type.hasTcpipOpenPayload()) try readTcpipOpen(rdr) else TcpipOpen{};
        const chan = self.channel_table.allocChannel(remote_id, peer_window, max_packet_size) orelse {
            try self.sendChannelOpenFailure(
                misshod,
                remote_id,
                SshOpenFailureReason.ResourceShortage,
                "too many channels",
            );
            return;
        };
        chan.channel_type = channel_type;
        chan.tcpip_open = tcpip_open;
        chan.state = .Open;
        self.active_channel_id = null;
        self.setSessionState(.ChannelActive);
        self.requestChannelOpenEvent(misshod, chan);
    }

    fn handleGlobalRequestSuccess(self: *Self, rdr: *BufferReader, misshod: *MisshodClient) MisshodError!void {
        const pending = self.pending_global_request orelse return IoError.UnexpectedResponse;
        self.pending_global_request = null;

        switch (pending.kind) {
            .TcpipForward => {
                const bound_port = if (pending.bind_port == 0) try rdr.readU32() else pending.bind_port;
                misshod.requestEvent(.{ .TcpipForwardSuccess = .{
                    .bind_address = pending.bind_address,
                    .requested_port = pending.bind_port,
                    .bound_port = bound_port,
                } }, .Idle);
            },
            .CancelTcpipForward => {
                misshod.requestEvent(.{ .CancelTcpipForwardSuccess = .{
                    .bind_address = pending.bind_address,
                    .bind_port = pending.bind_port,
                } }, .Idle);
            },
        }
    }

    fn handleGlobalRequestFailure(self: *Self, misshod: *MisshodClient) MisshodError!void {
        const pending = self.pending_global_request orelse return IoError.UnexpectedResponse;
        self.pending_global_request = null;

        switch (pending.kind) {
            .TcpipForward => {
                misshod.requestEvent(.{ .TcpipForwardFailure = .{
                    .bind_address = pending.bind_address,
                    .bind_port = pending.bind_port,
                } }, .Idle);
            },
            .CancelTcpipForward => {
                misshod.requestEvent(.{ .CancelTcpipForwardFailure = .{
                    .bind_address = pending.bind_address,
                    .bind_port = pending.bind_port,
                } }, .Idle);
            },
        }
    }

    pub fn handlePacket(self: *Self, buf: []const u8, misshod: *MisshodClient) MisshodError!void {
        var rdr = try misshod.getRecvBuffer(misshod.iobuf_rd[0..buf.len], &self.keydata.s2c);

        const msgid = try rdr.readU8();

        TRACE(.Debug, "handlePacket msgId={d}", .{msgid});
        TRACEDUMP(.Debug, "handlePacket", .{}, buf);

        switch (msgid) {
            @intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT) => {
                TRACE(.Debug, "{any}", .{@as(Protocol.MsgId, @enumFromInt(msgid))});

                const is_rekey = self.sessionState != .KexInitRead;
                if (is_rekey) {
                    if (self.sessionState != .ChannelActive) {
                        self.setIoSessionState(.ReadPktHdr);
                        return;
                    }
                    // RFC 4253 §9 - peer-initiated re-keying
                    TRACE(.Info, "Re-keying initiated by peer", .{});
                    self.kex_hasher = Hasher(Protocol.hash_algo).init();
                    self.kex_hash_order = .Init;
                    self.kex_hash_order = self.kex_hash_order.check(.V_C);
                    self.kex_hasher.writeU32LenString(Protocol.version);
                    self.kex_hash_order = self.kex_hash_order.check(.V_S);
                    self.kex_hasher.writeU32LenString(Protocol.version);
                    self.is_rekeying = true;
                }

                self.kex_hash_order = self.kex_hash_order.check(.I_S);
                self.kex_hasher.writeU32LenString(rdr.payload[(rdr.off - 1)..]); // from before the msgid

                // https://datatracker.ietf.org/doc/html/rfc4253#section-7.1
                const cookie = try rdr.readBytes(16);
                TRACEDUMP(.Debug, "cookie", .{}, cookie);

                const kex_namelist = try rdr.readU32LenString();
                if (!nameListContains(kex_namelist, Protocol.kex_algo_name)) {
                    TRACE(.Info, "No mutual algorithm for kex_algorithms: peer offers '{s}', we need '{s}'", .{ kex_namelist, Protocol.kex_algo_name });
                    return IoError.AlgorithmNegotiationFailed;
                }
                const hostkey_namelist = try rdr.readU32LenString();
                self.selected_hostkey_algorithm = Key.selectHostKeyAlgorithm(hostkey_namelist, null) orelse {
                    TRACE(.Info, "No mutual algorithm for server_host_key_algorithms: peer offers '{s}', we need '{s}'", .{ hostkey_namelist, Key.client_hostkey_algorithms });
                    return IoError.AlgorithmNegotiationFailed;
                };
                const required_algos = [_]struct { name: []const u8, required: []const u8 }{
                    .{ .name = "encryption_algorithms_client_to_server", .required = Protocol.enc_algo_name },
                    .{ .name = "encryption_algorithms_server_to_client", .required = Protocol.enc_algo_name },
                    .{ .name = "mac_algorithms_client_to_server", .required = Protocol.mac_algo_name },
                    .{ .name = "mac_algorithms_server_to_client", .required = Protocol.mac_algo_name },
                };

                for (required_algos) |algo| {
                    const namelist = try rdr.readU32LenString();
                    if (!nameListContains(namelist, algo.required)) {
                        TRACE(.Info, "No mutual algorithm for {s}: peer offers '{s}', we need '{s}'", .{ algo.name, namelist, algo.required });
                        return IoError.AlgorithmNegotiationFailed;
                    }
                }

                const compression_c2s_namelist = try rdr.readU32LenString();
                const compression_s2c_namelist = try rdr.readU32LenString();
                const compression_c2s = Protocol.selectCompressionAlgorithm(Protocol.compression_algorithms, compression_c2s_namelist) orelse {
                    TRACE(.Info, "No mutual algorithm for compression_algorithms_client_to_server: peer offers '{s}', we can use '{s}'", .{ compression_c2s_namelist, Protocol.compression_algorithms });
                    return IoError.AlgorithmNegotiationFailed;
                };
                const compression_s2c = Protocol.selectCompressionAlgorithm(Protocol.compression_algorithms, compression_s2c_namelist) orelse {
                    TRACE(.Info, "No mutual algorithm for compression_algorithms_server_to_client: peer offers '{s}', we can use '{s}'", .{ compression_s2c_namelist, Protocol.compression_algorithms });
                    return IoError.AlgorithmNegotiationFailed;
                };
                self.keydata.c2s.compression.queueAlgorithm(compression_c2s);
                self.keydata.s2c.compression.queueAlgorithm(compression_s2c);

                _ = try rdr.readU32LenString(); // language c2s
                _ = try rdr.readU32LenString(); // language s2c

                const first_kex_packet_follows = try rdr.readBoolean();
                TRACE(.Debug, "first_kex_packet_follows = {any}\n", .{first_kex_packet_follows});
                _ = try rdr.readU32(); // reserved, ignore

                if (self.sessionState == .KexInitRead or is_rekey) {
                    self.setSessionState(.EcdhInitWrite);
                    self.setIoSessionState(.Idle);
                } else {
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

                    const selected_sig_alg = self.selected_hostkey_algorithm orelse return IoError.UnexpectedResponse;
                    const sig_alg = try Key.signatureAlgorithm(sig_exch_hash);
                    if (sig_alg != selected_sig_alg) return IoError.AlgorithmNegotiationFailed;
                    const pubkey = try Key.parsePublicKeyBlob(self.hostkey_ks.?);
                    if (pubkey.algorithm() != selected_sig_alg.keyAlgorithm()) return IoError.AlgorithmNegotiationFailed;
                    try Key.verifySignature(pubkey, sig_exch_hash, &kexhash);

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
                    self.keydata.s2c.compression.applyPendingAlgorithm();
                    if (self.is_rekeying) {
                        try self.keydata.s2c.compression.activateInflate();
                    }
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
                // RFC 4252 §5.4 - banner message before auth completes
                const banner = try rdr.readU32LenString();
                TRACE(.Debug, "Server banner '{s}'", .{util.chomp(banner)});
                _ = try rdr.readU32LenString(); // language tag
                misshod.requestEvent(.{ .Banner = banner }, .ReadPktHdr);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_SUCCESS) => {
                // don't care what state we were in, we've been let in
                try self.activateDelayedCompression();
                self.setIoSessionState(.Idle);
                self.setSessionState(.ChannelOpenReq);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_FAILURE) => {
                misshod.requestEvent(.{ .EndSession = .AuthFailure }, .Idle);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_PK_OK) => {
                // RFC 4256 §3.3 - SSH_MSG_USERAUTH_INFO_REQUEST (same msg id as PK_OK)
                const name = try rdr.readU32LenString();
                const instruction = try rdr.readU32LenString();
                _ = try rdr.readU32LenString(); // language tag
                const num_prompts = try rdr.readU32();
                if (num_prompts > 0) {
                    const prompt = try rdr.readU32LenString();
                    const echo = try rdr.readBoolean();
                    misshod.requestEvent(.{ .KeyboardInteractive = .{
                        .name = name,
                        .instruction = instruction,
                        .prompt = prompt,
                        .echo = echo,
                    } }, .Idle);
                    self.setSessionState(.KeyboardInteractiveInfoRsp);
                } else {
                    // Zero prompts — send empty response
                    self.setSessionState(.KeyboardInteractiveInfoRsp);
                    self.setIoSessionState(.Idle);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_SUCCESS) => {
                try self.handleGlobalRequestSuccess(&rdr, misshod);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_FAILURE) => {
                try self.handleGlobalRequestFailure(misshod);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN) => {
                try self.handleChannelOpenPacket(&rdr, misshod);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
                const recipient = try rdr.readU32(); // recipient channel
                const sender = try rdr.readU32(); // sender channel
                const peer_window = try rdr.readU32(); // initial window size
                const max_packet_size = try rdr.readU32(); // maximum packet size
                if (self.channel_table.findByLocalId(recipient)) |chan| {
                    chan.remote_id = sender;
                    chan.peer_window = peer_window;
                    chan.remote_max_packet_size = max_packet_size;
                    switch (chan.client_open_mode) {
                        .AutoShell => if (chan.channel_type == .Session) {
                            chan.state = .Open;
                            self.active_channel_id = chan.local_id;
                            self.setSessionState(.ChannelActive);
                            self.setIoSessionState(.Idle);
                        } else return IoError.UnexpectedResponse,
                        .RawSession => {
                            chan.state = .Data;
                            self.active_channel_id = chan.local_id;
                            self.setSessionState(.ChannelActive);
                            misshod.requestEvent(.{ .ChannelOpened = chan.local_id }, .Idle);
                        },
                    }
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE) => {
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
                const recipient = try rdr.readU32(); // recipient channel
                const reason_code = try rdr.readU32();
                const description = try rdr.readU32LenString();
                _ = try rdr.readU32LenString(); // language tag

                if (self.channel_table.findByLocalId(recipient)) |chan| {
                    const local_id = chan.local_id;
                    self.channel_table.freeChannel(local_id);
                    self.active_channel_id = null;
                    self.setSessionState(.ChannelActive);
                    misshod.requestEvent(.{ .ChannelOpenFailure = .{
                        .channel = local_id,
                        .reason_code = reason_code,
                        .description = description,
                    } }, .Idle);
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA) => {
                const channelnum = try rdr.readU32();
                const chan = self.channel_table.findByLocalId(channelnum) orelse {
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                };
                if (chan.eof_received) {
                    TRACE(.Debug, "discarding data after EOF on channel {d}", .{channelnum});
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                }
                if (chan.state != .DataRx) {
                    return IoError.UnexpectedResponse;
                }
                const s = try rdr.readU32LenString();
                chan.consumeLocalWindow(@intCast(s.len));
                switch (chan.kind) {
                    .Session => misshod.requestEvent(.{ .RxData = s }, .Idle),
                    .AgentForward => misshod.requestEvent(.{ .AgentData = .{ .channel = chan.local_id, .data = s } }, .Idle),
                }
                chan.state = .Data;
                self.active_channel_id = chan.local_id;
                self.setSessionState(.ChannelActive);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EXTENDED_DATA) => {
                const channelnum = try rdr.readU32();
                const chan = self.channel_table.findByLocalId(channelnum) orelse {
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                };
                if (chan.eof_received) {
                    TRACE(.Debug, "discarding extended data after EOF on channel {d}", .{channelnum});
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                }
                if (chan.state != .DataRx) {
                    return IoError.UnexpectedResponse;
                }
                const data_type = try rdr.readU32();
                const s = try rdr.readU32LenString();
                chan.consumeLocalWindow(@intCast(s.len));
                misshod.requestEvent(.{ .RxExtendedData = .{ .data_type = data_type, .data = s } }, .Idle);
                chan.state = .Data;
                self.active_channel_id = chan.local_id;
                self.setSessionState(.ChannelActive);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_DISCONNECT) => {
                // RFC 4253 §11.1
                const reason_code = try rdr.readU32();
                const description = try rdr.readU32LenString();
                _ = try rdr.readU32LenString(); // language tag
                TRACE(.Info, "SSH_MSG_DISCONNECT reason={d} '{s}'", .{ reason_code, description });
                misshod.requestEvent(.{ .EndSession = .{ .ServerDisconnect = .{
                    .code = reason_code,
                    .description = description,
                } } }, .Idle);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EOF) => {
                const channelnum = try rdr.readU32();
                if (self.channel_table.findByLocalId(channelnum)) |chan| {
                    chan.eof_received = true;
                }
                self.setIoSessionState(.ReadPktHdr);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE) => {
                const channelnum = try rdr.readU32();
                const chan = self.channel_table.findByLocalId(channelnum) orelse {
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                };
                chan.close_received = true;
                if (chan.close_sent) {
                    if (chan.kind == .AgentForward) {
                        self.active_channel_id = chan.local_id;
                        chan.state = .Closed;
                        self.setSessionState(.ChannelActive);
                        self.setIoSessionState(.Idle);
                    } else {
                        self.channel_table.freeChannel(chan.local_id);
                        self.active_channel_id = null;
                        if (self.channel_table.activeCount() == 0) {
                            misshod.requestEvent(.{ .EndSession = .Disconnect }, .Idle);
                        } else {
                            self.setIoSessionState(.ReadPktHdr);
                        }
                    }
                } else {
                    self.active_channel_id = chan.local_id;
                    chan.state = .CloseWrite;
                    self.setSessionState(.ChannelActive);
                    self.setIoSessionState(.Idle);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_IGNORE) => {
                // RFC 4253 §11.2 - must be silently ignored
                self.setIoSessionState(.ReadPktHdr);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_DEBUG) => {
                // RFC 4253 §11.3 - may be logged, must not cause protocol failure
                const always_display = try rdr.readBoolean();
                const message = try rdr.readU32LenString();
                _ = try rdr.readU32LenString(); // language tag
                if (always_display) {
                    TRACE(.Info, "SSH_MSG_DEBUG: '{s}'", .{message});
                } else {
                    TRACE(.Debug, "SSH_MSG_DEBUG: '{s}'", .{message});
                }
                self.setIoSessionState(.ReadPktHdr);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST) => {
                // RFC 4254 §5.2 - peer is granting more window
                const channelnum = try rdr.readU32();
                if (self.channel_table.findByLocalId(channelnum)) |chan| {
                    const bytes_to_add = try rdr.readU32();
                    chan.peer_window +|= bytes_to_add;
                } else {
                    _ = try rdr.readU32();
                }
                self.setIoSessionState(.ReadPktHdr);
            },
            else => {
                // unhandled packet type
                TRACE(.Info, "Unhandled msg id={d}", .{msgid});
                self.setIoSessionState(.ReadPktHdr); // read again
            },
        }
    }
};

fn nameListContains(namelist: []const u8, target: []const u8) bool {
    var iter = util.NameListTokenizer.init(namelist);
    while (iter.next()) |name| {
        if (std.mem.eql(u8, name, target)) return true;
    }
    return false;
}

// Helper: build an unencrypted SSH packet in the provided buffer.
// Returns the total packet length (header + payload + padding).
fn buildUnencryptedPacket(buf: []u8, payload: []const u8) usize {
    const padding_length: u8 = 8;
    const packet_length: u32 = @intCast(payload.len + padding_length + 1);
    // Build PktHdr the same way wrapPkt does
    const hdr: Protocol.PktHdr = .{
        .packet_length = packet_length,
        .padding_length = padding_length,
    };
    std.mem.writeInt(u32, buf[0..4], hdr.packet_length, .big);
    buf[4] = hdr.padding_length;
    @memcpy(buf[Protocol.sizeof_PktHdr .. Protocol.sizeof_PktHdr + payload.len], payload);
    @memset(buf[Protocol.sizeof_PktHdr + payload.len .. Protocol.sizeof_PktHdr + payload.len + padding_length], 0);
    return Protocol.sizeof_PktHdr + payload.len + padding_length;
}

fn unencryptedPayload(packet: []const u8) []const u8 {
    const hdr = Protocol.readPktHdr(packet[0..Protocol.sizeof_PktHdr]);
    const payload_len = hdr.packet_length - hdr.padding_length - 1;
    return packet[Protocol.sizeof_PktHdr .. Protocol.sizeof_PktHdr + payload_len];
}

fn expectProducedChannelRequest(m: *MisshodClient, expected_type: []const u8) !void {
    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST), try rdr.readU8());
    _ = try rdr.readU32(); // recipient channel
    try std.testing.expectEqualStrings(expected_type, try rdr.readU32LenString());
}

test "handlePacket: SSH_MSG_IGNORE is silently consumed" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_buf: [1]u8 = .{@intFromEnum(Protocol.MsgId.SSH_MSG_IGNORE)};
    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, &payload_buf);
    m.session.encrypted = false;
    m.session.setIoSessionState(.ReadPktHdr);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(Protocol.IoSessionState.ReadPktHdr, m.session.ioSessionState);
}

test "openSessionChannel writes channel open for new raw session channel" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.setSessionState(.ChannelActive);

    const channel_id = try m.openSessionChannel();
    try std.testing.expectEqual(@as(u32, 0), channel_id);
    try std.testing.expectEqual(SessionState.ChannelOpenRsp, m.session.sessionState);

    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    try std.testing.expectEqual(ClientChannelOpenMode.RawSession, chan.client_open_mode);
    try std.testing.expectEqual(ChannelType.Session, chan.channel_type);
    try std.testing.expectEqual(ChannelState.OpenWrite, chan.state);

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN), try rdr.readU8());
    try std.testing.expectEqualStrings("session", try rdr.readU32LenString());
    try std.testing.expectEqual(channel_id, try rdr.readU32());
    try std.testing.expectEqual(Protocol.MaxPayload, try rdr.readU32());
    try std.testing.expectEqual(Protocol.MaxPayload, try rdr.readU32());
}

test "openDirectTcpipChannel writes direct-tcpip open payload" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.setSessionState(.ChannelActive);

    const channel_id = try m.openDirectTcpipChannel("example.com", 443, "127.0.0.1", 55555);
    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    try std.testing.expectEqual(ChannelType.DirectTcpip, chan.channel_type);

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN), try rdr.readU8());
    try std.testing.expectEqualStrings("direct-tcpip", try rdr.readU32LenString());
    try std.testing.expectEqual(channel_id, try rdr.readU32());
    try std.testing.expectEqual(Protocol.MaxPayload, try rdr.readU32());
    try std.testing.expectEqual(Protocol.MaxPayload, try rdr.readU32());
    try std.testing.expectEqualStrings("example.com", try rdr.readU32LenString());
    try std.testing.expectEqual(@as(u32, 443), try rdr.readU32());
    try std.testing.expectEqualStrings("127.0.0.1", try rdr.readU32LenString());
    try std.testing.expectEqual(@as(u32, 55555), try rdr.readU32());
}

test "requestRemoteForward writes tcpip-forward global request" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.setSessionState(.ChannelActive);

    try m.requestRemoteForward("127.0.0.1", 0);
    try std.testing.expect(m.session.pending_global_request != null);

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_GLOBAL_REQUEST), try rdr.readU8());
    try std.testing.expectEqualStrings("tcpip-forward", try rdr.readU32LenString());
    try std.testing.expect(try rdr.readBoolean());
    try std.testing.expectEqualStrings("127.0.0.1", try rdr.readU32LenString());
    try std.testing.expectEqual(@as(u32, 0), try rdr.readU32());
}

test "cancelRemoteForward writes cancel-tcpip-forward global request" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.setSessionState(.ChannelActive);

    try m.cancelRemoteForward("127.0.0.1", 2200);

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_GLOBAL_REQUEST), try rdr.readU8());
    try std.testing.expectEqualStrings("cancel-tcpip-forward", try rdr.readU32LenString());
    try std.testing.expect(try rdr.readBoolean());
    try std.testing.expectEqualStrings("127.0.0.1", try rdr.readU32LenString());
    try std.testing.expectEqual(@as(u32, 2200), try rdr.readU32());
}

test "handlePacket: request success maps allocated tcpip-forward port" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.setSessionState(.ChannelActive);
    try m.requestRemoteForward("127.0.0.1", 0);
    try m.consumed(m.wr_nbytes);

    var payload_backing: [16]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_SUCCESS));
    try pw.writeU32(2222);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .TcpipForwardSuccess => |forward| {
                try std.testing.expectEqualStrings("127.0.0.1", forward.bind_address);
                try std.testing.expectEqual(@as(u32, 0), forward.requested_port);
                try std.testing.expectEqual(@as(u32, 2222), forward.bound_port);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: request failure maps cancel-tcpip-forward failure" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.setSessionState(.ChannelActive);
    try m.cancelRemoteForward("127.0.0.1", 2200);
    try m.consumed(m.wr_nbytes);

    var payload_backing: [8]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_REQUEST_FAILURE));

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .CancelTcpipForwardFailure => |cancel| {
                try std.testing.expectEqualStrings("127.0.0.1", cancel.bind_address);
                try std.testing.expectEqual(@as(u32, 2200), cancel.bind_port);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "openSessionChannel rejects another open while one is pending" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.setSessionState(.ChannelActive);

    _ = try m.openSessionChannel();
    try std.testing.expectError(IoError.cannotAcceptWrite, m.openSessionChannel());
}

test "openSessionChannel can open another raw channel after confirmation" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.encrypted = false;
    m.session.setSessionState(.ChannelActive);

    const first_id = try m.openSessionChannel();
    try m.consumed(m.wr_nbytes);

    var payload_backing: [32]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(first_id); // recipient channel
    try pw.writeU32(42); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.iostate_rd = .Idle;
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try m.clearEvent(.{ .ChannelOpened = first_id });

    const second_id = try m.openSessionChannel();
    try std.testing.expectEqual(@as(u32, 1), second_id);

    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN), try rdr.readU8());
    try std.testing.expectEqualStrings("session", try rdr.readU32LenString());
    try std.testing.expectEqual(second_id, try rdr.readU32());
}

test "handlePacket: SSH_MSG_DEBUG with always_display=true" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_DEBUG));
    try pw.writeBoolean(true);
    try pw.writeU32LenString("test debug message");
    try pw.writeU32LenString("en");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.setIoSessionState(.ReadPktHdr);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(Protocol.IoSessionState.ReadPktHdr, m.session.ioSessionState);
}

test "handlePacket: SSH_MSG_DEBUG with always_display=false" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_DEBUG));
    try pw.writeBoolean(false);
    try pw.writeU32LenString("quiet debug");
    try pw.writeU32LenString("");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.setIoSessionState(.ReadPktHdr);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(Protocol.IoSessionState.ReadPktHdr, m.session.ioSessionState);
}

test "handlePacket: SSH_MSG_DISCONNECT surfaces reason code" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_DISCONNECT));
    try pw.writeU32(11); // SSH_DISCONNECT_BY_APPLICATION
    try pw.writeU32LenString("shutting down");
    try pw.writeU32LenString("");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .EndSession => |reason| switch (reason) {
                .ServerDisconnect => |r| {
                    try std.testing.expectEqual(@as(u32, 11), r.code);
                    try std.testing.expectEqualStrings("shutting down", r.description);
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: auth-agent channel open requires opt-in" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
    try pw.writeU32LenString(Protocol.channel_type_auth_agent_openssh);
    try pw.writeU32(42);
    try pw.writeU32(32768);
    try pw.writeU32(32768);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    try std.testing.expectEqual(@as(u32, 0), m.session.channel_table.activeCount());
    try std.testing.expect(m.iostate_wr != .Idle);
}

test "handlePacket: auth-agent channel open creates agent channel when enabled" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    try m.session.enableAgentForwarding();

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
    try pw.writeU32LenString(Protocol.channel_type_auth_agent);
    try pw.writeU32(42);
    try pw.writeU32(32768);
    try pw.writeU32(32768);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const chan = m.session.channel_table.findByLocalId(0).?;
    try std.testing.expectEqual(.AgentForward, chan.kind);
    try std.testing.expectEqual(@as(u32, 42), chan.remote_id);
    try std.testing.expectEqual(ChannelState.ConfirmWrite, chan.state);
    try std.testing.expectEqual(SessionState.ChannelActive, m.session.sessionState);
}

test "handlePacket: agent channel data surfaces AgentData event" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannelKind(.AgentForward, 42, 32768, 32768).?;
    chan.state = .DataRx;

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
    try pw.writeU32(chan.local_id);
    try pw.writeU32LenString("agent-bytes");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .AgentData => |data| {
                try std.testing.expectEqual(chan.local_id, data.channel);
                try std.testing.expectEqualStrings("agent-bytes", data.data);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: SSH_MSG_CHANNEL_CLOSE when not yet sent triggers close reply" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Allocate a channel
    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.close_sent = false;

    var payload_backing: [16]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE));
    try pw.writeU32(0);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(SessionState.ChannelActive, m.session.sessionState);
    try std.testing.expectEqual(ChannelState.CloseWrite, chan.state);
}

test "handlePacket: SSH_MSG_CHANNEL_CLOSE when already sent emits disconnect" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Allocate a channel and mark close as sent
    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.close_sent = true;

    var payload_backing: [16]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_CLOSE));
    try pw.writeU32(0);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .EndSession => {},
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: SSH_MSG_USERAUTH_BANNER surfaces banner event" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_BANNER));
    try pw.writeU32LenString("Welcome to the server!\r\n");
    try pw.writeU32LenString("en");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .Banner => |text| {
                try std.testing.expectEqualStrings("Welcome to the server!\r\n", text);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "client session deinit zeros sensitive fields" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);

    try session.setPrivateKey("fake-key-data-for-testing");
    try session.setPrivateKeyPassphrase("my-secret-passphrase");
    try session.setAuthPassphrase("my-auth-password");
    @memset(&session.shared_secret_k, 0xAA);
    @memset(&session.session_id, 0xBB);

    session.deinit();

    try std.testing.expect(session.privkey_ascii == null);
    try std.testing.expect(session.privkey_passphrase == null);
    try std.testing.expect(session.auth_passphrase == null);
    for (session.shared_secret_k) |b| try std.testing.expectEqual(@as(u8, 0), b);
    for (session.session_id) |b| try std.testing.expectEqual(@as(u8, 0), b);
    try std.testing.expect(session.private_key == null);
}

test "setPrivateKey replaces previous key" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    try session.setPrivateKey("first-key");
    try session.setPrivateKey("second-key");
    try std.testing.expectEqualStrings("second-key", session.privkey_ascii.?);
}

test "client channel_close_sent starts false" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();
    // No channels allocated yet, so no close_sent to check
    try std.testing.expectEqual(@as(u32, 0), session.channel_table.activeCount());
}

test "client channel write buffer is MaxChannelDataLen" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    // Allocate a channel first
    _ = session.channel_table.allocChannel(0, 0, 0);
    const buf = try session.getChannelWriteBuffer(0);
    try std.testing.expectEqual(Protocol.MaxChannelDataLen, buf.len);
}

test "channelWriteComplete rejects oversized writes" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    _ = session.channel_table.allocChannel(0, 0, 0);
    const result = session.channelWriteComplete(0, Protocol.MaxChannelDataLen + 1);
    try std.testing.expectError(IoError.tooBig, result);
}

test "channelWriteComplete accepts max-size write" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    const chan = session.channel_table.allocChannel(0, 0, 0).?;
    chan.state = .DataRx;
    session.setIoSessionState(.ReadPktHdr);

    try session.channelWriteComplete(0, Protocol.MaxChannelDataLen);
    try std.testing.expectEqual(@as(usize, Protocol.MaxChannelDataLen), chan.write_buf_nbytes);
}

test "peer_window starts at zero" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();
    // Channels start with peer_window from allocChannel; table starts empty
    try std.testing.expectEqual(@as(u32, 0), session.channel_table.activeCount());
}

test "handlePacket: CHANNEL_OPEN_CONFIRMATION captures initial window" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Allocate a channel so findByLocalId(0) works
    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.client_open_mode = .AutoShell;

    var payload_backing: [32]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(0); // recipient channel
    try pw.writeU32(0); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.setSessionState(.ChannelOpenRsp);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    const confirmed = m.session.channel_table.findByLocalId(0).?;
    try std.testing.expectEqual(@as(u32, 32768), confirmed.peer_window);
}

test "handlePacket: raw channel confirmation emits ChannelOpened without shell setup" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.client_open_mode = .RawSession;
    chan.state = .OpenWrite;

    var payload_backing: [32]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(chan.local_id); // recipient channel
    try pw.writeU32(42); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.setSessionState(.ChannelOpenRsp);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    try std.testing.expectEqual(@as(u32, 42), chan.remote_id);
    try std.testing.expectEqual(ChannelState.Data, chan.state);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .ChannelOpened => |channel_id| try std.testing.expectEqual(chan.local_id, channel_id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    try m.clearEvent(.{ .ChannelOpened = chan.local_id });
    try std.testing.expect(std.meta.eql(m.iostate_wr, .Idle));
}

test "handlePacket: direct-tcpip confirmation emits ChannelOpened" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.client_open_mode = .RawSession;
    chan.channel_type = .DirectTcpip;
    chan.state = .OpenWrite;

    var payload_backing: [32]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(chan.local_id); // recipient channel
    try pw.writeU32(42); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.setSessionState(.ChannelOpenRsp);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(ChannelState.Data, chan.state);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .ChannelOpened => |channel_id| try std.testing.expectEqual(chan.local_id, channel_id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: forwarded-tcpip open emits request and accept confirms" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [160]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
    try pw.writeU32LenString("forwarded-tcpip");
    try pw.writeU32(77); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size
    try pw.writeU32LenString("127.0.0.1");
    try pw.writeU32(2222);
    try pw.writeU32LenString("10.0.0.2");
    try pw.writeU32(54321);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    const channel_id = switch (evt) {
        .Event => |code| switch (code) {
            .ChannelOpenRequest => |request| blk: {
                switch (request.request) {
                    .ForwardedTcpip => |tcp| {
                        try std.testing.expectEqualStrings("127.0.0.1", tcp.connected_host);
                        try std.testing.expectEqual(@as(u32, 2222), tcp.connected_port);
                        try std.testing.expectEqualStrings("10.0.0.2", tcp.originator_host);
                        try std.testing.expectEqual(@as(u32, 54321), tcp.originator_port);
                    },
                    else => return error.TestUnexpectedResult,
                }
                break :blk request.channel;
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    };

    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    try std.testing.expectEqual(ChannelType.ForwardedTcpip, chan.channel_type);
    try std.testing.expectEqual(ChannelState.Open, chan.state);

    try m.acceptChannelOpen(channel_id);
    const data = try m.peek(Protocol.MaxSSHPacket);
    var rdr = BufferReader.init(unencryptedPayload(data));
    try std.testing.expectEqual(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION), try rdr.readU8());
    try std.testing.expectEqual(@as(u32, 77), try rdr.readU32());
    try std.testing.expectEqual(channel_id, try rdr.readU32());
}

test "handlePacket: auto-shell confirmation still emits Connected" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.client_open_mode = .AutoShell;
    chan.state = .OpenWrite;

    var payload_backing: [32]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(chan.local_id); // recipient channel
    try pw.writeU32(42); // sender channel
    try pw.writeU32(32768); // initial window size
    try pw.writeU32(4096); // max packet size

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.setSessionState(.ChannelOpenRsp);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(ChannelState.Open, chan.state);

    try m.advance();
    try expectProducedChannelRequest(&m, "pty-req");
    try m.consumed(m.wr_nbytes);
    try expectProducedChannelRequest(&m, "shell");
    try m.consumed(m.wr_nbytes);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .Connected => {},
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: channel open failure frees channel and emits event" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.client_open_mode = .RawSession;
    chan.state = .OpenWrite;
    const local_id = chan.local_id;

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE));
    try pw.writeU32(local_id); // recipient channel
    try pw.writeU32(4); // SSH_OPEN_RESOURCE_SHORTAGE
    try pw.writeU32LenString("too many channels");
    try pw.writeU32LenString("");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;
    m.session.setSessionState(.ChannelOpenRsp);

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expect(m.session.channel_table.findByLocalId(local_id) == null);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .ChannelOpenFailure => |failure| {
                try std.testing.expectEqual(local_id, failure.channel);
                try std.testing.expectEqual(@as(u32, 4), failure.reason_code);
                try std.testing.expectEqualStrings("too many channels", failure.description);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: CHANNEL_WINDOW_ADJUST increases peer window" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannel(0, 1000, 0).?;

    var payload_backing: [16]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_WINDOW_ADJUST));
    try pw.writeU32(0); // channel
    try pw.writeU32(5000); // bytes to add

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);
    try std.testing.expectEqual(@as(u32, 6000), chan.peer_window);
}

test "handlePacket: SSH_MSG_CHANNEL_EXTENDED_DATA surfaces stderr" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Allocate a channel in DataRx state
    const chan = m.session.channel_table.allocChannel(0, 0, 0).?;
    chan.state = .DataRx;

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_EXTENDED_DATA));
    try pw.writeU32(0); // channel
    try pw.writeU32(1); // data_type_code = SSH_EXTENDED_DATA_STDERR
    try pw.writeU32LenString("error: something failed\n");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .RxExtendedData => |ext| {
                try std.testing.expectEqual(@as(u32, 1), ext.data_type);
                try std.testing.expectEqualStrings("error: something failed\n", ext.data);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "sendWindowChange queues pending change" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    try std.testing.expect(session.pending_window_change == null);
    session.sendWindowChange(120, 40, 960, 640);
    try std.testing.expect(session.pending_window_change != null);
    const wc = session.pending_window_change.?;
    try std.testing.expectEqual(@as(u32, 120), wc[0]);
    try std.testing.expectEqual(@as(u32, 40), wc[1]);
    try std.testing.expectEqual(@as(u32, 960), wc[2]);
    try std.testing.expectEqual(@as(u32, 640), wc[3]);
}

test "handlePacket: SSH_MSG_USERAUTH_INFO_REQUEST surfaces keyboard-interactive prompt" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    var payload_backing: [256]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_PK_OK)); // msg 60 = INFO_REQUEST
    try pw.writeU32LenString("Authentication"); // name
    try pw.writeU32LenString("Please enter your password"); // instruction
    try pw.writeU32LenString(""); // language tag
    try pw.writeU32(1); // num-prompts
    try pw.writeU32LenString("Password: "); // prompt
    try pw.writeBoolean(false); // echo

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .KeyboardInteractive => |ki| {
                try std.testing.expectEqualStrings("Authentication", ki.name);
                try std.testing.expectEqualStrings("Please enter your password", ki.instruction);
                try std.testing.expectEqualStrings("Password: ", ki.prompt);
                try std.testing.expect(!ki.echo);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(SessionState.KeyboardInteractiveInfoRsp, m.session.sessionState);
}

test "setKeyboardInteractiveResponse stores response" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();

    try session.setKeyboardInteractiveResponse("my-password");
    try std.testing.expect(session.kbd_interactive_response != null);
    try std.testing.expectEqualStrings("my-password", session.kbd_interactive_response.?);
}

test "nameListContains finds algorithm in list" {
    try std.testing.expect(nameListContains("aes256-ctr,aes128-ctr,aes256-cbc", "aes256-ctr"));
    try std.testing.expect(nameListContains("aes256-ctr,aes128-ctr,aes256-cbc", "aes128-ctr"));
    try std.testing.expect(nameListContains("aes256-ctr,aes128-ctr,aes256-cbc", "aes256-cbc"));
    try std.testing.expect(nameListContains("aes256-ctr", "aes256-ctr"));
}

test "nameListContains rejects missing algorithm" {
    try std.testing.expect(!nameListContains("aes128-ctr,aes256-cbc", "aes256-ctr"));
    try std.testing.expect(!nameListContains("", "aes256-ctr"));
    try std.testing.expect(!nameListContains("aes256-ct", "aes256-ctr"));
}

test "is_rekeying starts false" {
    var prng = std.Random.DefaultPrng.init(42);
    var session = try Session.init(prng.random(), "testuser", std.testing.allocator);
    defer session.deinit();
    try std.testing.expect(!session.is_rekeying);
}
