const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const MisshodServer = @import("misshod.zig").MisshodServer;
const MisshodError = @import("misshod.zig").MisshodError;
const IoError = @import("misshod.zig").IoError;
const native_endian = @import("builtin").target.cpu.arch.endian();
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

pub const SessionState = enum {
    Init,
    KexInitWrite,
    KexInitRead,
    EcdhInitRead,
    EcdhReplyWrite,
    NewKeysRead,
    NewKeysWrite,
    AuthRead,
    AuthRspServReqSuccess,
    CheckUserPasswordAuth,
    UserPasswordAuthDenied,
    UserAuthAccepted,
    AuthPkAllowed,
    Authenticated,
    ChannelActive,
};

pub const Session = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    ioSessionState: Protocol.IoSessionState,
    sessionState: SessionState,

    ecdh_ephem_keypair: Protocol.kex_algo.KeyPair = undefined,
    shared_secret_k: [Protocol.kex_algo.shared_length]u8 = undefined, // K
    kex_hasher: Hasher(Protocol.hash_algo) = undefined, // for building H
    kex_hash_order: Protocol.KexHashOrder = .Init,
    selected_hostkey_algorithm: ?Key.SignatureAlgorithm,
    session_id: [Protocol.hash_algo.digest_length]u8 = undefined,
    keydata: Protocol.KeyDataBi,
    rand: std.Random = undefined,
    encrypted: bool,
    channel_table: ChannelTable,
    active_channel_id: ?u32,
    is_rekeying: bool,

    privkey_ascii: ?[]u8, // allocated
    privkey_passphrase: ?[]u8, //allocated
    auth_passphrase: ?[]u8, //allocated

    auth_pubkey_attempted: Key.Blob,
    auth_pubkey_algorithm: ?Key.SignatureAlgorithm,
    q_c:[Protocol.kex_algo.public_length]u8 = undefined,

    host_private_key: Key.PrivateKey,

    pub fn init(rand: std.Random, hostkey_ascii: []const u8, allocator: std.mem.Allocator) !Self {
        var s = Self {
            .ioSessionState = .Init,
            .sessionState = .Init,
            .rand = rand,
            .allocator = allocator,
            .encrypted = false,
            .keydata = Protocol.KeyDataBi.init(),
            .kex_hasher = Hasher(Protocol.hash_algo).init(), // for hashing H
            .selected_hostkey_algorithm = null,
            .privkey_ascii = null,
            .privkey_passphrase = null,
            .auth_passphrase = null,
            .auth_pubkey_attempted = .{},
            .auth_pubkey_algorithm = null,
            .host_private_key = undefined,
            .channel_table = ChannelTable{},
            .active_channel_id = null,
            .is_rekeying = false,
        };

        s.host_private_key = try decodeOpenSshPrivateKey(hostkey_ascii, null);

        return s;
    }

    pub fn deinit(self: *Self) void {
        self.clearAndFreeOptional(&self.privkey_ascii);
        self.clearAndFreeOptional(&self.privkey_passphrase);
        self.clearAndFreeOptional(&self.auth_passphrase);
        std.crypto.secureZero(u8, &self.shared_secret_k);
        std.crypto.secureZero(u8, &self.session_id);
        self.host_private_key.clear();
        self.auth_pubkey_attempted.clear();
        self.auth_pubkey_algorithm = null;
        std.crypto.secureZero(u8, &self.q_c);
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

    pub fn grantAccess(self: *Self, allow:bool) MisshodError!void {
        if (self.sessionState != .CheckUserPasswordAuth) {
            return IoError.UnexpectedResponse;
        } else {
            if (allow) {
                self.setSessionState(.UserAuthAccepted);
            } else {
                self.setSessionState(.UserPasswordAuthDenied);
            }
        }
    }

    pub fn advanceSession(self: *Self, misshod: *MisshodServer) MisshodError!void {
        const outkeys = &self.keydata.s2c;

        switch (self.sessionState) {
            .Init => {
                self.setSessionState(.KexInitRead);
            },
            .KexInitRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .KexInitWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT));
                var cookie: [16]u8 = undefined;
                self.rand.bytes(&cookie);
                try pkt.writeBytes(&cookie);

                try pkt.writeU32LenString(Protocol.kex_algo_name); // kex
                try pkt.writeU32LenString(self.host_private_key.hostKeyAlgorithms()); // hostkey verification
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

                self.kex_hash_order = self.kex_hash_order.check(.I_S);
                self.kex_hasher.writeU32LenString(pkt.active());

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                self.setSessionState(.EcdhInitRead);
            },
            .EcdhInitRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .EcdhReplyWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);

                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_REPLY));

                var hostkey_blob_buf: Key.Blob = .{};
                const hostkey_blob = try self.host_private_key.publicBlob(&hostkey_blob_buf);

                TRACEDUMP(.Debug, "ks", .{}, hostkey_blob);
                self.kex_hash_order = self.kex_hash_order.check(.K_S);
                self.kex_hasher.writeU32LenString(hostkey_blob);
                try pkt.writeU32LenString(hostkey_blob);

                self.kex_hash_order = self.kex_hash_order.check(.Q_C);
                self.kex_hasher.writeU32LenString(&self.q_c);

                var seed: [Protocol.kex_algo.seed_length]u8 = undefined;
                self.rand.bytes(&seed);
                self.ecdh_ephem_keypair = Protocol.kex_algo.KeyPair.generateDeterministic(seed) catch unreachable;
                try pkt.writeU32LenString(&self.ecdh_ephem_keypair.public_key);
                TRACEDUMP(.Debug, "qs", .{}, &self.ecdh_ephem_keypair.public_key);

                self.kex_hash_order = self.kex_hash_order.check(.Q_S);
                self.kex_hasher.writeU32LenString(&self.ecdh_ephem_keypair.public_key);

                // generate shared secret
                @memcpy(&self.shared_secret_k, &try Protocol.kex_algo.scalarmult(self.ecdh_ephem_keypair.secret_key, self.q_c));

                TRACEDUMP(.Debug, "shared secret len={d}", .{self.shared_secret_k.len}, &self.shared_secret_k);

                self.kex_hash_order = self.kex_hash_order.check(.K);
                self.kex_hasher.writeMpint(&self.shared_secret_k);

                // Produce H/session_id/key exchange hash
                // Both sides now have this
                var kexhash: [Protocol.hash_algo.digest_length]u8 = undefined; // session_id, H
                self.kex_hasher.final(&kexhash, null);
                TRACEDUMP(.Debug, "kexhash: (len={d})", .{kexhash.len}, &kexhash);

                @memcpy(&self.session_id, &kexhash); // store as session_id

                const sig_alg = self.selected_hostkey_algorithm orelse self.host_private_key.defaultSignatureAlgorithm();
                var typed_sig: Key.SignatureBlob = .{};
                const sig = try self.host_private_key.sign(sig_alg, &kexhash, &typed_sig);
                try pkt.writeU32LenString(sig);

                // generate keys
                try self.keydata.genKeys(kexhash, self.shared_secret_k, self.session_id);

                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);

                self.setSessionState(.NewKeysWrite);
            },
            .NewKeysWrite => {
                // https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS));
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                self.setSessionState(.NewKeysRead);

            },
            .NewKeysRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .AuthRead => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .AuthRspServReqSuccess => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_SERVICE_ACCEPT));
                try pkt.writeU32LenString("ssh-userauth");
                self.setSessionState(.AuthRead);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
            },
            .CheckUserPasswordAuth => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .UserPasswordAuthDenied => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_FAILURE));
                try pkt.writeU32LenString("password,publickey");
                try pkt.writeBoolean(false);    // partial success
                self.setSessionState(.AuthRead);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
            },
            .UserAuthAccepted => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_SUCCESS));
                self.setSessionState(.Authenticated);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
            },
            .AuthPkAllowed => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_PK_OK));
                const auth_alg = self.auth_pubkey_algorithm orelse return IoError.UnexpectedResponse;
                try pkt.writeU32LenString(auth_alg.name());
                try pkt.writeU32LenString(self.auth_pubkey_attempted.slice());
                self.setSessionState(.AuthRead);
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
            },
            .Authenticated => {
                self.setIoSessionState(.ReadPktHdr);
            },
            .ChannelActive => {
                try self.advanceChannel(misshod, outkeys);
            },
        }
    }

    fn advanceChannel(self: *Self, misshod: *MisshodServer, outkeys: *Protocol.KeyDataUni) MisshodError!void {
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
            .ConfirmWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
                try pkt.writeU32(chan.remote_id);
                try pkt.writeU32(chan.local_id);
                try pkt.writeU32(Protocol.MaxPayload);
                try pkt.writeU32(Protocol.MaxPayload);
                chan.state = .Connected;
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
            },
            .OpenFailureWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE));
                try pkt.writeU32(chan.remote_id);
                try pkt.writeU32(4); // SSH_OPEN_RESOURCE_SHORTAGE
                try pkt.writeU32LenString("too many channels");
                try pkt.writeU32LenString("");
                self.channel_table.freeChannel(chan.local_id);
                self.active_channel_id = null;
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
            },
            .RspWrite => {
                var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_SUCCESS));
                try pkt.writeU32(chan.remote_id);
                chan.state = .Data;
                misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
            },
            .Connected => {
                misshod.requestEvent(.{ .Connected = chan.local_id }, .Idle);
                chan.state = .Data;
            },
            .Data => {
                if (chan.write_buf_nbytes > 0) {
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
                // RFC 4254 §5.3 — send EOF to signal no more data from us
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
                    misshod.requestEvent(.{ .AgentChannelClosed = local_id }, .ReadPktHdr);
                } else if (self.channel_table.activeCount() == 0) {
                    misshod.requestEvent(.{ .EndSession = .Disconnect }, .Idle);
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            .Open => {
                if (chan.kind == .AgentForward) {
                    var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                    try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN));
                    try pkt.writeU32LenString(Protocol.channel_type_auth_agent_openssh);
                    try pkt.writeU32(chan.local_id);
                    try pkt.writeU32(Protocol.MaxPayload);
                    try pkt.writeU32(Protocol.MaxPayload);
                    chan.state = .OpenSent;
                    misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .ReadPktHdr);
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            .OpenSent => {
                self.setIoSessionState(.ReadPktHdr);
            },
        }
    }

    pub fn getChannelWriteBuffer(self: *Self, channel_id: u32) MisshodError![]u8 {
        if (self.channel_table.findByLocalId(channel_id)) |chan| {
            if (chan.eof_sent) return &.{};
            if (chan.write_buf_nbytes > 0 and self.ioSessionState == .Idle) {
                return &.{};
            } else {
                return &chan.write_buf;
            }
        }
        return &.{};
    }

    pub fn channelWriteComplete(self: *Self, channel_id: u32, nbytes: usize) MisshodError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.eof_sent) return IoError.UnexpectedResponse;
        if (nbytes > chan.write_buf.len) {
            return IoError.tooBig;
        }
        chan.write_buf_nbytes = nbytes;
        self.active_channel_id = channel_id;
        chan.state = .Data;
        self.setSessionState(.ChannelActive);
        self.setIoSessionState(.Idle);
    }

    // Full-duplex: build and send channel data packet directly without going through state machine
    pub fn directChannelWrite(self: *Self, channel_id: u32, nbytes: usize, misshod: *MisshodServer) MisshodError!void {
        const chan = self.channel_table.findByLocalId(channel_id) orelse return IoError.UnexpectedResponse;
        if (chan.eof_sent) return IoError.UnexpectedResponse;
        if (nbytes > chan.write_buf.len) {
            return IoError.tooBig;
        }
        chan.write_buf_nbytes = nbytes;
        const outkeys = &self.keydata.s2c;
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

    pub fn openAgentChannel(self: *Self) MisshodError!u32 {
        const chan = self.channel_table.allocChannelKind(.AgentForward, 0, 0, 0) orelse return IoError.UnexpectedResponse;
        chan.state = .Open;
        self.active_channel_id = chan.local_id;
        self.setSessionState(.ChannelActive);
        self.setIoSessionState(.Idle);
        return chan.local_id;
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
        self.kex_hash_order = self.kex_hash_order.check(.V_S);
        self.kex_hasher.writeU32LenString(Protocol.version);
        return vers;
    }

    pub fn handlePacket(self: *Self, buf: []const u8, misshod: *MisshodServer) MisshodError!void {
        var rdr = try misshod.getRecvBuffer(misshod.iobuf_rd[0..buf.len], &self.keydata.c2s);

        const msgid = try rdr.readU8();

        TRACE(.Debug, "handlePacket msgId={d}", .{msgid});
        TRACEDUMP(.Debug, "handlePacket", .{}, buf);

        switch (msgid) {
            @intFromEnum(Protocol.MsgId.SSH_MSG_KEXINIT) => {
                TRACE(.Debug, "{any}", .{@as(Protocol.MsgId, @enumFromInt(msgid))});

                const is_rekey = self.sessionState != .KexInitRead;
                if (is_rekey) {
                    if (self.sessionState != .ChannelActive)
                    {
                        self.setIoSessionState(.ReadPktHdr);
                        return;
                    }
                    TRACE(.Info, "Re-keying initiated by peer", .{});
                    self.kex_hasher = Hasher(Protocol.hash_algo).init();
                    self.kex_hash_order = .Init;
                    self.kex_hash_order = self.kex_hash_order.check(.V_C);
                    self.kex_hasher.writeU32LenString(Protocol.version);
                    self.kex_hash_order = self.kex_hash_order.check(.V_S);
                    self.kex_hasher.writeU32LenString(Protocol.version);
                    self.is_rekeying = true;
                }

                self.kex_hash_order = self.kex_hash_order.check(.I_C);
                self.kex_hasher.writeU32LenString(rdr.payload[(rdr.off - 1)..]); // from before the msgid

                // https://datatracker.ietf.org/doc/html/rfc4253#section-7.1
                // https://datatracker.ietf.org/doc/html/rfc4251#section-5
                const cookie = try rdr.readBytes(16);
                TRACEDUMP(.Debug, "cookie", .{}, cookie);

                const kex_namelist = try rdr.readU32LenString();
                if (!nameListContains(kex_namelist, Protocol.kex_algo_name)) {
                    TRACE(.Info, "No mutual algorithm for kex_algorithms: peer offers '{s}', we need '{s}'", .{ kex_namelist, Protocol.kex_algo_name });
                    return IoError.AlgorithmNegotiationFailed;
                }
                const hostkey_namelist = try rdr.readU32LenString();
                self.selected_hostkey_algorithm = Key.selectHostKeyAlgorithm(hostkey_namelist, &self.host_private_key) orelse {
                    TRACE(.Info, "No mutual algorithm for server_host_key_algorithms: peer offers '{s}', we can use '{s}'", .{ hostkey_namelist, self.host_private_key.hostKeyAlgorithms() });
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

                // skip remaining lists (compression, languages)
                for (0..4) |_| {
                    _ = try rdr.readU32LenString();
                }

                const first_kex_packet_follows = try rdr.readBoolean();
                TRACE(.Debug, "first_kex_packet_follows = {any}\n", .{first_kex_packet_follows});
                _ = try rdr.readU32(); // reserved, ignore

                if (self.sessionState == .KexInitRead or is_rekey) {
                    self.setSessionState(.KexInitWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_KEX_ECDH_INIT) => {
                if (self.sessionState == .EcdhInitRead) {
                    const q_c = try rdr.readU32LenString();
                    if (q_c.len != Protocol.kex_algo.public_length) {
                        // client may have sent a hopeful q_c for wrong algo
                        // go read another packet
                        self.setIoSessionState(.ReadPktHdr);
                        return;
                    }
                    TRACEDUMP(.Debug, "q_c", .{}, q_c);
                    @memcpy(&self.q_c, q_c);

                    self.setSessionState(.EcdhReplyWrite);
                    self.setIoSessionState(.Idle);
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_NEWKEYS) => {
                if (self.sessionState == .NewKeysRead) {
                    self.encrypted = true;
                    if (self.is_rekeying) {
                        self.is_rekeying = false;
                        self.setSessionState(.ChannelActive);
                        self.setIoSessionState(.Idle);
                    } else {
                        self.setSessionState(.AuthRead);
                        self.setIoSessionState(.ReadPktHdr);
                    }
                } else {
                    return IoError.UnexpectedResponse;
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_SERVICE_REQUEST) => {
                if (self.sessionState == .AuthRead) {
                    const svcname = try rdr.readU32LenString();
                    if (std.mem.eql(u8, svcname, "ssh-userauth")) {
                        self.setSessionState(.AuthRspServReqSuccess);
                        self.setIoSessionState(.Idle);
                    } else {
                        return IoError.UnimplementedService;
                    }
                } else {
                    return IoError.UnexpectedResponse;  // why is client asking now?
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST) => {
                if (self.sessionState == .AuthRead) {
                    //https://datatracker.ietf.org/doc/html/rfc4252#section-5.1
                    //https://datatracker.ietf.org/doc/html/rfc4252#section-8
                    const username = try rdr.readU32LenString();
                    const svcname = try rdr.readU32LenString();
                    const authtyp = try rdr.readU32LenString();

                    TRACE(.Debug, "username={s} svcname={s} authtyp={s}", .{username, svcname, authtyp});
                    if (!std.mem.eql(u8, svcname, "ssh-connection")) {
                        return IoError.UnimplementedService;
                    }

                    if (std.mem.eql(u8, authtyp, "password")) {
                        const b = try rdr.readBoolean();
                        if (b != false) {
                            return IoError.UnexpectedResponse;
                        }
                        const password = try rdr.readU32LenString();
                        self.setSessionState(.CheckUserPasswordAuth);
                        misshod.requestEvent(.{ .UserAuth = .{
                            .username = username,
                            .auth = .{.Password = password},
                        } }, .Idle);
                    } else if (std.mem.eql(u8, authtyp, "publickey")) {
                        const forreal = try rdr.readBoolean();
                        const algoname = try rdr.readU32LenString();
                        const typed_pubkey = try rdr.readU32LenString();

                        TRACE(.Debug, "forreal={any} algoname={s} typed_pubkey len={d}", .{forreal, algoname, typed_pubkey.len});

                        const auth_alg = Key.SignatureAlgorithm.fromName(algoname) orelse {
                            self.setSessionState(.UserPasswordAuthDenied);
                            self.setIoSessionState(.Idle);
                            return;
                        };
                        const pubkey = Key.parsePublicKeyBlob(typed_pubkey) catch {
                            self.setSessionState(.UserPasswordAuthDenied);
                            self.setIoSessionState(.Idle);
                            return;
                        };
                        if (auth_alg.keyAlgorithm() != pubkey.algorithm()) {
                            self.setSessionState(.UserPasswordAuthDenied);
                            self.setIoSessionState(.Idle);
                            return;
                        }
                        try self.auth_pubkey_attempted.set(typed_pubkey);
                        self.auth_pubkey_algorithm = auth_alg;

                        if (!forreal) {
                            self.setSessionState(.AuthPkAllowed);
                            self.setIoSessionState(.Idle);
                        } else {
                            const typedsig = try rdr.readU32LenString();
                            const sig_alg = Key.signatureAlgorithm(typedsig) catch {
                                self.setSessionState(.UserPasswordAuthDenied);
                                self.setIoSessionState(.Idle);
                                return;
                            };
                            if (sig_alg != auth_alg) {
                                self.setSessionState(.UserPasswordAuthDenied);
                                self.setIoSessionState(.Idle);
                                return;
                            }

                            var backing_sigbuffer_buf: [1024]u8 = undefined;
                            var sigbuffer = BufferWriter.init(&backing_sigbuffer_buf, 0);
                            try sigbuffer.writeU32LenString(&self.session_id);
                            try sigbuffer.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_USERAUTH_REQUEST));
                            try sigbuffer.writeU32LenString(username);
                            try sigbuffer.writeU32LenString("ssh-connection");
                            try sigbuffer.writeU32LenString("publickey");
                            try sigbuffer.writeBoolean(true);
                            try sigbuffer.writeU32LenString(algoname);
                            try sigbuffer.writeU32LenString(typed_pubkey);

                            TRACEDUMP(.Debug, "typed_pubkey", .{}, typed_pubkey);

                            // verify sig, as provided by user
                            Key.verifySignature(pubkey, typedsig, sigbuffer.payload) catch {
                                TRACE(.Info, "pubkey sig verify failed", .{});
                                self.setSessionState(.UserPasswordAuthDenied);
                                self.setIoSessionState(.Idle);
                                return;
                            };

                            // sig verify ok, confirm with app that this username+pubkey is allowed
                            self.setSessionState(.CheckUserPasswordAuth);
                            misshod.requestEvent(.{ .UserAuth = .{
                                .username = username,
                                .auth = .{ .Pubkey = .{ .algorithm = algoname, .blob = typed_pubkey } },
                            } }, .Idle);
                        }
                    } else if (std.mem.eql(u8, authtyp, "none")) {
                        self.setSessionState(.CheckUserPasswordAuth);
                        misshod.requestEvent(.{ .UserAuth = .{
                            .username = username,
                            .auth = null
                        } }, .Idle);
                    } else if (std.mem.eql(u8, authtyp, "keyboard-interactive")) {
                        // RFC 4256 §3.1
                        _ = try rdr.readU32LenString(); // language tag
                        const submethods = try rdr.readU32LenString();
                        self.setSessionState(.CheckUserPasswordAuth);
                        misshod.requestEvent(.{ .UserAuth = .{
                            .username = username,
                            .auth = .{ .KeyboardInteractive = submethods },
                        } }, .Idle);
                    } else {
                        return IoError.UnimplementedService;
                    }
                } else {
                    return IoError.UnexpectedResponse;  // why is client asking now?
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN) => {
                // https://datatracker.ietf.org/doc/html/rfc4254#section-5.1
                const chantype = try rdr.readU32LenString();
                const remote_id = try rdr.readU32();
                const peer_window = try rdr.readU32();
                const max_packet_size = try rdr.readU32();

                if (!std.mem.eql(u8, chantype, Protocol.channel_type_session)) {
                    return IoError.UnimplementedService;
                }

                if (self.channel_table.allocChannelKind(.Session, remote_id, peer_window, max_packet_size)) |chan| {
                    chan.state = .ConfirmWrite;
                    self.active_channel_id = chan.local_id;
                } else {
                    var pkt = BufferWriter.init(&misshod.iobuf_wr, Protocol.sizeof_PktHdr);
                    try pkt.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE));
                    try pkt.writeU32(remote_id);
                    try pkt.writeU32(4);
                    try pkt.writeU32LenString("too many channels");
                    try pkt.writeU32LenString("");
                    const outkeys = &self.keydata.s2c;
                    misshod.requestWrite(try Protocol.wrapPkt(&self.rand, self.encrypted, outkeys, &pkt, &misshod.iobuf_wr), .Idle);
                    return;
                }

                self.setSessionState(.ChannelActive);
                self.setIoSessionState(.Idle);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION) => {
                const recipient = try rdr.readU32();
                const sender = try rdr.readU32();
                const peer_window = try rdr.readU32();
                const max_packet_size = try rdr.readU32();
                if (self.channel_table.findByLocalId(recipient)) |chan| {
                    if (chan.kind != .AgentForward or chan.state != .OpenSent) {
                        return IoError.UnexpectedResponse;
                    }
                    chan.remote_id = sender;
                    chan.peer_window = peer_window;
                    chan.remote_max_packet_size = max_packet_size;
                    chan.state = .Data;
                    self.active_channel_id = null;
                    self.setSessionState(.ChannelActive);
                    misshod.requestEvent(.{ .AgentChannelOpen = chan.local_id }, .ReadPktHdr);
                } else {
                    self.setIoSessionState(.ReadPktHdr);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE) => {
                const recipient = try rdr.readU32();
                _ = try rdr.readU32(); // reason code
                _ = try rdr.readU32LenString(); // description
                _ = try rdr.readU32LenString(); // language tag
                if (self.channel_table.findByLocalId(recipient)) |chan| {
                    if (chan.kind == .AgentForward and chan.state == .OpenSent) {
                        const local_id = chan.local_id;
                        self.channel_table.freeChannel(chan.local_id);
                        self.active_channel_id = null;
                        misshod.requestEvent(.{ .AgentChannelClosed = local_id }, .ReadPktHdr);
                        return;
                    }
                }
                self.active_channel_id = null;
                self.setIoSessionState(.ReadPktHdr);
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST) => {
                // https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
                const recipient = try rdr.readU32();
                const chan = self.channel_table.findByLocalId(recipient) orelse {
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                };
                const typ = try rdr.readU32LenString();
                const wantreply = try rdr.readBoolean();
                if (std.mem.eql(u8, typ, "pty-req")) {
                    const term = try rdr.readU32LenString();
                    const cols = try rdr.readU32();
                    const rows = try rdr.readU32();
                    const widthpx = try rdr.readU32();
                    const heightpx = try rdr.readU32();

                    _ = term;
                    _ = cols;
                    _ = rows;
                    _ = widthpx;
                    _ = heightpx;
                } else if (std.mem.eql(u8, typ, "shell")) {
                    // RFC 4254 §6.5 — interactive shell
                    misshod.requestEvent(.{ .ChannelRequest = .{ .channel = chan.local_id, .request = .Shell } }, .Idle);
                    if (!wantreply) return;
                } else if (std.mem.eql(u8, typ, "exec")) {
                    // RFC 4254 §6.5 — single command execution
                    const command = try rdr.readU32LenString();
                    misshod.requestEvent(.{ .ChannelRequest = .{ .channel = chan.local_id, .request = .{ .Exec = command } } }, .Idle);
                    if (!wantreply) return;
                } else if (std.mem.eql(u8, typ, "subsystem")) {
                    // RFC 4254 §6.5 — named subsystem (e.g. sftp)
                    const subsystem = try rdr.readU32LenString();
                    misshod.requestEvent(.{ .ChannelRequest = .{ .channel = chan.local_id, .request = .{ .Subsystem = subsystem } } }, .Idle);
                    if (!wantreply) return;
                } else if (std.mem.eql(u8, typ, "env")) {
                    // RFC 4254 §6.4 — set environment variable
                    const name = try rdr.readU32LenString();
                    const value = try rdr.readU32LenString();
                    misshod.requestEvent(.{ .ChannelRequest = .{ .channel = chan.local_id, .request = .{ .Env = .{ .name = name, .value = value } } } }, .Idle);
                    if (!wantreply) return;
                } else if (std.mem.eql(u8, typ, Protocol.channel_request_auth_agent)) {
                    misshod.requestEvent(.{ .ChannelRequest = .{ .channel = chan.local_id, .request = .AgentForward } }, .Idle);
                    if (!wantreply) return;
                } else if (std.mem.eql(u8, typ, "window-change")) {
                    // RFC 4254 §6.7
                    const cols = try rdr.readU32();
                    const rows = try rdr.readU32();
                    const widthpx = try rdr.readU32();
                    const heightpx = try rdr.readU32();
                    misshod.requestEvent(.{ .WindowChange = .{
                        .channel = chan.local_id,
                        .cols = cols,
                        .rows = rows,
                        .width_px = widthpx,
                        .height_px = heightpx,
                    } }, .Idle);
                    return;
                } else if (std.mem.eql(u8, typ, "signal")) {
                    // RFC 4254 §6.9
                    const signal_name = try rdr.readU32LenString();
                    misshod.requestEvent(.{ .Signal = .{ .channel = chan.local_id, .name = signal_name } }, .Idle);
                    return;
                } else {
                    TRACE(.Debug, "channel req '{s}'", .{typ});
                    if (wantreply) {    // can't do this
                        return IoError.UnimplementedService;
                    }
                }

                if (wantreply) {
                    self.active_channel_id = chan.local_id;
                    chan.state = .RspWrite;
                    self.setSessionState(.ChannelActive);
                    self.setIoSessionState(.Idle);
                } else {
                    chan.state = .Data;
                    self.setSessionState(.ChannelActive);
                    self.setIoSessionState(.Idle);
                }
            },
            @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA) => {
                const channelnum = try rdr.readU32();
                const chan = self.channel_table.findByLocalId(channelnum) orelse {
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                };
                if (chan.eof_received) {
                    // Peer sent EOF then data — protocol violation, silently discard
                    TRACE(.Debug, "discarding data after EOF on channel {d}", .{channelnum});
                    self.setIoSessionState(.ReadPktHdr);
                    return;
                }
                if (chan.state != .DataRx) {
                    return IoError.UnexpectedResponse;
                }
                const s = try rdr.readU32LenString();
                chan.consumeLocalWindow(@intCast(s.len));
                misshod.requestEvent(.{ .RxData = .{ .channel = chan.local_id, .data = s } }, .Idle);
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
                misshod.requestEvent(.{ .RxExtendedData = .{ .channel = chan.local_id, .data_type = data_type, .data = s } }, .Idle);
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

fn buildUnencryptedPacket(buf: []u8, payload: []const u8) usize {
    const padding_length: u8 = 8;
    const packet_length: u32 = @intCast(payload.len + padding_length + 1);
    var hdr: Protocol.PktHdr = .{
        .packet_length = packet_length,
        .padding_length = padding_length,
    };
    if (native_endian != .big) {
        std.mem.byteSwapAllFields(Protocol.PktHdr, &hdr);
    }
    @memcpy(buf[0..Protocol.sizeof_PktHdr], util.asPackedBytes(Protocol.PktHdr, &hdr));
    @memcpy(buf[Protocol.sizeof_PktHdr .. Protocol.sizeof_PktHdr + payload.len], payload);
    @memset(buf[Protocol.sizeof_PktHdr + payload.len .. Protocol.sizeof_PktHdr + payload.len + padding_length], 0);
    return Protocol.sizeof_PktHdr + payload.len + padding_length;
}

test "handlePacket: auth-agent request surfaces channel request event" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();

    const chan = m.session.channel_table.allocChannelKind(.Session, 100, 32768, 32768).?;
    chan.state = .DataRx;

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_REQUEST));
    try pw.writeU32(chan.local_id);
    try pw.writeU32LenString(Protocol.channel_request_auth_agent);
    try pw.writeBoolean(false);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .ChannelRequest => |request| {
                try std.testing.expectEqual(chan.local_id, request.channel);
                switch (request.request) {
                    .AgentForward => {},
                    else => return error.TestUnexpectedResult,
                }
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "openAgentChannel sends an agent channel open" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();

    const channel_id = try m.openAgentChannel();
    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    try std.testing.expectEqual(.AgentForward, chan.kind);
    try std.testing.expectEqual(ChannelState.OpenSent, chan.state);
    try std.testing.expect(m.iostate_wr != .Idle);
}

test "handlePacket: agent channel open confirmation activates server channel" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();

    const channel_id = try m.session.openAgentChannel();
    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    chan.state = .OpenSent;

    var payload_backing: [64]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
    try pw.writeU32(channel_id);
    try pw.writeU32(77);
    try pw.writeU32(32768);
    try pw.writeU32(32768);

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    try std.testing.expectEqual(@as(u32, 77), chan.remote_id);
    try std.testing.expectEqual(@as(u32, 32768), chan.peer_window);
    try std.testing.expectEqual(ChannelState.Data, chan.state);
    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .AgentChannelOpen => |id| try std.testing.expectEqual(channel_id, id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "handlePacket: agent channel open failure emits close event" {
    const privkey = @import("privkey.zig");
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodServer.init(prng.random(), privkey.testkey_valid, std.testing.allocator);
    defer m.deinit();

    const channel_id = try m.session.openAgentChannel();
    const chan = m.session.channel_table.findByLocalId(channel_id).?;
    chan.state = .OpenSent;

    var payload_backing: [128]u8 = undefined;
    var pw = BufferWriter.init(&payload_backing, 0);
    try pw.writeU8(@intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_OPEN_FAILURE));
    try pw.writeU32(channel_id);
    try pw.writeU32(1);
    try pw.writeU32LenString("rejected");
    try pw.writeU32LenString("");

    const pkt_len = buildUnencryptedPacket(&m.iobuf_rd, pw.payload);
    m.session.encrypted = false;

    try m.session.handlePacket(m.iobuf_rd[0..pkt_len], &m);

    try std.testing.expect(m.session.channel_table.findByLocalId(channel_id) == null);
    const evt = try m.getNextEvent();
    switch (evt) {
        .Event => |code| switch (code) {
            .AgentChannelClosed => |id| try std.testing.expectEqual(channel_id, id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}
