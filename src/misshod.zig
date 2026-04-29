const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const ClientSession = @import("client_session.zig").Session;
const ServerSession = @import("server_session.zig").Session;
const BufferError = @import("buffer.zig").BufferError;
const PrivKeyError = @import("privkey.zig").PrivKeyError;
const Protocol = @import("protocol.zig");
const native_endian = @import("builtin").target.cpu.arch.endian();
const BufferReader = @import("buffer.zig").BufferReader;

pub const MisshodError = std.crypto.errors.Error || std.mem.Allocator.Error || BufferError || IoError || PrivKeyError;

pub const IoError = error{
    cannotAcceptWrite,
    notProducing,
    notEnoughData,
    noEOLFound,
    badClearEvent,
    InvalidPacketSize,
    InvalidMac,
    UnexpectedResponse,
    tooBig,
    UnimplementedService,
    AlgorithmNegotiationFailed,
};

pub const DisconnectReason = struct {
    code: u32,
    description: []const u8,
};

pub const EndSessionReason = union(enum) {
    Disconnect,
    ServerDisconnect: DisconnectReason,
    AuthFailure,
};

pub const Role = enum {
    Client,
    Server,
};

fn sessionType(role:Role) type {
    return switch(role) {
        .Client => ClientSession,
        .Server => ServerSession,
    };
}

fn eventCodeType(role:Role) type {
    return switch(role) {
        .Client => MisshodClientEventCodes,
        .Server => MisshodServerEventCodes,
    };
}

pub const KeyboardInteractivePrompt = struct {
    name: []const u8,
    instruction: []const u8,
    prompt: []const u8,
    echo: bool,
};

pub const HostKeyInfo = struct {
    raw_key: ?[]const u8,
    fingerprint: [Protocol.hash_algo.digest_length]u8,

    pub fn fingerprintStr(self: *const HostKeyInfo, buf: *[44]u8) []const u8 {
        return std.base64.standard.Encoder.encode(buf, &self.fingerprint);
    }
};

pub const MisshodClientEventCodes = union(enum) {
    CheckHostKey: HostKeyInfo,
    GetPrivateKey,
    GetKeyPassphrase,
    GetAuthPassphrase,
    EndSession: EndSessionReason,
    Connected,
    RxData: []const u8,
    RxExtendedData: ExtendedData,
    Banner: []const u8,
    KeyboardInteractive: KeyboardInteractivePrompt,
};

pub const ExtendedData = struct {
    data_type: u32,
    data: []const u8,
};

pub const UserCredentialsPasswordOrPubkey = union(enum) {
    Password: []const u8,
    Pubkey: []const u8,
    KeyboardInteractive: []const u8, // submethods
};

pub const UserCredentials = struct {
    username: []const u8,
    auth: ?UserCredentialsPasswordOrPubkey, // null for "none" auth
};

pub const WindowSize = struct {
    cols: u32,
    rows: u32,
    width_px: u32,
    height_px: u32,
};

pub const ChannelRequestType = union(enum) {
    Shell,
    Exec: []const u8,
    Subsystem: []const u8,
    Env: struct { name: []const u8, value: []const u8 },
};

pub const MisshodServerEventCodes = union(enum) {
    EndSession: EndSessionReason,
    UserAuth: UserCredentials,
    GetPubkeyForUser: []const u8,
    Connected,
    RxData: []const u8,
    RxExtendedData: ExtendedData,
    WindowChange: WindowSize,
    Signal: []const u8,
    ChannelRequest: ChannelRequestType,
};

pub fn MisshodEvent(role:Role) type {
    return union(enum) {
        Event: eventCodeType(role),
        ReadyToConsume: usize,
        ReadyToProduce: usize,
        ReadyToConsumeAndProduce: struct { consume: usize, produce: usize },
    };
}

// Producing a block, or consuming a block
pub fn IoAction(role:Role) type {
    return union(enum) {
        Producing: usize,
        Consuming: usize,
        Eventing: eventCodeType(role),
    };
}

// An IoAction, followed by state to move Session to on completion
pub fn IoStep(role:Role) type {
    return struct {
        action: IoAction(role),
        next_state: Protocol.IoSessionState,
    };
}

// Either Idle, or Active (Producing or Consuming) with a next IoSessionState on completion
pub fn IoState(role:Role) type {
    return union(enum) {
        Idle,
        Active: IoStep(role),
    };
}


pub const MisshodClient = MisshodImpl(.Client);
pub const MisshodServer = MisshodImpl(.Server);


pub fn MisshodImpl(role: Role) type {
    return struct {
    const Self = @This();

    session: sessionType(role),
    iostate_rd: IoState(role),
    iostate_wr: IoState(role),

    // full-duplex: separate read and write buffers
    iobuf_rd: [Protocol.MaxSSHPacket]u8 = undefined,
    iobuf_wr: [Protocol.MaxSSHPacket]u8 = undefined,
    rd_nbytes: usize,
    rd_off: usize,
    wr_nbytes: usize,
    wr_off: usize,

    pub fn init(rand: std.Random, username: []const u8, allocator: std.mem.Allocator) !Self {
        return Self{
            .session = try sessionType(role).init(rand, username, allocator),
            .rd_nbytes = 0,
            .rd_off = 0,
            .wr_nbytes = 0,
            .wr_off = 0,
            .iostate_rd = .Idle,
            .iostate_wr = .Idle,
        };
    }

    pub fn deinit(self: *Self) void {
        self.session.deinit();
        std.crypto.secureZero(u8, &self.iobuf_rd);
        std.crypto.secureZero(u8, &self.iobuf_wr);
    }

    // for session use
    pub fn requestWrite(self: *Self, wbuf: []const u8, next_state: Protocol.IoSessionState) void {
        std.debug.assert(self.iostate_wr == .Idle);
        std.debug.assert(&wbuf[0] == &self.iobuf_wr[0]);
        self.wr_nbytes = wbuf.len;
        self.wr_off = 0;
        self.iostate_wr = .{ .Active = .{
            .action = .{ .Producing = wbuf.len },
            .next_state = next_state,
        } };
    }

    // for session use
    pub fn requestRead(self: *Self, offset: usize, nbytes: usize, next_state: Protocol.IoSessionState) void {
        self.rd_nbytes = 0;
        self.rd_off = offset;
        self.iostate_rd = .{ .Active = .{
            .action = .{ .Consuming = nbytes },
            .next_state = next_state,
        } };
    }

    // for session use
    pub fn requestEvent(self: *Self, code: eventCodeType(role), next_state: Protocol.IoSessionState) void {
        self.iostate_wr = .{ .Active = .{
            .action = .{ .Eventing = code },
            .next_state = next_state,
        } };
    }

    pub fn grantAccess(self: *Self, allow:bool) MisshodError!void {
        switch(role) {
            .Client => return IoError.UnimplementedService, // FIXME something more tailored
            .Server => return try self.session.grantAccess(allow),
        }
    }

    pub fn clearEvent(self: *Self, clearEventCode: eventCodeType(role)) MisshodError!void {
        TRACE(.Debug, "clearEvent clearEventCode={any}", .{clearEventCode});
        TRACE(.Debug, "clearEvent iostate_wr={any}", .{self.iostate_wr});

        switch (self.iostate_wr) {
            .Active => |iotype| {
                switch (iotype.action) {
                    .Eventing => |eventCode| {
                        if (@intFromEnum(eventCode) == @intFromEnum(clearEventCode)) {
                            // event succesfully cleared
                            self.session.setIoSessionState(iotype.next_state);
                            self.iostate_wr = .Idle;
                            try self.advance();
                            return;
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }

        return IoError.badClearEvent;
    }

    pub fn getNextEvent(self: *Self) MisshodError!MisshodEvent(role) {
        // if eventing, send an event
        switch (self.iostate_wr) {
            .Active => |iotype| {
                switch (iotype.action) {
                    .Eventing => |eventCode| {
                        return MisshodEvent(role){ .Event = eventCode };
                    },
                    else => {},
                }
            },
            else => {},
        }

        // check both read and write readiness
        var can_consume_nbytes: usize = 0;
        var can_produce_nbytes: usize = 0;

        try self.getIoReq(&can_consume_nbytes, &can_produce_nbytes);

        std.debug.assert(can_consume_nbytes > 0 or can_produce_nbytes > 0);

        if (can_consume_nbytes > 0 and can_produce_nbytes > 0) {
            return MisshodEvent(role){ .ReadyToConsumeAndProduce = .{ .consume = can_consume_nbytes, .produce = can_produce_nbytes } };
        } else if (can_consume_nbytes > 0) {
            return MisshodEvent(role){ .ReadyToConsume = can_consume_nbytes };
        } else {
            return MisshodEvent(role){ .ReadyToProduce = can_produce_nbytes };
        }
    }

    fn getIoReq(self: *Self, can_consume: *usize, can_produce: *usize) MisshodError!void {
        try self.advance();

        // check read side
        can_consume.* = 0;
        switch (self.iostate_rd) {
            .Active => |iotype| {
                switch (iotype.action) {
                    .Consuming => |target_size| {
                        TRACE(.Debug, "getIoReq Consuming target_size={d} iobuf_rd.len={d} rd_nbytes={d}", .{ target_size, self.iobuf_rd.len, self.rd_nbytes });
                        if (target_size > self.iobuf_rd.len - self.rd_nbytes) {
                            can_consume.* = self.iobuf_rd.len - self.rd_nbytes;
                        } else {
                            can_consume.* = target_size - self.rd_nbytes;
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }

        // check write side
        can_produce.* = 0;
        switch (self.iostate_wr) {
            .Active => |iotype| {
                switch (iotype.action) {
                    .Producing => |block_size| {
                        _ = block_size;
                        TRACE(.Debug, "getIoReq Producing wr_nbytes={d}", .{self.wr_nbytes});
                        can_produce.* = self.wr_nbytes;
                    },
                    else => {},
                }
            },
            else => {},
        }
    }

    pub fn write(self: *Self, wbuf: []const u8) MisshodError!void {
        TRACE(.Debug, "misshod.write len={d} .rd_nbytes={d}", .{ wbuf.len, self.rd_nbytes });
        switch (self.iostate_rd) {
            .Active => |iotype| {
                switch (iotype.action) {
                    .Consuming => |target_size| {
                        if (wbuf.len > target_size - self.rd_nbytes) {
                            return IoError.cannotAcceptWrite;
                        }

                        @memcpy(self.iobuf_rd[self.rd_nbytes + self.rd_off .. self.rd_nbytes + wbuf.len + self.rd_off], wbuf);
                        self.rd_nbytes += wbuf.len;

                        if (self.rd_nbytes == target_size) {
                            // entire block has been written by caller
                            self.session.setIoSessionState(iotype.next_state);
                            self.iostate_rd = .Idle;
                            try self.advance();
                        }
                    },
                    else => {},
                }
            },
            else => return IoError.cannotAcceptWrite,
        }
    }

    pub fn peek(self: *Self, nbytes: usize) MisshodError![]const u8 {
        TRACE(.Debug, "peek nbytes={d} .wr_off={d} .wr_nbytes={d}", .{ nbytes, self.wr_off, self.wr_nbytes });
        // sanity check
        switch (self.iostate_wr) {
            .Active => |iotype| {
                switch (iotype.action) {
                    .Producing => {}, // ok
                    else => return IoError.notProducing,
                }
            },
            else => return IoError.notProducing,
        }

        const bytes_remaining = self.wr_nbytes - self.wr_off;

        if (bytes_remaining < nbytes) {
            return self.iobuf_wr[self.wr_off .. self.wr_off + bytes_remaining];
        } else {
            return self.iobuf_wr[self.wr_off..self.wr_nbytes];
        }
    }

    pub fn consumed(self: *Self, nbytes: usize) MisshodError!void {
        TRACE(.Debug, "consumed nbytes={d} wr_off={d} .wr_nbytes={d}", .{ nbytes, self.wr_off, self.wr_nbytes });

        const bytes_remaining = self.wr_nbytes - self.wr_off;

        // sanity check
        switch (self.iostate_wr) {
            .Active => |iotype| {
                switch (iotype.action) {
                    .Producing => {
                        if (nbytes > bytes_remaining) {
                            return IoError.notEnoughData;
                        }
                    },
                    else => return IoError.notProducing,
                }
            },
            else => return IoError.notProducing,
        }

        self.wr_off += nbytes;

        if (self.wr_off == self.wr_nbytes) {
            // entire block has been consumed by caller
            switch (self.iostate_wr) {
                .Active => |iotype| {
                    self.session.setIoSessionState(iotype.next_state);
                    self.iostate_wr = .Idle;
                    try self.advance();
                },
                else => unreachable,
            }
        }
    }

    pub fn getRecvBuffer(self: *Self, iobuf: []u8, inkeys: *Protocol.KeyDataUni) MisshodError!BufferReader {

        var hdr: Protocol.PktHdr = std.mem.bytesAsValue(Protocol.PktHdr, iobuf[0..Protocol.sizeof_PktHdr]).*;
        if (native_endian != .big) {
            // flip bytes
            std.mem.byteSwapAllFields(Protocol.PktHdr, &hdr);
        }
        const payload_len = hdr.packet_length - hdr.padding_length - 1;
        const payload = iobuf[Protocol.sizeof_PktHdr .. Protocol.sizeof_PktHdr + payload_len];

        if (!self.session.encrypted) {
            return BufferReader.init(payload);
        } else {
            TRACEDUMP(.Debug, "all buf", .{}, iobuf);
            const pkt_len = payload_len + (Protocol.sizeof_PktHdr) + hdr.padding_length;
            if (pkt_len > Protocol.AesCtrT.block_size) { // if there's more to be decrypted after first block
                const remaining_pkt_bytes = pkt_len - Protocol.AesCtrT.block_size;
                var dec: [Protocol.MaxSSHPacket]u8 = undefined;
                inkeys.aesctr.encrypt(iobuf[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes], dec[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes]); // use same offset into dec for simplicity

                TRACEDUMP(.Debug, "dec", .{}, dec[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes]);
                // copy decrypted back into writebuf
                @memcpy(iobuf[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes], dec[Protocol.AesCtrT.block_size .. Protocol.AesCtrT.block_size + remaining_pkt_bytes]);
                TRACEDUMP(.Debug, "writebuf", .{}, iobuf[0..pkt_len]);
            }

            // verify mac
            if (iobuf.len < Protocol.mac_algo.key_length) {
                return error.InvalidPacketSize; // too small to have a mac
            }
            const rxmac = iobuf[pkt_len..iobuf.len]; // at the end
            var calcmac: [Protocol.mac_algo.key_length]u8 = undefined;
            var m = Protocol.mac_algo.init(inkeys.mackey[0..Protocol.mac_algo.key_length]);
            const seq = std.mem.nativeTo(u32, inkeys.seq - 1, .big); // seq has already been incremented
            m.update(std.mem.asBytes(&seq));
            m.update(iobuf[0 .. iobuf.len - Protocol.mac_algo.key_length]); // plaintext
            m.final(&calcmac);

            TRACEDUMP(.Debug, "rxmac", .{}, rxmac);
            TRACEDUMP(.Debug, "mackey", .{}, inkeys.mackey[0..Protocol.mac_algo.key_length]);
            TRACEDUMP(.Debug, "macseq", .{}, std.mem.asBytes(&seq));
            TRACEDUMP(.Debug, "macdata", .{}, iobuf[0 .. iobuf.len - Protocol.mac_algo.key_length]);
            TRACEDUMP(.Debug, "calcmac", .{}, std.mem.asBytes(&calcmac));

            if (!std.mem.eql(u8, &calcmac, rxmac)) {
                return IoError.InvalidMac;
            }

            // remove mac and return buffer containing just plaintext payload
            return BufferReader.init(iobuf[Protocol.sizeof_PktHdr .. iobuf.len - Protocol.mac_algo.key_length]);
        }
    }


    fn advanceIoSession(self:*Self, inkeys:*Protocol.KeyDataUni) MisshodError!void {
        switch (self.session.ioSessionState) {
            .Idle => {
                TRACE(.Debug, "ioSessionState Idle", .{});
                try self.session.advanceSession(self);
            },
            .Init => {
                switch(role) {
                    .Client => self.session.setIoSessionState(.VersionWrite),
                    .Server => self.session.setIoSessionState(.VersionReadLine),
                }
            },
            .VersionWrite => {
                const sl = self.session.writeProtocolVersion(&self.iobuf_wr);
                switch(role) {
                    .Client => self.requestWrite(sl, .VersionReadLine),
                    .Server => self.requestWrite(sl, .Idle),
                }
            },
            .VersionReadLine => {
                // read first char
                self.requestRead(0, 1, .{ .VersionReadLineChar = self.iobuf_rd[0..1] });
            },
            .VersionReadLineChar => |buf| {
                if (buf.len + 1 > self.iobuf_rd.len) {
                    return IoError.noEOLFound;
                } else {
                    if (buf.len >= 2) {
                        if (buf[buf.len - 2] == '\r' and buf[buf.len - 1] == '\n') {
                            self.session.setIoSessionState(.{ .VersionReadLineCompletion = buf });
                            return;
                        }
                    }
                    // read next char
                    self.requestRead(buf.len, 1, .{ .VersionReadLineChar = self.iobuf_rd[0 .. buf.len + 1] });
                }
            },
            .VersionReadLineCompletion => |buf| {
                TRACE(.Debug, "RX: version '{s}'", .{util.chomp(buf)});
                switch(role) {
                    .Client => self.session.kex_hash_order = self.session.kex_hash_order.check(.V_S),
                    .Server => self.session.kex_hash_order = self.session.kex_hash_order.check(.V_C)
                }
                self.session.kex_hasher.writeU32LenString(util.chomp(buf));
                switch(role) {
                    .Client => self.session.setIoSessionState(.Idle),
                    .Server => self.session.setIoSessionState(.VersionWrite),
                }
            },
            .ReadPktHdr => {
                if (self.session.encrypted) {
                    self.requestRead(0, Protocol.AesCtrT.block_size, .{ .ReadPktBody = self.iobuf_rd[0..Protocol.AesCtrT.block_size] });
                } else {
                    self.requestRead(0, Protocol.sizeof_PktHdr, .{ .ReadPktBody = self.iobuf_rd[0..Protocol.sizeof_PktHdr] });
                }
            },
            .ReadPktBody => |buf| {
                if (self.session.encrypted) {
                    // https://datatracker.ietf.org/doc/html/rfc4253#section-6
                    // grab first encrypted block from writebuf
                    var firstblock_encbuf: [Protocol.AesCtrT.block_size]u8 = undefined;
                    @memcpy(&firstblock_encbuf, buf);

                    // decrypt directly into iobuf_rd
                    inkeys.aesctr.encrypt(&firstblock_encbuf, self.iobuf_rd[0..Protocol.AesCtrT.block_size]);
                    TRACEDUMP(.Debug, "firstblock_dec(in payload)", .{}, self.iobuf_rd[0..Protocol.AesCtrT.block_size]);

                    // read Protocol.PktHdr from first block
                    const pkthdr_size = Protocol.sizeof_PktHdr;
                    var hdr: Protocol.PktHdr = undefined;
                    hdr = std.mem.bytesToValue(Protocol.PktHdr, buf[0..pkthdr_size]);
                    if (native_endian != .big) {
                        std.mem.byteSwapAllFields(Protocol.PktHdr, &hdr);
                    }

                    // padding len is such that payload_len + sizeof(hdr) + padding = block size
                    const payload_len = hdr.packet_length - (hdr.padding_length + 1);
                    if (hdr.padding_length < 4) {
                        return IoError.InvalidPacketSize;
                    }
                    const pkt_len = payload_len + (Protocol.sizeof_PktHdr) + hdr.padding_length;
                    // avoid reading obviously bad packet sizes
                    if (pkt_len < 8 or pkt_len > Protocol.MaxSSHPacket) {
                        TRACE(.Info, "Bad pkt size {d}\n", .{pkt_len});
                        return IoError.InvalidPacketSize;
                    }

                    // calc number of remaining bytes + mac, read from network
                    var remaining_pkt_bytes: usize = 0;
                    if (pkt_len > Protocol.AesCtrT.block_size) {
                        remaining_pkt_bytes = pkt_len - Protocol.AesCtrT.block_size;
                    }
                    TRACE(.Debug, "About to read {d}\n", .{remaining_pkt_bytes + Protocol.mac_algo.key_length});
                    //
                    self.requestRead(buf.len, (remaining_pkt_bytes + Protocol.mac_algo.key_length), .{ .ReadPktCompletion = self.iobuf_rd[0 .. buf.len + remaining_pkt_bytes + Protocol.mac_algo.key_length] }); // on completion, how much we have

                    inkeys.seq +%= 1;
                } else {
                    // copy header
                    var hdr: Protocol.PktHdr = std.mem.bytesAsValue(Protocol.PktHdr, buf[0..Protocol.sizeof_PktHdr]).*;
                    if (native_endian != .big) {
                        // flip bytes
                        std.mem.byteSwapAllFields(Protocol.PktHdr, &hdr);
                    }

                    TRACE(.Debug, ".ReadPktBody hdr={any}", .{hdr});
                    // read in payload
                    const payload_len = hdr.packet_length - hdr.padding_length - 1;
                    std.debug.assert(payload_len <= Protocol.MaxPayload);

                    self.requestRead(buf.len, payload_len + hdr.padding_length, .{ .ReadPktCompletion = self.iobuf_rd[0 .. buf.len + payload_len + hdr.padding_length] });
                    inkeys.seq +%= 1;
                }
            },
            .ReadPktCompletion => |buf| {
                TRACEDUMP(.Debug, ".ReadPktCompletion", .{}, buf);
                try self.session.handlePacket(buf, self);
            },
        }
    }


    fn canProcessIoSessionState(self: *Self) bool {
        return switch (self.session.ioSessionState) {
            // Idle needs both sides free — session will decide what to do
            .Idle => self.iostate_rd == .Idle and self.iostate_wr == .Idle,
            .Init => true,
            // Read-requiring states only need read side idle
            .VersionReadLine, .VersionReadLineChar => self.iostate_rd == .Idle,
            .ReadPktHdr, .ReadPktBody => self.iostate_rd == .Idle,
            // Write-requiring states need write side idle
            .VersionWrite => self.iostate_wr == .Idle,
            // Processing states
            .VersionReadLineCompletion => true, // just sets next ioSessionState
            .ReadPktCompletion => self.iostate_wr == .Idle, // handlePacket may event/write
        };
    }

    pub fn advance(self: *Self) MisshodError!void {
        const inkeys = switch(role) {
            .Client => &self.session.keydata.s2c,
            .Server => &self.session.keydata.c2s,
        };
        while (self.canProcessIoSessionState()) {
            const prev_io_state = self.session.ioSessionState;
            const prev_rd = self.iostate_rd;
            const prev_wr = self.iostate_wr;
            try self.advanceIoSession(inkeys);
            // Break if no progress was made to prevent infinite loops
            const same_io = std.meta.eql(prev_io_state, self.session.ioSessionState);
            const same_rd = std.meta.eql(prev_rd, self.iostate_rd);
            const same_wr = std.meta.eql(prev_wr, self.iostate_wr);
            if (same_io and same_rd and same_wr) break;
        }
    }

    pub fn setPrivateKey(self: *Self, keydata_ascii: []const u8) MisshodError!void {
        try self.session.setPrivateKey(keydata_ascii);
    }

    pub fn setPrivateKeyPassphrase(self: *Self, data: []const u8) MisshodError!void {
        try self.session.setPrivateKeyPassphrase(data);
    }

    pub fn setAuthPassphrase(self: *Self, data: []const u8) MisshodError!void {
        try self.session.setAuthPassphrase(data);
    }

    pub fn isActive(self: *Self) bool {
        return self.session.isActive();
    }

    pub fn getChannelWriteBuffer(self: *Self) MisshodError![]u8 {
        // only returns a nonzero sized buffer if iosessionstate == .Idle
        return self.session.getChannelWriteBuffer();
    }

    pub fn channelWriteComplete(self: *Self, nbytes: usize) MisshodError!void {
        if (self.iostate_wr == .Idle and self.iostate_rd != .Idle) {
            // Full-duplex: read is active, write is idle
            // Build channel data packet directly without disturbing the read side
            try self.session.directChannelWrite(nbytes, self);
        } else {
            // Sequential fallback (e.g. during handshake or when both idle)
            self.iostate_rd = .Idle;
            self.iostate_wr = .Idle;
            try self.advance();

            try self.session.channelWriteComplete(nbytes);
            self.iostate_rd = .Idle;
            self.iostate_wr = .Idle;
            try self.advance();
        }
    }
};
}

test "EndSessionReason tagged union" {
    const reason_disconnect: EndSessionReason = .Disconnect;
    const reason_auth: EndSessionReason = .AuthFailure;
    const reason_server: EndSessionReason = .{ .ServerDisconnect = .{
        .code = 11,
        .description = "test disconnect",
    } };

    switch (reason_disconnect) {
        .Disconnect => {},
        else => return error.TestUnexpectedResult,
    }

    switch (reason_auth) {
        .AuthFailure => {},
        else => return error.TestUnexpectedResult,
    }

    switch (reason_server) {
        .ServerDisconnect => |r| {
            try std.testing.expectEqual(@as(u32, 11), r.code);
            try std.testing.expectEqualStrings("test disconnect", r.description);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "MisshodClientEventCodes Banner variant" {
    const banner: MisshodClientEventCodes = .{ .Banner = "Welcome to the server" };
    switch (banner) {
        .Banner => |text| {
            try std.testing.expectEqualStrings("Welcome to the server", text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "ExtendedData struct" {
    const ext: ExtendedData = .{ .data_type = 1, .data = "stderr output" };
    try std.testing.expectEqual(@as(u32, 1), ext.data_type);
    try std.testing.expectEqualStrings("stderr output", ext.data);
}

test "WindowSize struct" {
    const ws: WindowSize = .{ .cols = 120, .rows = 40, .width_px = 960, .height_px = 640 };
    try std.testing.expectEqual(@as(u32, 120), ws.cols);
    try std.testing.expectEqual(@as(u32, 40), ws.rows);
}

test "MisshodServerEventCodes WindowChange variant" {
    const evt: MisshodServerEventCodes = .{ .WindowChange = .{ .cols = 80, .rows = 24, .width_px = 640, .height_px = 480 } };
    switch (evt) {
        .WindowChange => |ws| {
            try std.testing.expectEqual(@as(u32, 80), ws.cols);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "MisshodServerEventCodes Signal variant" {
    const evt: MisshodServerEventCodes = .{ .Signal = "INT" };
    switch (evt) {
        .Signal => |sig| {
            try std.testing.expectEqualStrings("INT", sig);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "ChannelRequestType Exec variant" {
    const req: ChannelRequestType = .{ .Exec = "ls -la" };
    switch (req) {
        .Exec => |cmd| try std.testing.expectEqualStrings("ls -la", cmd),
        else => return error.TestUnexpectedResult,
    }
}

test "ChannelRequestType Subsystem variant" {
    const req: ChannelRequestType = .{ .Subsystem = "sftp" };
    switch (req) {
        .Subsystem => |name| try std.testing.expectEqualStrings("sftp", name),
        else => return error.TestUnexpectedResult,
    }
}

test "ChannelRequestType Env variant" {
    const req: ChannelRequestType = .{ .Env = .{ .name = "LANG", .value = "en_US.UTF-8" } };
    switch (req) {
        .Env => |env| {
            try std.testing.expectEqualStrings("LANG", env.name);
            try std.testing.expectEqualStrings("en_US.UTF-8", env.value);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "ChannelRequestType Shell variant" {
    const req: ChannelRequestType = .Shell;
    switch (req) {
        .Shell => {},
        else => return error.TestUnexpectedResult,
    }
}

test "KeyboardInteractivePrompt struct" {
    const prompt: KeyboardInteractivePrompt = .{
        .name = "Login",
        .instruction = "Enter credentials",
        .prompt = "Password: ",
        .echo = false,
    };
    try std.testing.expectEqualStrings("Password: ", prompt.prompt);
    try std.testing.expect(!prompt.echo);
}

test "UserCredentialsPasswordOrPubkey KeyboardInteractive variant" {
    const auth: UserCredentialsPasswordOrPubkey = .{ .KeyboardInteractive = "" };
    switch (auth) {
        .KeyboardInteractive => {},
        else => return error.TestUnexpectedResult,
    }
}

test "client-server full handshake round-trip" {
    const privkey = @import("privkey.zig");

    var cprng = std.Random.DefaultPrng.init(1);
    var sprng = std.Random.DefaultPrng.init(2);

    var client = try MisshodClient.init(cprng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    var server = try MisshodServer.init(sprng.random(), privkey.testkey_valid, std.testing.allocator);
    defer server.deinit();

    var c2s_buf: [16384]u8 = undefined;
    var s2c_buf: [16384]u8 = undefined;
    var c2s_len: usize = 0;
    var s2c_len: usize = 0;

    var connected_client = false;

    const Endpoint = enum { client_ep, server_ep };
    const endpoints = [_]Endpoint{ .client_ep, .server_ep };

    var steps: usize = 0;
    while (steps < 500) : (steps += 1) {
        if (connected_client) break;

        for (endpoints) |ep| {
            const is_client = ep == .client_ep;

            if (is_client) {
                const cev = client.getNextEvent() catch continue;
                switch (cev) {
                    .ReadyToProduce => {
                        const data = client.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(c2s_buf[c2s_len .. c2s_len + data.len], data);
                        c2s_len += data.len;
                        client.consumed(data.len) catch {};
                    },
                    .ReadyToConsume => |n| {
                        if (s2c_len > 0) {
                            const feed = @min(n, s2c_len);
                            client.write(s2c_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &s2c_buf, s2c_buf[feed..s2c_len]);
                            s2c_len -= feed;
                        }
                    },
                    .ReadyToConsumeAndProduce => |s| {
                        const data = client.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(c2s_buf[c2s_len .. c2s_len + data.len], data);
                        c2s_len += data.len;
                        client.consumed(data.len) catch {};
                        if (s2c_len > 0) {
                            const feed = @min(s.consume, s2c_len);
                            client.write(s2c_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &s2c_buf, s2c_buf[feed..s2c_len]);
                            s2c_len -= feed;
                        }
                    },
                    .Event => |code| switch (code) {
                        .CheckHostKey => { client.clearEvent(.{ .CheckHostKey = .{ .raw_key = null, .fingerprint = .{0} ** 32 } }) catch {}; },
                        .GetPrivateKey => { client.clearEvent(.GetPrivateKey) catch {}; },
                        .GetAuthPassphrase => {
                            client.session.setAuthPassphrase("testpass") catch {};
                            client.clearEvent(.GetAuthPassphrase) catch {};
                        },
                        .Connected => {
                            connected_client = true;
                            client.clearEvent(.Connected) catch {};
                        },
                        .EndSession => { connected_client = false; break; },
                        else => {},
                    },
                }
            } else {
                const sev = server.getNextEvent() catch continue;
                switch (sev) {
                    .ReadyToProduce => {
                        const data = server.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(s2c_buf[s2c_len .. s2c_len + data.len], data);
                        s2c_len += data.len;
                        server.consumed(data.len) catch {};
                    },
                    .ReadyToConsume => |n| {
                        if (c2s_len > 0) {
                            const feed = @min(n, c2s_len);
                            server.write(c2s_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &c2s_buf, c2s_buf[feed..c2s_len]);
                            c2s_len -= feed;
                        }
                    },
                    .ReadyToConsumeAndProduce => |s| {
                        const data = server.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(s2c_buf[s2c_len .. s2c_len + data.len], data);
                        s2c_len += data.len;
                        server.consumed(data.len) catch {};
                        if (c2s_len > 0) {
                            const feed = @min(s.consume, c2s_len);
                            server.write(c2s_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &c2s_buf, c2s_buf[feed..c2s_len]);
                            c2s_len -= feed;
                        }
                    },
                    .Event => |code| switch (code) {
                        .UserAuth => {
                            server.grantAccess(true) catch {};
                            server.clearEvent(.{ .UserAuth = .{ .username = "", .auth = null } }) catch {};
                        },
                        .Connected => { server.clearEvent(.Connected) catch {}; },
                        .ChannelRequest => { server.clearEvent(.{ .ChannelRequest = .Shell }) catch {}; },
                        else => {},
                    },
                }
            }
        }
    }

    try std.testing.expect(connected_client);
}

test "HostKeyInfo fingerprint computation" {
    const Misshod = @import("misshod.zig");
    const key_data = "test-host-key-data";
    var fp: [Protocol.hash_algo.digest_length]u8 = undefined;
    Protocol.hash_algo.hash(key_data, &fp, .{});

    const info: Misshod.HostKeyInfo = .{
        .raw_key = key_data,
        .fingerprint = fp,
    };

    var buf: [44]u8 = undefined;
    const fp_str = info.fingerprintStr(&buf);
    // SHA-256 of "test-host-key-data" base64-encoded should be 44 chars
    try std.testing.expectEqual(@as(usize, 44), fp_str.len);
    try std.testing.expect(fp_str[0] != 0); // not empty
}

test "HostKeyInfo fingerprint is deterministic" {
    const key = "same-key";
    var fp1: [Protocol.hash_algo.digest_length]u8 = undefined;
    var fp2: [Protocol.hash_algo.digest_length]u8 = undefined;
    Protocol.hash_algo.hash(key, &fp1, .{});
    Protocol.hash_algo.hash(key, &fp2, .{});
    try std.testing.expectEqualSlices(u8, &fp1, &fp2);
}
