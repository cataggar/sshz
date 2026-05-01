const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const ClientSession = @import("client_session.zig").Session;
const ServerSession = @import("server_session.zig").Session;
const BufferError = @import("buffer.zig").BufferError;
const PrivKeyError = @import("privkey.zig").PrivKeyError;
const Protocol = @import("protocol.zig");
const BufferReader = @import("buffer.zig").BufferReader;
const log = std.log.scoped(.misshod);

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
};

pub const EndSessionReason = enum {
    Disconnect,
    AuthFailure,
};

pub const Role = enum {
    Client,
    Server,
};

fn sessionType(role: Role) type {
    return switch (role) {
        .Client => ClientSession,
        .Server => ServerSession,
    };
}

fn eventCodeType(role: Role) type {
    return switch (role) {
        .Client => MisshodClientEventCodes,
        .Server => MisshodServerEventCodes,
    };
}

pub const MisshodClientEventCodes = union(enum) {
    CheckHostKey: ?[]const u8,
    GetPrivateKey,
    GetKeyPassphrase,
    GetAuthPassphrase,
    EndSession: EndSessionReason,
    Connected,
    RxData: []const u8,
};

pub const UserCredentialsPasswordOrPubkey = union(enum) {
    Password: []const u8, // "password" auth
    Pubkey: []const u8, // "publickey" auth
};

pub const UserCredentials = struct {
    username: []const u8,
    auth: ?UserCredentialsPasswordOrPubkey, // null for "none" auth
};

pub const MisshodServerEventCodes = union(enum) {
    EndSession: EndSessionReason,
    UserAuth: UserCredentials,
    GetPubkeyForUser: []const u8,
    Connected,
    RxData: []const u8,
};

pub fn MisshodEvent(role: Role) type {
    return union(enum) {
        Event: eventCodeType(role),
        ReadyToConsume: usize,
        ReadyToProduce: usize,
    };
}

// Producing a block, or consuming a block
pub fn IoAction(role: Role) type {
    return union(enum) {
        Producing: usize,
        Consuming: usize,
        Eventing: eventCodeType(role),
    };
}

// An IoAction, followed by state to move Session to on completion
pub fn IoStep(role: Role) type {
    return struct {
        action: IoAction(role),
        next_state: Protocol.IoSessionState,
    };
}

// Either Idle, or Active (Producing or Consuming) with a next IoSessionState on completion
pub fn IoState(role: Role) type {
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
        iostate: IoState(role),

        // io strategy, only ever reading or writing, always trying to get a fixed number of bytes
        iobuf: [Protocol.MaxSSHPacket]u8 = undefined, // single shared buf, half duplex
        iobuf_nbytes: usize,
        iobuf_rdwroff: usize,

        fn invalidPacket(
            self: *Self,
            comptime reason: []const u8,
            packet_length: usize,
            padding_length: usize,
            available: usize,
            needed: usize,
        ) IoError {
            log.err(
                "invalid SSH packet {s}: role={any} encrypted={} session={any} io={any} packet_length={} padding_length={} available={} needed={} max={}",
                .{
                    reason,
                    role,
                    self.session.encrypted,
                    self.session.sessionState,
                    self.session.ioSessionState,
                    packet_length,
                    padding_length,
                    available,
                    needed,
                    Protocol.MaxSSHPacket,
                },
            );
            return IoError.InvalidPacketSize;
        }

        pub fn init(rand: std.Random, username: []const u8, allocator: std.mem.Allocator) !Self {
            return Self{
                .session = try sessionType(role).init(rand, username, allocator),
                .iobuf_nbytes = 0, // number of bytes in iobuf
                .iobuf_rdwroff = 0, // rd offset into iobuf
                .iostate = .Idle,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (role == .Client) {
                self.session.deinit(allocator);
            }
        }

        // for session use
        pub fn requestWrite(self: *Self, wbuf: []const u8, next_state: Protocol.IoSessionState) void {
            std.debug.assert(self.iostate == .Idle);
            std.debug.assert(&wbuf[0] == &self.iobuf[0]);
            self.iobuf_nbytes = wbuf.len;
            self.iobuf_rdwroff = 0; // all writes start from start of buf
            self.iostate = .{ .Active = .{
                .action = .{ .Producing = wbuf.len },
                .next_state = next_state,
            } };
        }

        // for session use
        pub fn requestRead(self: *Self, offset: usize, nbytes: usize, next_state: Protocol.IoSessionState) void {
            self.iobuf_nbytes = 0;
            self.iobuf_rdwroff = offset;
            self.iostate = .{ .Active = .{
                .action = .{ .Consuming = nbytes },
                .next_state = next_state,
            } };
        }

        // for session use
        // FIXME add event code
        pub fn requestEvent(self: *Self, code: eventCodeType(role), next_state: Protocol.IoSessionState) void {
            self.iobuf_nbytes = 0; // unused
            self.iobuf_rdwroff = 0; // unused
            self.iostate = .{ .Active = .{
                .action = .{ .Eventing = code },
                .next_state = next_state,
            } };
        }

        pub fn grantAccess(self: *Self, allow: bool) MisshodError!void {
            switch (role) {
                .Client => return IoError.UnimplementedService, // FIXME something more tailored
                .Server => return try self.session.grantAccess(allow),
            }
        }

        pub fn clearEvent(self: *Self, clearEventCode: eventCodeType(role)) MisshodError!void {
            TRACE(.Debug, "clearEvent clearEventCode={any}", .{clearEventCode});
            TRACE(.Debug, "clearEvent iostate={any}", .{self.iostate});

            switch (self.iostate) {
                .Active => |iotype| {
                    switch (iotype.action) {
                        .Eventing => |eventCode| {
                            if (@intFromEnum(eventCode) == @intFromEnum(clearEventCode)) {
                                // event succesfully cleared
                                self.session.setIoSessionState(iotype.next_state);
                                self.iostate = .Idle;
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
            switch (self.iostate) {
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

            // else either .ReadyToConsume ^ .ReadyToProduce
            var can_consume_nbytes: usize = 0;
            var can_produce_nbytes: usize = 0;

            try self.getIoReq(&can_consume_nbytes, &can_produce_nbytes);

            std.debug.assert(!(can_consume_nbytes > 0 and can_produce_nbytes > 0));
            std.debug.assert(can_consume_nbytes > 0 or can_produce_nbytes > 0);

            if (can_consume_nbytes > 0) {
                return MisshodEvent(role){ .ReadyToConsume = can_consume_nbytes };
            } else {
                return MisshodEvent(role){ .ReadyToProduce = can_produce_nbytes };
            }

            unreachable;
        }

        fn getIoReq(self: *Self, can_consume: *usize, can_produce: *usize) MisshodError!void {
            try self.advance();

            switch (self.iostate) {
                .Idle => {
                    TRACE(.Debug, "getIoReq Idle", .{});
                    can_consume.* = 0;
                    can_produce.* = 0;
                },
                .Active => |iotype| {
                    switch (iotype.action) {
                        .Consuming => |target_size| {
                            TRACE(.Debug, "getIoReq Consuming target_size={d} iobuf.len={d} iobuf.nbytes={d}", .{ target_size, self.iobuf.len, self.iobuf_nbytes });
                            // reading from caller into iobuf
                            if (target_size > self.iobuf.len - self.iobuf_nbytes) {
                                can_consume.* = self.iobuf.len - self.iobuf_nbytes;
                            } else {
                                can_consume.* = target_size - self.iobuf_nbytes;
                            }
                            can_produce.* = 0;
                        },
                        .Producing => |block_size| {
                            TRACE(.Debug, "getIoReq Producing {d} iobuf_nbytes={d}", .{ block_size, self.iobuf_nbytes });
                            // being read by caller from iobuf
                            can_produce.* = self.iobuf_nbytes; // number of bytes in buffer
                            can_consume.* = 0;
                        },
                        .Eventing => {
                            can_produce.* = 0;
                            can_consume.* = 0;
                        },
                    }
                },
            }
        }

        pub fn write(self: *Self, wbuf: []const u8) MisshodError!void {
            TRACE(.Debug, "misshod.write len={d} .iobuf_nbytes={d}", .{ wbuf.len, self.iobuf_nbytes });
            switch (self.iostate) {
                .Active => |iotype| {
                    switch (iotype.action) {
                        .Consuming => |target_size| {
                            if (wbuf.len > target_size - self.iobuf_nbytes) {
                                return IoError.cannotAcceptWrite;
                            }

                            @memcpy(self.iobuf[self.iobuf_nbytes + self.iobuf_rdwroff .. self.iobuf_nbytes + wbuf.len + self.iobuf_rdwroff], wbuf);
                            self.iobuf_nbytes += wbuf.len;

                            if (self.iobuf_nbytes == target_size) {
                                // entire block has been written by caller
                                self.session.setIoSessionState(iotype.next_state);
                                self.iostate = .Idle;
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
            TRACE(.Debug, "peek nbytes={d} .iobuf_rdwroff={d} .iobuf_nbytes={d}", .{ nbytes, self.iobuf_rdwroff, self.iobuf_nbytes });
            // sanity check
            switch (self.iostate) {
                .Active => |iotype| {
                    switch (iotype.action) {
                        .Producing => {}, // ok
                        else => return IoError.notProducing,
                    }
                },
                else => return IoError.notProducing,
            }

            const bytes_remaining = self.iobuf_nbytes - self.iobuf_rdwroff;

            if (bytes_remaining < nbytes) {
                return self.iobuf[self.iobuf_rdwroff .. self.iobuf_rdwroff + bytes_remaining];
            } else {
                return self.iobuf[self.iobuf_rdwroff..self.iobuf_nbytes];
            }
        }

        pub fn consumed(self: *Self, nbytes: usize) MisshodError!void {
            TRACE(.Debug, "consumed nbytes={d} iobuf_rdwroff={d} .iobuf_nbytes={d}", .{ nbytes, self.iobuf_rdwroff, self.iobuf_nbytes });

            const bytes_remaining = self.iobuf_nbytes - self.iobuf_rdwroff;

            // sanity check
            switch (self.iostate) {
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

            self.iobuf_rdwroff += nbytes;

            if (self.iobuf_rdwroff == self.iobuf_nbytes) {
                // entire block has been consumed by caller
                switch (self.iostate) {
                    .Active => |iotype| {
                        self.session.setIoSessionState(iotype.next_state);
                        self.iostate = .Idle;
                        try self.advance();
                    },
                    else => unreachable,
                }
            }
        }

        pub fn getRecvBuffer(self: *Self, iobuf: []u8, inkeys: *Protocol.KeyDataUni) MisshodError!BufferReader {
            const hdr = Protocol.readPktHdr(iobuf[0..Protocol.sizeof_PktHdr]);
            const packet_length: usize = hdr.packet_length;
            const padding_length: usize = hdr.padding_length;
            if (padding_length < 4 or packet_length <= padding_length) {
                return self.invalidPacket("recv header bounds", packet_length, padding_length, iobuf.len, padding_length + 1);
            }
            const bytes_after_header = packet_length - 1;
            if (bytes_after_header > iobuf.len - Protocol.sizeof_PktHdr) {
                return self.invalidPacket("recv truncated body", packet_length, padding_length, iobuf.len - Protocol.sizeof_PktHdr, bytes_after_header);
            }
            const payload_len = bytes_after_header - padding_length;
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
                    return self.invalidPacket("recv missing mac", packet_length, padding_length, iobuf.len, Protocol.mac_algo.key_length);
                }
                if (pkt_len > iobuf.len or iobuf.len - pkt_len != Protocol.mac_algo.key_length) {
                    return self.invalidPacket("recv mac length mismatch", packet_length, padding_length, iobuf.len, pkt_len + Protocol.mac_algo.key_length);
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

        fn advanceIoSession(self: *Self, inkeys: *Protocol.KeyDataUni) MisshodError!void {
            std.debug.assert(self.iostate == .Idle); // we only get called once IO completes
            switch (self.session.ioSessionState) {
                .Idle => {
                    TRACE(.Debug, "ioSessionState Idle", .{});
                    try self.session.advanceSession(self);
                },
                .Init => {
                    switch (role) {
                        .Client => self.session.setIoSessionState(.VersionWrite),
                        .Server => self.session.setIoSessionState(.VersionReadLine),
                    }
                },
                .VersionWrite => {
                    const sl = self.session.writeProtocolVersion(&self.iobuf);
                    switch (role) {
                        .Client => self.requestWrite(sl, .VersionReadLine),
                        .Server => self.requestWrite(sl, .Idle),
                    }
                },
                .VersionReadLine => {
                    // read first char
                    self.requestRead(0, 1, .{ .VersionReadLineChar = self.iobuf[0..1] });
                },
                .VersionReadLineChar => |buf| {
                    if (buf.len + 1 > self.iobuf.len) {
                        return IoError.noEOLFound;
                    } else {
                        if (buf.len >= 2) {
                            if (buf[buf.len - 2] == '\r' and buf[buf.len - 1] == '\n') {
                                self.session.setIoSessionState(.{ .VersionReadLineCompletion = buf });
                                return;
                            }
                        }
                        // read next char
                        self.requestRead(buf.len, 1, .{ .VersionReadLineChar = self.iobuf[0 .. buf.len + 1] });
                    }
                },
                .VersionReadLineCompletion => |buf| {
                    TRACE(.Debug, "RX: version '{s}'", .{util.chomp(buf)});
                    switch (role) {
                        .Client => self.session.kex_hash_order = self.session.kex_hash_order.check(.V_S),
                        .Server => self.session.kex_hash_order = self.session.kex_hash_order.check(.V_C),
                    }
                    self.session.kex_hasher.writeU32LenString(util.chomp(buf));
                    switch (role) {
                        .Client => self.session.setIoSessionState(.Idle),
                        .Server => self.session.setIoSessionState(.VersionWrite),
                    }
                },
                .ReadPktHdr => {
                    if (self.session.encrypted) {
                        self.requestRead(0, Protocol.AesCtrT.block_size, .{ .ReadPktBody = self.iobuf[0..Protocol.AesCtrT.block_size] });
                    } else {
                        self.requestRead(0, Protocol.sizeof_PktHdr, .{ .ReadPktBody = self.iobuf[0..Protocol.sizeof_PktHdr] });
                    }
                },
                .ReadPktBody => |buf| {
                    if (self.session.encrypted) {
                        // https://datatracker.ietf.org/doc/html/rfc4253#section-6
                        // grab first encrypted block from writebuf
                        var firstblock_encbuf: [Protocol.AesCtrT.block_size]u8 = undefined;
                        @memcpy(&firstblock_encbuf, buf);

                        // decrypt directly into iobuf
                        inkeys.aesctr.encrypt(&firstblock_encbuf, self.iobuf[0..Protocol.AesCtrT.block_size]);
                        TRACEDUMP(.Debug, "firstblock_dec(in payload)", .{}, self.iobuf[0..Protocol.AesCtrT.block_size]);

                        // read Protocol.PktHdr from first block
                        const pkthdr_size = Protocol.sizeof_PktHdr;
                        const hdr = Protocol.readPktHdr(self.iobuf[0..pkthdr_size]);

                        // padding len is such that payload_len + sizeof(hdr) + padding = block size
                        const packet_length: usize = hdr.packet_length;
                        const padding_length: usize = hdr.padding_length;
                        if (padding_length < 4 or packet_length <= padding_length) {
                            return self.invalidPacket("encrypted header bounds", packet_length, padding_length, buf.len, padding_length + 1);
                        }
                        const payload_len = packet_length - (padding_length + 1);
                        const pkt_len = payload_len + (Protocol.sizeof_PktHdr) + padding_length;
                        // avoid reading obviously bad packet sizes
                        if (pkt_len < Protocol.AesCtrT.block_size or pkt_len > Protocol.MaxSSHPacket) {
                            TRACE(.Info, "Bad pkt size {d}\n", .{pkt_len});
                            return self.invalidPacket("encrypted packet size", packet_length, padding_length, Protocol.MaxSSHPacket, pkt_len);
                        }

                        // calc number of remaining bytes + mac, read from network
                        var remaining_pkt_bytes: usize = 0;
                        if (pkt_len > Protocol.AesCtrT.block_size) {
                            remaining_pkt_bytes = pkt_len - Protocol.AesCtrT.block_size;
                        }
                        const read_len = remaining_pkt_bytes + Protocol.mac_algo.key_length;
                        if (read_len > self.iobuf.len - buf.len) {
                            return self.invalidPacket("encrypted read exceeds buffer", packet_length, padding_length, self.iobuf.len - buf.len, read_len);
                        }
                        TRACE(.Debug, "About to read {d}\n", .{read_len});
                        //
                        self.requestRead(buf.len, read_len, .{ .ReadPktCompletion = self.iobuf[0 .. buf.len + read_len] }); // on completion, how much we have

                        inkeys.seq +%= 1;
                    } else {
                        // copy header
                        const hdr = Protocol.readPktHdr(buf[0..Protocol.sizeof_PktHdr]);

                        TRACE(.Debug, ".ReadPktBody hdr={any}", .{hdr});
                        // read in payload
                        const packet_length: usize = hdr.packet_length;
                        const padding_length: usize = hdr.padding_length;
                        if (padding_length < 4 or packet_length <= padding_length) {
                            return self.invalidPacket("clear header bounds", packet_length, padding_length, buf.len, padding_length + 1);
                        }
                        const payload_len = packet_length - padding_length - 1;
                        const body_len = payload_len + padding_length;
                        if (body_len > self.iobuf.len - buf.len) {
                            return self.invalidPacket("clear read exceeds buffer", packet_length, padding_length, self.iobuf.len - buf.len, body_len);
                        }

                        self.requestRead(buf.len, body_len, .{ .ReadPktCompletion = self.iobuf[0 .. buf.len + body_len] });
                        inkeys.seq +%= 1;
                    }
                },
                .ReadPktCompletion => |buf| {
                    TRACEDUMP(.Debug, ".ReadPktCompletion", .{}, buf);
                    try self.session.handlePacket(buf, self);
                },
            }
        }

        pub fn advance(self: *Self) MisshodError!void {
            while (self.iostate == .Idle) { // only ever in Idle at init time or after event, until everything gets flowing
                switch (role) {
                    .Client => try self.advanceIoSession(&self.session.keydata.s2c),
                    .Server => try self.advanceIoSession(&self.session.keydata.c2s),
                }
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

        pub fn setPty(self: *Self, term: []const u8, cols: u16, rows: u16) MisshodError!void {
            switch (role) {
                .Client => return try self.session.setPty(term, cols, rows),
                .Server => return IoError.UnimplementedService,
            }
        }

        pub fn setWindowSize(self: *Self, cols: u16, rows: u16) MisshodError!void {
            switch (role) {
                .Client => {
                    self.session.setWindowSize(cols, rows);
                    if (self.iobuf_nbytes == 0 and self.canInterruptReadForChannelWrite()) {
                        _ = self.session.interruptIdleChannelRead();
                        self.iostate = .Idle;
                        try self.advance();
                    }
                    return;
                },
                .Server => return IoError.UnimplementedService,
            }
        }

        pub fn setExecCommand(self: *Self, command: []const u8) MisshodError!void {
            switch (role) {
                .Client => return self.session.setExecCommand(command),
                .Server => return IoError.UnimplementedService,
            }
        }

        pub fn isActive(self: *Self) bool {
            return self.session.isActive();
        }

        pub fn getChannelWriteBuffer(self: *Self) MisshodError![]u8 {
            switch (self.iostate) {
                .Idle => {},
                .Active => |iotype| switch (iotype.action) {
                    .Consuming => {
                        if (self.iobuf_nbytes != 0 or !self.canInterruptReadForChannelWrite()) return &.{};
                    },
                    .Producing, .Eventing => return &.{},
                },
            }
            return self.session.getChannelWriteBuffer();
        }

        pub fn channelWriteComplete(self: *Self, nbytes: usize) MisshodError!void {
            // assumes that getChannelWriteBuffer() is called then channelWriteComplete()
            switch (self.iostate) {
                .Idle => {},
                .Active => |iotype| switch (iotype.action) {
                    .Consuming => {
                        if (self.iobuf_nbytes != 0 or !self.canInterruptReadForChannelWrite()) {
                            return IoError.cannotAcceptWrite;
                        }
                    },
                    .Producing, .Eventing => return IoError.cannotAcceptWrite,
                },
            }
            self.iostate = .Idle;
            try self.advance();

            try self.session.channelWriteComplete(nbytes);
            self.iostate = .Idle;
            try self.advance();
        }

        fn canInterruptReadForChannelWrite(self: *Self) bool {
            return switch (self.session.ioSessionState) {
                .ReadPktHdr => true,
                else => false,
            };
        }
    };
}

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

fn putClientInPacketRead(misshod: *MisshodClient, buffered_nbytes: usize) void {
    misshod.session.sessionState = .ChannelDataRx;
    misshod.session.ioSessionState = .ReadPktHdr;
    misshod.iostate = .{ .Active = .{
        .action = .{ .Consuming = Protocol.AesCtrT.block_size },
        .next_state = .{ .ReadPktBody = misshod.iobuf[0..Protocol.AesCtrT.block_size] },
    } };
    misshod.iobuf_nbytes = buffered_nbytes;
    misshod.iobuf_rdwroff = 0;
}

test "client channel writes are rejected while packet read has buffered bytes" {
    var prng = std.Random.DefaultPrng.init(0);
    var misshod = try MisshodClient.init(prng.random(), "alice", std.testing.allocator);
    defer misshod.deinit(std.testing.allocator);
    putClientInPacketRead(&misshod, 1);

    try std.testing.expect((try misshod.getChannelWriteBuffer()).len == 0);
    try std.testing.expectError(IoError.cannotAcceptWrite, misshod.channelWriteComplete(1));
}

test "client resize is deferred while packet read has buffered bytes" {
    var prng = std.Random.DefaultPrng.init(0);
    var misshod = try MisshodClient.init(prng.random(), "alice", std.testing.allocator);
    defer misshod.deinit(std.testing.allocator);
    putClientInPacketRead(&misshod, 1);

    try misshod.setWindowSize(100, 40);

    try std.testing.expect(misshod.session.sessionState == .ChannelDataRx);
    try std.testing.expect(misshod.session.ioSessionState == .ReadPktHdr);
    try std.testing.expect(misshod.session.resize_pending);
    switch (misshod.iostate) {
        .Active => |step| switch (step.action) {
            .Consuming => {},
            else => try std.testing.expect(false),
        },
        else => try std.testing.expect(false),
    }
}

test "client channel writes interrupt idle packet header read" {
    var prng = std.Random.DefaultPrng.init(0);
    var misshod = try MisshodClient.init(prng.random(), "alice", std.testing.allocator);
    defer misshod.deinit(std.testing.allocator);
    putClientInPacketRead(&misshod, 0);
    misshod.session.remote_channel = 7;

    const buf = try misshod.getChannelWriteBuffer();
    try std.testing.expect(buf.len == misshod.session.channel_write_buf.len);
    buf[0] = 'x';
    try misshod.channelWriteComplete(1);

    var rdr = BufferReader.init(clearPacketPayload(try producedPacket(&misshod)));
    try std.testing.expect(try rdr.readU8() == @intFromEnum(Protocol.MsgId.SSH_MSG_CHANNEL_DATA));
    try std.testing.expect(try rdr.readU32() == 7);
    try std.testing.expect(std.mem.eql(u8, try rdr.readU32LenString(), "x"));
    try std.testing.expect(rdr.off == rdr.payload.len);
}
