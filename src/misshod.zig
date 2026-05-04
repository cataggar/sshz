const std = @import("std");
const util = @import("util.zig");
const TRACE = util.trace;
const TRACEDUMP = util.tracedump;
const ClientSession = @import("client_session.zig").Session;
const ServerSession = @import("server_session.zig").Session;
const BufferError = @import("buffer.zig").BufferError;
const PrivKeyError = @import("privkey.zig").PrivKeyError;
const Key = @import("key.zig");
const Protocol = @import("protocol.zig");
const BufferReader = @import("buffer.zig").BufferReader;

pub const MisshodError = std.crypto.errors.Error || std.mem.Allocator.Error || BufferError || IoError || PrivKeyError || Key.KeyError;

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
    NotReady,
    tooManyChannels,
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
    ChannelOpened: u32,
    ChannelOpenFailure: ChannelOpenFailure,
    ChannelOpenRequest: ChannelOpenRequestEvent,
    TcpipForwardSuccess: TcpipForwardSuccess,
    TcpipForwardFailure: TcpipForwardFailure,
    CancelTcpipForwardSuccess: TcpipForwardRequest,
    CancelTcpipForwardFailure: TcpipForwardRequest,
    RxData: []const u8,
    RxExtendedData: ExtendedData,
    AgentChannelOpen: u32,
    AgentData: ChannelData,
    AgentChannelClosed: u32,
    Banner: []const u8,
    KeyboardInteractive: KeyboardInteractivePrompt,
};

pub const SshOpenFailureReason = struct {
    pub const AdministrativelyProhibited: u32 = 1;
    pub const ConnectFailed: u32 = 2;
    pub const UnknownChannelType: u32 = 3;
    pub const ResourceShortage: u32 = 4;
};

pub const ChannelOpenFailure = struct {
    channel: u32,
    reason_code: u32,
    description: []const u8,
};

pub const TcpipForwardRequest = struct {
    bind_address: []const u8,
    bind_port: u32,
};

pub const TcpipForwardSuccess = struct {
    bind_address: []const u8,
    requested_port: u32,
    bound_port: u32,
};

pub const TcpipForwardFailure = struct {
    bind_address: []const u8,
    bind_port: u32,
};

pub const DirectTcpipOpen = struct {
    host: []const u8,
    port: u32,
    originator_host: []const u8,
    originator_port: u32,
};

pub const ForwardedTcpipOpen = struct {
    connected_host: []const u8,
    connected_port: u32,
    originator_host: []const u8,
    originator_port: u32,
};

pub const ChannelOpenRequestType = union(enum) {
    Session,
    DirectTcpip: DirectTcpipOpen,
    ForwardedTcpip: ForwardedTcpipOpen,
};

pub const ChannelOpenRequestEvent = struct {
    channel: u32,
    request: ChannelOpenRequestType,
};

pub const ExtendedData = struct {
    data_type: u32,
    data: []const u8,
};

pub const UserCredentialsPasswordOrPubkey = union(enum) {
    Password: []const u8,
    Pubkey: PublicKeyIdentity,
    KeyboardInteractive: []const u8, // submethods
};

pub const PublicKeyIdentity = struct {
    algorithm: []const u8,
    blob: []const u8,
};

pub const UserCredentials = struct {
    username: []const u8,
    auth: ?UserCredentialsPasswordOrPubkey, // null for "none" auth
};

pub const ChannelRequestType = union(enum) {
    Shell,
    Exec: []const u8,
    Subsystem: []const u8,
    Env: struct { name: []const u8, value: []const u8 },
    AgentForward,
};

pub const ChannelRequestEvent = struct {
    channel: u32,
    request: ChannelRequestType,
};

pub const WindowSize = struct {
    channel: u32,
    cols: u32,
    rows: u32,
    width_px: u32,
    height_px: u32,
};

pub const ChannelSignal = struct {
    channel: u32,
    name: []const u8,
};

pub const ChannelData = struct {
    channel: u32,
    data: []const u8,
};

pub const ChannelExtendedData = struct {
    channel: u32,
    data_type: u32,
    data: []const u8,
};

pub const MisshodServerEventCodes = union(enum) {
    EndSession: EndSessionReason,
    UserAuth: UserCredentials,
    GetPubkeyForUser: []const u8,
    Connected: u32,
    ChannelOpened: u32,
    ChannelOpenFailure: ChannelOpenFailure,
    AgentChannelOpen: u32,
    AgentChannelClosed: u32,
    RxData: ChannelData,
    RxExtendedData: ChannelExtendedData,
    WindowChange: WindowSize,
    Signal: ChannelSignal,
    ChannelRequest: ChannelRequestEvent,
    ChannelOpenRequest: ChannelOpenRequestEvent,
    TcpipForward: TcpipForwardRequest,
    CancelTcpipForward: TcpipForwardRequest,
};

pub fn MisshodEvent(role: Role) type {
    return union(enum) {
        Event: eventCodeType(role),
        ReadyToConsume: usize,
        ReadyToProduce: usize,
        ReadyToConsumeAndProduce: struct { consume: usize, produce: usize },
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
        iostate_rd: IoState(role),
        iostate_wr: IoState(role),

        // full-duplex: separate read and write buffers
        iobuf_rd: [Protocol.MaxSSHPacket]u8 = undefined,
        iobuf_wr: [Protocol.MaxSSHPacket]u8 = undefined,
        iobuf_decompressed: [Protocol.MaxPayload]u8 = undefined,
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
            std.crypto.secureZero(u8, &self.iobuf_decompressed);
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

        pub fn grantAccess(self: *Self, allow: bool) MisshodError!void {
            switch (role) {
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
                                if (comptime role == .Server) {
                                    switch (eventCode) {
                                        .TcpipForward, .CancelTcpipForward => return IoError.badClearEvent,
                                        else => {},
                                    }
                                }
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

            if (can_consume_nbytes > 0 and can_produce_nbytes > 0) {
                return MisshodEvent(role){ .ReadyToConsumeAndProduce = .{ .consume = can_consume_nbytes, .produce = can_produce_nbytes } };
            } else if (can_consume_nbytes > 0) {
                return MisshodEvent(role){ .ReadyToConsume = can_consume_nbytes };
            } else if (can_produce_nbytes > 0) {
                return MisshodEvent(role){ .ReadyToProduce = can_produce_nbytes };
            } else {
                return IoError.NotReady;
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
            const hdr = Protocol.readPktHdr(iobuf[0..Protocol.sizeof_PktHdr]);
            if (hdr.padding_length < 4 or hdr.packet_length < @as(u32, hdr.padding_length) + 1) {
                return IoError.InvalidPacketSize;
            }
            const payload_len: usize = @intCast(hdr.packet_length - @as(u32, hdr.padding_length) - 1);
            if (payload_len > Protocol.MaxPayload) return IoError.InvalidPacketSize;
            const pkt_len = Protocol.sizeof_PktHdr + payload_len + hdr.padding_length;
            if (pkt_len > iobuf.len) return IoError.InvalidPacketSize;
            const payload = iobuf[Protocol.sizeof_PktHdr .. Protocol.sizeof_PktHdr + payload_len];

            if (!self.session.encrypted) {
                const decompressed = try inkeys.compression.decompressPayload(payload, &self.iobuf_decompressed);
                return BufferReader.init(decompressed);
            } else {
                TRACEDUMP(.Debug, "all buf", .{}, iobuf);
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
                    return IoError.InvalidPacketSize; // too small to have a mac
                }
                const rxmac = iobuf[pkt_len..iobuf.len]; // at the end
                var calcmac: [Protocol.mac_algo.key_length]u8 = undefined;
                var m = Protocol.mac_algo.init(inkeys.mackey[0..Protocol.mac_algo.key_length]);
                const seq = std.mem.nativeTo(u32, inkeys.seq - 1, .big); // seq has already been incremented
                m.update(std.mem.asBytes(&seq));
                m.update(iobuf[0..pkt_len]); // plaintext
                m.final(&calcmac);

                TRACEDUMP(.Debug, "rxmac", .{}, rxmac);
                TRACEDUMP(.Debug, "mackey", .{}, inkeys.mackey[0..Protocol.mac_algo.key_length]);
                TRACEDUMP(.Debug, "macseq", .{}, std.mem.asBytes(&seq));
                TRACEDUMP(.Debug, "macdata", .{}, iobuf[0..pkt_len]);
                TRACEDUMP(.Debug, "calcmac", .{}, std.mem.asBytes(&calcmac));

                if (!std.mem.eql(u8, &calcmac, rxmac)) {
                    return IoError.InvalidMac;
                }

                // remove mac and return buffer containing just plaintext payload
                const decrypted_payload = iobuf[Protocol.sizeof_PktHdr .. Protocol.sizeof_PktHdr + payload_len];
                const decompressed = try inkeys.compression.decompressPayload(decrypted_payload, &self.iobuf_decompressed);
                return BufferReader.init(decompressed);
            }
        }

        fn advanceIoSession(self: *Self, inkeys: *Protocol.KeyDataUni) MisshodError!void {
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
                    const sl = self.session.writeProtocolVersion(&self.iobuf_wr);
                    switch (role) {
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
                        const hdr = Protocol.readPktHdr(buf[0..pkthdr_size]);

                        // padding len is such that payload_len + sizeof(hdr) + padding = block size
                        if (hdr.packet_length < @as(u32, hdr.padding_length) + 1) {
                            return IoError.InvalidPacketSize;
                        }
                        const payload_len: usize = @intCast(hdr.packet_length - (@as(u32, hdr.padding_length) + 1));
                        if (hdr.padding_length < 4) {
                            return IoError.InvalidPacketSize;
                        }
                        if (payload_len > Protocol.MaxPayload) {
                            return IoError.InvalidPacketSize;
                        }
                        const pkt_len = payload_len + (Protocol.sizeof_PktHdr) + hdr.padding_length;
                        // avoid reading obviously bad packet sizes
                        if (pkt_len < 8 or pkt_len > Protocol.MaxSSHPacket or pkt_len % Protocol.AesCtrT.block_size != 0) {
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
                        const hdr = Protocol.readPktHdr(buf[0..Protocol.sizeof_PktHdr]);

                        TRACE(.Debug, ".ReadPktBody hdr={any}", .{hdr});
                        // read in payload
                        if (hdr.padding_length < 4 or hdr.packet_length < @as(u32, hdr.padding_length) + 1) {
                            return IoError.InvalidPacketSize;
                        }
                        const payload_len: usize = @intCast(hdr.packet_length - @as(u32, hdr.padding_length) - 1);
                        if (payload_len > Protocol.MaxPayload) return IoError.InvalidPacketSize;

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
            const inkeys = switch (role) {
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

        pub fn getChannelWriteBuffer(self: *Self, channel_id: u32) MisshodError![]u8 {
            return self.session.getChannelWriteBuffer(channel_id);
        }

        pub fn channelWriteComplete(self: *Self, channel_id: u32, nbytes: usize) MisshodError!void {
            if (self.iostate_wr == .Idle and self.iostate_rd != .Idle) {
                try self.session.directChannelWrite(channel_id, nbytes, self);
            } else {
                self.iostate_rd = .Idle;
                self.iostate_wr = .Idle;
                try self.advance();
                try self.session.channelWriteComplete(channel_id, nbytes);
                self.iostate_rd = .Idle;
                self.iostate_wr = .Idle;
                try self.advance();
            }
        }

        pub fn openSessionChannel(self: *Self) MisshodError!u32 {
            return switch (role) {
                .Client => try self.session.openSessionChannel(self),
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn setAutoExecCommand(self: *Self, command: []const u8) MisshodError!void {
            return switch (role) {
                .Client => try self.session.setAutoExecCommand(command),
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn setAutoPty(self: *Self, term: []const u8, cols: u32, rows: u32, width_px: u32, height_px: u32) MisshodError!void {
            return switch (role) {
                .Client => try self.session.setAutoPty(term, cols, rows, width_px, height_px),
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn openDirectTcpipChannel(
            self: *Self,
            host: []const u8,
            port: u32,
            originator_host: []const u8,
            originator_port: u32,
        ) MisshodError!u32 {
            return switch (role) {
                .Client => try self.session.openDirectTcpipChannel(
                    self,
                    host,
                    port,
                    originator_host,
                    originator_port,
                ),
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn openLocalForwardChannel(
            self: *Self,
            host: []const u8,
            port: u32,
            originator_host: []const u8,
            originator_port: u32,
        ) MisshodError!u32 {
            return try self.openDirectTcpipChannel(host, port, originator_host, originator_port);
        }

        pub fn requestRemoteForward(self: *Self, bind_address: []const u8, bind_port: u32) MisshodError!void {
            return switch (role) {
                .Client => try self.session.requestRemoteForward(self, bind_address, bind_port),
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn cancelRemoteForward(self: *Self, bind_address: []const u8, bind_port: u32) MisshodError!void {
            return switch (role) {
                .Client => try self.session.cancelRemoteForward(self, bind_address, bind_port),
                .Server => IoError.UnimplementedService,
            };
        }

        pub fn openForwardedTcpipChannel(
            self: *Self,
            connected_host: []const u8,
            connected_port: u32,
            originator_host: []const u8,
            originator_port: u32,
        ) MisshodError!u32 {
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => try self.session.openForwardedTcpipChannel(
                    self,
                    connected_host,
                    connected_port,
                    originator_host,
                    originator_port,
                ),
            };
        }

        fn clearPendingChannelOpenRequest(self: *Self, channel_id: u32) MisshodError!void {
            switch (self.iostate_wr) {
                .Idle => return,
                .Active => |iotype| switch (iotype.action) {
                    .Eventing => |eventCode| switch (eventCode) {
                        .ChannelOpenRequest => |request| {
                            if (request.channel != channel_id) return IoError.badClearEvent;
                            self.session.setIoSessionState(iotype.next_state);
                            self.iostate_wr = .Idle;
                            return;
                        },
                        else => return IoError.badClearEvent,
                    },
                    else => return IoError.cannotAcceptWrite,
                },
            }
        }

        fn clearPendingTcpipForwardEvent(self: *Self) MisshodError!void {
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => {
                    switch (self.iostate_wr) {
                        .Idle => return IoError.badClearEvent,
                        .Active => |iotype| switch (iotype.action) {
                            .Eventing => |eventCode| switch (eventCode) {
                                .TcpipForward => {
                                    self.session.setIoSessionState(iotype.next_state);
                                    self.iostate_wr = .Idle;
                                },
                                else => return IoError.badClearEvent,
                            },
                            else => return IoError.cannotAcceptWrite,
                        },
                    }
                },
            };
        }

        fn clearPendingCancelTcpipForwardEvent(self: *Self) MisshodError!void {
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => {
                    switch (self.iostate_wr) {
                        .Idle => return IoError.badClearEvent,
                        .Active => |iotype| switch (iotype.action) {
                            .Eventing => |eventCode| switch (eventCode) {
                                .CancelTcpipForward => {
                                    self.session.setIoSessionState(iotype.next_state);
                                    self.iostate_wr = .Idle;
                                },
                                else => return IoError.badClearEvent,
                            },
                            else => return IoError.cannotAcceptWrite,
                        },
                    }
                },
            };
        }

        pub fn acceptTcpipForward(self: *Self, bound_port: u32) MisshodError!void {
            try self.clearPendingTcpipForwardEvent();
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => {
                    try self.session.acceptTcpipForward(self, bound_port);
                    try self.advance();
                },
            };
        }

        pub fn rejectTcpipForward(self: *Self) MisshodError!void {
            try self.clearPendingTcpipForwardEvent();
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => {
                    try self.session.rejectTcpipForward(self);
                    try self.advance();
                },
            };
        }

        pub fn acceptCancelTcpipForward(self: *Self) MisshodError!void {
            try self.clearPendingCancelTcpipForwardEvent();
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => {
                    try self.session.acceptCancelTcpipForward(self);
                    try self.advance();
                },
            };
        }

        pub fn rejectCancelTcpipForward(self: *Self) MisshodError!void {
            try self.clearPendingCancelTcpipForwardEvent();
            return switch (role) {
                .Client => IoError.UnimplementedService,
                .Server => {
                    try self.session.rejectCancelTcpipForward(self);
                    try self.advance();
                },
            };
        }

        pub fn acceptChannelOpen(self: *Self, channel_id: u32) MisshodError!void {
            try self.clearPendingChannelOpenRequest(channel_id);
            try self.session.acceptChannelOpen(channel_id);
            try self.advance();
        }

        pub fn rejectChannelOpen(self: *Self, channel_id: u32, reason_code: u32, description: []const u8) MisshodError!void {
            try self.clearPendingChannelOpenRequest(channel_id);
            try self.session.rejectChannelOpen(channel_id, reason_code, description);
            try self.advance();
        }

        pub fn sendChannelEof(self: *Self, channel_id: u32) MisshodError!void {
            try self.session.sendChannelEof(channel_id);
            self.iostate_wr = .Idle;
            try self.advance();
        }

        pub fn sendChannelClose(self: *Self, channel_id: u32) MisshodError!void {
            try self.session.sendChannelClose(channel_id);
            self.iostate_wr = .Idle;
            try self.advance();
        }

        pub fn enableAgentForwarding(self: *Self) MisshodError!void {
            switch (role) {
                .Client => return try self.session.enableAgentForwarding(),
                .Server => return IoError.UnimplementedService,
            }
        }

        pub fn openAgentChannel(self: *Self) MisshodError!u32 {
            switch (role) {
                .Client => return IoError.UnimplementedService,
                .Server => {
                    self.iostate_rd = .Idle;
                    self.iostate_wr = .Idle;
                    const channel_id = try self.session.openAgentChannel();
                    try self.advance();
                    return channel_id;
                },
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

test "MisshodClientEventCodes agent forwarding variants" {
    const open_evt: MisshodClientEventCodes = .{ .AgentChannelOpen = 3 };
    switch (open_evt) {
        .AgentChannelOpen => |channel| try std.testing.expectEqual(@as(u32, 3), channel),
        else => return error.TestUnexpectedResult,
    }

    const data_evt: MisshodClientEventCodes = .{ .AgentData = .{ .channel = 3, .data = "agent-data" } };
    switch (data_evt) {
        .AgentData => |data| {
            try std.testing.expectEqual(@as(u32, 3), data.channel);
            try std.testing.expectEqualStrings("agent-data", data.data);
        },
        else => return error.TestUnexpectedResult,
    }

    const closed_evt: MisshodClientEventCodes = .{ .AgentChannelClosed = 3 };
    switch (closed_evt) {
        .AgentChannelClosed => |channel| try std.testing.expectEqual(@as(u32, 3), channel),
        else => return error.TestUnexpectedResult,
    }
}

test "ExtendedData struct" {
    const ext: ExtendedData = .{ .data_type = 1, .data = "stderr output" };
    try std.testing.expectEqual(@as(u32, 1), ext.data_type);
    try std.testing.expectEqualStrings("stderr output", ext.data);
}

test "WindowSize struct" {
    const ws: WindowSize = .{ .channel = 0, .cols = 120, .rows = 40, .width_px = 960, .height_px = 640 };
    try std.testing.expectEqual(@as(u32, 120), ws.cols);
    try std.testing.expectEqual(@as(u32, 40), ws.rows);
}

test "MisshodServerEventCodes WindowChange variant" {
    const evt: MisshodServerEventCodes = .{ .WindowChange = .{ .channel = 0, .cols = 80, .rows = 24, .width_px = 640, .height_px = 480 } };
    switch (evt) {
        .WindowChange => |ws| {
            try std.testing.expectEqual(@as(u32, 80), ws.cols);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "MisshodServerEventCodes Signal variant" {
    const evt: MisshodServerEventCodes = .{ .Signal = .{ .channel = 0, .name = "INT" } };
    switch (evt) {
        .Signal => |sig| {
            try std.testing.expectEqualStrings("INT", sig.name);
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

test "ChannelRequestType AgentForward variant" {
    const req: ChannelRequestType = .AgentForward;
    switch (req) {
        .AgentForward => {},
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
                        .CheckHostKey => {
                            client.clearEvent(.{ .CheckHostKey = .{ .raw_key = null, .fingerprint = .{0} ** 32 } }) catch {};
                        },
                        .GetPrivateKey => {
                            client.clearEvent(.GetPrivateKey) catch {};
                        },
                        .GetAuthPassphrase => {
                            client.session.setAuthPassphrase("testpass") catch {};
                            client.clearEvent(.GetAuthPassphrase) catch {};
                        },
                        .Connected => {
                            connected_client = true;
                            client.clearEvent(.Connected) catch {};
                        },
                        .EndSession => {
                            connected_client = false;
                            break;
                        },
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
                        .Connected => {
                            server.clearEvent(.{ .Connected = 0 }) catch {};
                        },
                        .ChannelRequest => {
                            server.clearEvent(.{ .ChannelRequest = .{ .channel = 0, .request = .Shell } }) catch {};
                        },
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

test "init sets both iostates to Idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    try std.testing.expectEqual(IoState(.Client).Idle, m.iostate_rd);
    try std.testing.expectEqual(IoState(.Client).Idle, m.iostate_wr);
    try std.testing.expectEqual(@as(usize, 0), m.rd_nbytes);
    try std.testing.expectEqual(@as(usize, 0), m.rd_off);
    try std.testing.expectEqual(@as(usize, 0), m.wr_nbytes);
    try std.testing.expectEqual(@as(usize, 0), m.wr_off);
}

test "deinit zeros both buffers" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);

    @memset(&m.iobuf_rd, 0xAA);
    @memset(&m.iobuf_wr, 0xBB);

    m.deinit();

    for (m.iobuf_rd) |b| try std.testing.expectEqual(@as(u8, 0), b);
    for (m.iobuf_wr) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "requestRead sets iostate_rd, leaves iostate_wr unchanged" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.requestRead(0, 10, .ReadPktHdr);

    try std.testing.expect(m.iostate_rd != .Idle);
    try std.testing.expectEqual(IoState(.Client).Idle, m.iostate_wr);
    try std.testing.expectEqual(@as(usize, 0), m.rd_nbytes);
    try std.testing.expectEqual(@as(usize, 0), m.rd_off);
}

test "requestWrite sets iostate_wr, leaves iostate_rd unchanged" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Simulate data in write buffer
    const data = "hello";
    @memcpy(m.iobuf_wr[0..data.len], data);
    m.requestWrite(m.iobuf_wr[0..data.len], .Idle);

    try std.testing.expect(m.iostate_wr != .Idle);
    try std.testing.expectEqual(IoState(.Client).Idle, m.iostate_rd);
    try std.testing.expectEqual(@as(usize, data.len), m.wr_nbytes);
    try std.testing.expectEqual(@as(usize, 0), m.wr_off);
}

test "requestEvent sets iostate_wr to Eventing" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.requestEvent(.Connected, .Idle);

    switch (m.iostate_wr) {
        .Active => |step| {
            switch (step.action) {
                .Eventing => {},
                else => return error.TestUnexpectedResult,
            }
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(IoState(.Client).Idle, m.iostate_rd);
}

test "write feeds data into iobuf_rd" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.requestRead(0, 5, .ReadPktHdr);
    try m.write("hel");
    try std.testing.expectEqual(@as(usize, 3), m.rd_nbytes);
    try std.testing.expectEqualStrings("hel", m.iobuf_rd[0..3]);
}

test "write rejects data when iostate_rd is Idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const result = m.write("data");
    try std.testing.expectError(IoError.cannotAcceptWrite, result);
}

test "peek reads from iobuf_wr" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const msg = "world";
    @memcpy(m.iobuf_wr[0..msg.len], msg);
    m.requestWrite(m.iobuf_wr[0..msg.len], .Idle);

    const data = try m.peek(msg.len);
    try std.testing.expectEqualStrings(msg, data);
}

test "peek fails when iostate_wr is Idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const result = m.peek(1);
    try std.testing.expectError(IoError.notProducing, result);
}

test "consumed advances wr_off" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const msg = "abcde";
    @memcpy(m.iobuf_wr[0..msg.len], msg);
    m.requestWrite(m.iobuf_wr[0..msg.len], .Idle);

    try m.consumed(2);
    try std.testing.expectEqual(@as(usize, 2), m.wr_off);
}

test "consumed fails when iostate_wr is Idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const result = m.consumed(1);
    try std.testing.expectError(IoError.notProducing, result);
}

test "getNextEvent returns Event when Eventing" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.requestEvent(.Connected, .Idle);
    const ev = try m.getNextEvent();
    switch (ev) {
        .Event => |code| switch (code) {
            .Connected => {},
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "getNextEvent returns ReadyToConsume when only read is active" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Set ioSessionState to ReadPktHdr so advance() doesn't try to process Idle
    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, 10, .ReadPktHdr);
    const ev = try m.getNextEvent();
    switch (ev) {
        .ReadyToConsume => |n| try std.testing.expectEqual(@as(usize, 10), n),
        else => return error.TestUnexpectedResult,
    }
}

test "getNextEvent returns ReadyToProduce when only write is active" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Set ioSessionState to Idle; with write active, canProcessIoSessionState(.Idle)
    // requires both idle, so advance won't process it
    m.session.setIoSessionState(.Idle);
    const msg = "data";
    @memcpy(m.iobuf_wr[0..msg.len], msg);
    m.requestWrite(m.iobuf_wr[0..msg.len], .Idle);
    const ev = try m.getNextEvent();
    switch (ev) {
        .ReadyToProduce => |n| try std.testing.expectEqual(@as(usize, msg.len), n),
        else => return error.TestUnexpectedResult,
    }
}

test "getNextEvent returns ReadyToConsumeAndProduce when both active" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setIoSessionState(.ReadPktHdr);
    m.requestRead(0, 10, .ReadPktHdr);
    const msg = "data";
    @memcpy(m.iobuf_wr[0..msg.len], msg);
    m.requestWrite(m.iobuf_wr[0..msg.len], .Idle);

    const ev = try m.getNextEvent();
    switch (ev) {
        .ReadyToConsumeAndProduce => |s| {
            try std.testing.expectEqual(@as(usize, 10), s.consume);
            try std.testing.expectEqual(@as(usize, msg.len), s.produce);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "clearEvent resets iostate_wr from Eventing to Idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.requestEvent(.Connected, .Idle);
    try std.testing.expect(m.iostate_wr != .Idle);

    try m.clearEvent(.Connected);
    // After clearing, advance() runs and may set new states,
    // but the event was cleared successfully (no error returned)
}

test "clearEvent fails for wrong event code" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.requestEvent(.Connected, .Idle);
    const result = m.clearEvent(.GetPrivateKey);
    try std.testing.expectError(IoError.badClearEvent, result);
}

test "clearEvent fails when not eventing" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    const result = m.clearEvent(.Connected);
    try std.testing.expectError(IoError.badClearEvent, result);
}

test "read and write buffers are independent" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    // Fill read buffer
    @memset(&m.iobuf_rd, 0x11);
    // Fill write buffer
    @memset(&m.iobuf_wr, 0x22);

    // Verify they don't alias
    try std.testing.expectEqual(@as(u8, 0x11), m.iobuf_rd[0]);
    try std.testing.expectEqual(@as(u8, 0x22), m.iobuf_wr[0]);
    try std.testing.expect(&m.iobuf_rd[0] != &m.iobuf_wr[0]);
}

test "simultaneous read and write I/O: data does not cross-contaminate" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setIoSessionState(.ReadPktHdr);

    // Start a read (consuming 5 bytes)
    m.requestRead(0, 5, .ReadPktHdr);

    // Start a write (producing 3 bytes)
    const wr_data = "abc";
    @memcpy(m.iobuf_wr[0..wr_data.len], wr_data);
    m.requestWrite(m.iobuf_wr[0..wr_data.len], .Idle);

    // Feed data to read side
    try m.write("xy");
    try std.testing.expectEqual(@as(usize, 2), m.rd_nbytes);
    try std.testing.expectEqualStrings("xy", m.iobuf_rd[0..2]);

    // Drain data from write side
    const peeked = try m.peek(3);
    try std.testing.expectEqualStrings("abc", peeked);
    try m.consumed(3);

    // Write side done, read side still has 3 bytes to go
    try std.testing.expectEqual(IoState(.Client).Idle, m.iostate_wr);
    try std.testing.expect(m.iostate_rd != .Idle);
}

test "canProcessIoSessionState: Idle requires both sides idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setIoSessionState(.Idle);
    m.iostate_rd = .Idle;
    m.iostate_wr = .Idle;
    try std.testing.expect(m.canProcessIoSessionState());

    // If read is active, Idle should not be processable
    m.requestRead(0, 1, .ReadPktHdr);
    try std.testing.expect(!m.canProcessIoSessionState());
}

test "canProcessIoSessionState: ReadPktHdr only needs read idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setIoSessionState(.ReadPktHdr);
    m.iostate_rd = .Idle;
    // Write side active should not block read states
    const wr_data = "x";
    @memcpy(m.iobuf_wr[0..wr_data.len], wr_data);
    m.requestWrite(m.iobuf_wr[0..wr_data.len], .Idle);

    try std.testing.expect(m.canProcessIoSessionState());
}

test "canProcessIoSessionState: VersionWrite needs write idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setIoSessionState(.VersionWrite);
    m.iostate_wr = .Idle;
    try std.testing.expect(m.canProcessIoSessionState());

    const wr_data = "x";
    @memcpy(m.iobuf_wr[0..wr_data.len], wr_data);
    m.requestWrite(m.iobuf_wr[0..wr_data.len], .Idle);
    try std.testing.expect(!m.canProcessIoSessionState());
}

test "canProcessIoSessionState: ReadPktCompletion needs write idle" {
    var prng = std.Random.DefaultPrng.init(42);
    var m = try MisshodClient.init(prng.random(), "testuser", std.testing.allocator);
    defer m.deinit();

    m.session.setIoSessionState(.{ .ReadPktCompletion = m.iobuf_rd[0..0] });
    m.iostate_wr = .Idle;
    try std.testing.expect(m.canProcessIoSessionState());

    // With write active, ReadPktCompletion should be blocked
    const wr_data = "x";
    @memcpy(m.iobuf_wr[0..wr_data.len], wr_data);
    m.requestWrite(m.iobuf_wr[0..wr_data.len], .Idle);
    try std.testing.expect(!m.canProcessIoSessionState());
}

test "ReadyToConsumeAndProduce struct fields" {
    const ev = MisshodEvent(.Client){ .ReadyToConsumeAndProduce = .{ .consume = 100, .produce = 50 } };
    switch (ev) {
        .ReadyToConsumeAndProduce => |s| {
            try std.testing.expectEqual(@as(usize, 100), s.consume);
            try std.testing.expectEqual(@as(usize, 50), s.produce);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "full handshake round-trip then channel data exchange" {
    const privkey = @import("privkey.zig");

    var cprng = std.Random.DefaultPrng.init(10);
    var sprng = std.Random.DefaultPrng.init(20);

    var client = try MisshodClient.init(cprng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    var server = try MisshodServer.init(sprng.random(), privkey.testkey_valid, std.testing.allocator);
    defer server.deinit();

    var c2s_buf: [16384]u8 = undefined;
    var s2c_buf: [16384]u8 = undefined;
    var c2s_len: usize = 0;
    var s2c_len: usize = 0;

    var connected_client = false;
    var connected_server = false;
    var server_sent_data = false;
    var client_rx_data: bool = false;

    const Endpoint = enum { client_ep, server_ep };
    const endpoints = [_]Endpoint{ .client_ep, .server_ep };

    var steps: usize = 0;
    while (steps < 1000) : (steps += 1) {
        if (client_rx_data) break;

        for (endpoints) |ep| {
            if (ep == .client_ep) {
                const cev = client.getNextEvent() catch continue;
                switch (cev) {
                    .ReadyToProduce, .ReadyToConsumeAndProduce => {
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
                    .Event => |code| switch (code) {
                        .CheckHostKey => client.clearEvent(.{ .CheckHostKey = .{ .raw_key = null, .fingerprint = .{0} ** 32 } }) catch {},
                        .GetPrivateKey => client.clearEvent(.GetPrivateKey) catch {},
                        .GetAuthPassphrase => {
                            client.session.setAuthPassphrase("testpass") catch {};
                            client.clearEvent(.GetAuthPassphrase) catch {};
                        },
                        .Connected => {
                            connected_client = true;
                            client.clearEvent(.Connected) catch {};
                        },
                        .RxData => |data| {
                            if (data.len > 0) client_rx_data = true;
                            client.clearEvent(.{ .RxData = data }) catch {};
                        },
                        .EndSession => break,
                        else => {
                            client.clearEvent(code) catch {};
                        },
                    },
                }
            } else {
                const sev = server.getNextEvent() catch continue;
                switch (sev) {
                    .ReadyToProduce, .ReadyToConsumeAndProduce => {
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
                    .Event => |code| switch (code) {
                        .UserAuth => {
                            server.grantAccess(true) catch {};
                            server.clearEvent(.{ .UserAuth = .{ .username = "", .auth = null } }) catch {};
                        },
                        .Connected => {
                            connected_server = true;
                            server.clearEvent(.{ .Connected = 0 }) catch {};
                        },
                        .ChannelRequest => server.clearEvent(.{ .ChannelRequest = .{ .channel = 0, .request = .Shell } }) catch {},
                        else => {
                            server.clearEvent(code) catch {};
                        },
                    },
                }

                // After server connects and event loop is clear, send channel data
                if (connected_server and !server_sent_data and server.iostate_wr == .Idle) {
                    const buf = server.getChannelWriteBuffer(0) catch continue;
                    if (buf.len > 0) {
                        const msg = "hello from server";
                        @memcpy(buf[0..msg.len], msg);
                        server.channelWriteComplete(0, msg.len) catch continue;
                        server_sent_data = true;
                    }
                }
            }
        }
    }

    try std.testing.expect(connected_client);
    try std.testing.expect(connected_server);
    try std.testing.expect(client_rx_data);
    try std.testing.expectEqual(Protocol.CompressionAlgorithm.ZlibOpenSsh, client.session.keydata.c2s.compression.algorithm);
    try std.testing.expectEqual(Protocol.CompressionAlgorithm.ZlibOpenSsh, client.session.keydata.s2c.compression.algorithm);
    try std.testing.expectEqual(Protocol.CompressionAlgorithm.ZlibOpenSsh, server.session.keydata.c2s.compression.algorithm);
    try std.testing.expectEqual(Protocol.CompressionAlgorithm.ZlibOpenSsh, server.session.keydata.s2c.compression.algorithm);
    try std.testing.expect(client.session.keydata.c2s.compression.active);
    try std.testing.expect(client.session.keydata.s2c.compression.active);
    try std.testing.expect(server.session.keydata.c2s.compression.active);
    try std.testing.expect(server.session.keydata.s2c.compression.active);
}

test "client channelWriteComplete uses direct write when read is active" {
    const privkey = @import("privkey.zig");

    var cprng = std.Random.DefaultPrng.init(100);
    var sprng = std.Random.DefaultPrng.init(200);

    var client = try MisshodClient.init(cprng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    var server = try MisshodServer.init(sprng.random(), privkey.testkey_valid, std.testing.allocator);
    defer server.deinit();

    var c2s_buf: [16384]u8 = undefined;
    var s2c_buf: [16384]u8 = undefined;
    var c2s_len: usize = 0;
    var s2c_len: usize = 0;

    var connected_client = false;
    var sent_channel_data = false;
    var duplex_event_seen = false;

    const Endpoint = enum { client_ep, server_ep };
    const endpoints = [_]Endpoint{ .client_ep, .server_ep };

    var steps: usize = 0;
    while (steps < 1000) : (steps += 1) {
        if (sent_channel_data and duplex_event_seen) break;

        for (endpoints) |ep| {
            if (ep == .client_ep) {
                const cev = client.getNextEvent() catch continue;
                switch (cev) {
                    .ReadyToProduce => {
                        const data = client.peek(Protocol.MaxSSHPacket) catch continue;
                        @memcpy(c2s_buf[c2s_len .. c2s_len + data.len], data);
                        c2s_len += data.len;
                        client.consumed(data.len) catch {};
                    },
                    .ReadyToConsume => |n| {
                        // After connecting, try to send channel data while reading
                        if (connected_client and !sent_channel_data) {
                            const buf = client.getChannelWriteBuffer(0) catch continue;
                            if (buf.len > 0) {
                                const msg = "keyboard-input";
                                @memcpy(buf[0..msg.len], msg);
                                client.channelWriteComplete(0, msg.len) catch {};
                                sent_channel_data = true;
                            }
                        }
                        if (s2c_len > 0) {
                            const feed = @min(n, s2c_len);
                            client.write(s2c_buf[0..feed]) catch {};
                            std.mem.copyForwards(u8, &s2c_buf, s2c_buf[feed..s2c_len]);
                            s2c_len -= feed;
                        }
                    },
                    .ReadyToConsumeAndProduce => |s| {
                        duplex_event_seen = true;
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
                        .CheckHostKey => client.clearEvent(.{ .CheckHostKey = .{ .raw_key = null, .fingerprint = .{0} ** 32 } }) catch {},
                        .GetPrivateKey => client.clearEvent(.GetPrivateKey) catch {},
                        .GetAuthPassphrase => {
                            client.session.setAuthPassphrase("testpass") catch {};
                            client.clearEvent(.GetAuthPassphrase) catch {};
                        },
                        .Connected => {
                            connected_client = true;
                            client.clearEvent(.Connected) catch {};
                        },
                        .EndSession => break,
                        else => {
                            client.clearEvent(code) catch {};
                        },
                    },
                }
            } else {
                const sev = server.getNextEvent() catch continue;
                switch (sev) {
                    .ReadyToProduce, .ReadyToConsumeAndProduce => {
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
                    .Event => |code| switch (code) {
                        .UserAuth => {
                            server.grantAccess(true) catch {};
                            server.clearEvent(.{ .UserAuth = .{ .username = "", .auth = null } }) catch {};
                        },
                        .Connected => server.clearEvent(.{ .Connected = 0 }) catch {},
                        .ChannelRequest => server.clearEvent(.{ .ChannelRequest = .{ .channel = 0, .request = .Shell } }) catch {},
                        else => {
                            server.clearEvent(code) catch {};
                        },
                    },
                }
            }
        }
    }

    try std.testing.expect(connected_client);
    try std.testing.expect(sent_channel_data);
}

fn driveHandshakeForKeys(hostkey_ascii: []const u8, client_key_ascii: ?[]const u8, expected_pubkey_algorithm: ?[]const u8) !void {
    var cprng = std.Random.DefaultPrng.init(1000);
    var sprng = std.Random.DefaultPrng.init(2000);

    var client = try MisshodClient.init(cprng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    var server = try MisshodServer.init(sprng.random(), hostkey_ascii, std.testing.allocator);
    defer server.deinit();

    var c2s_buf: [65536]u8 = undefined;
    var s2c_buf: [65536]u8 = undefined;
    var c2s_len: usize = 0;
    var s2c_len: usize = 0;
    var connected_client = false;
    var saw_expected_pubkey = expected_pubkey_algorithm == null;

    const Endpoint = enum { client_ep, server_ep };
    const endpoints = [_]Endpoint{ .client_ep, .server_ep };

    var steps: usize = 0;
    while (steps < 2000) : (steps += 1) {
        if (connected_client and saw_expected_pubkey) break;

        for (endpoints) |ep| {
            if (ep == .client_ep) {
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
                        .CheckHostKey => client.clearEvent(.{ .CheckHostKey = .{ .raw_key = null, .fingerprint = .{0} ** 32 } }) catch {},
                        .GetPrivateKey => {
                            if (client_key_ascii) |key| client.setPrivateKey(key) catch {};
                            client.clearEvent(.GetPrivateKey) catch {};
                        },
                        .GetAuthPassphrase => {
                            client.session.setAuthPassphrase("testpass") catch {};
                            client.clearEvent(.GetAuthPassphrase) catch {};
                        },
                        .Connected => {
                            connected_client = true;
                            client.clearEvent(.Connected) catch {};
                        },
                        .EndSession => break,
                        else => {
                            client.clearEvent(code) catch {};
                        },
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
                        .UserAuth => |credentials| {
                            if (expected_pubkey_algorithm) |expected| {
                                if (credentials.auth) |auth| switch (auth) {
                                    .Pubkey => |pubkey| {
                                        try std.testing.expectEqualStrings(expected, pubkey.algorithm);
                                        try std.testing.expect(pubkey.blob.len > 0);
                                        saw_expected_pubkey = true;
                                    },
                                    else => {},
                                };
                            }
                            server.grantAccess(true) catch {};
                            server.clearEvent(.{ .UserAuth = .{ .username = "", .auth = null } }) catch {};
                        },
                        .Connected => server.clearEvent(.{ .Connected = 0 }) catch {},
                        .ChannelRequest => server.clearEvent(.{ .ChannelRequest = .{ .channel = 0, .request = .Shell } }) catch {},
                        else => {
                            server.clearEvent(code) catch {};
                        },
                    },
                }
            }
        }
    }

    try std.testing.expect(connected_client);
    try std.testing.expect(saw_expected_pubkey);
}

test "handshake supports ECDSA and RSA host keys" {
    const privkey = @import("privkey.zig");
    try driveHandshakeForKeys(privkey.testkey_ecdsa_p256, null, null);
    try driveHandshakeForKeys(privkey.testkey_rsa_2048, null, null);
}

test "public key auth supports Ed25519 ECDSA and RSA SHA2 keys" {
    const privkey = @import("privkey.zig");
    try driveHandshakeForKeys(privkey.testkey_valid, privkey.testkey_valid, "ssh-ed25519");
    try driveHandshakeForKeys(privkey.testkey_valid, privkey.testkey_ecdsa_p256, "ecdsa-sha2-nistp256");
    try driveHandshakeForKeys(privkey.testkey_valid, privkey.testkey_rsa_2048, "rsa-sha2-512");
}
