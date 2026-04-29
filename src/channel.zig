const std = @import("std");
const Protocol = @import("protocol.zig");

pub const MaxChannels = 4;

pub const ClientChannelOpenMode = enum {
    AutoShell,
    RawSession,
};

pub const ChannelType = enum {
    Session,
    DirectTcpip,
    ForwardedTcpip,

    pub fn name(self: ChannelType) []const u8 {
        return switch (self) {
            .Session => "session",
            .DirectTcpip => "direct-tcpip",
            .ForwardedTcpip => "forwarded-tcpip",
        };
    }

    pub fn fromName(channel_name: []const u8) ?ChannelType {
        if (std.mem.eql(u8, channel_name, "session")) return .Session;
        if (std.mem.eql(u8, channel_name, "direct-tcpip")) return .DirectTcpip;
        if (std.mem.eql(u8, channel_name, "forwarded-tcpip")) return .ForwardedTcpip;
        return null;
    }

    pub fn hasTcpipOpenPayload(self: ChannelType) bool {
        return switch (self) {
            .Session => false,
            .DirectTcpip, .ForwardedTcpip => true,
        };
    }
};

pub const TcpipOpen = struct {
    host: []const u8 = "",
    port: u32 = 0,
    originator_host: []const u8 = "",
    originator_port: u32 = 0,
};

pub const ChannelState = enum {
    OpenWrite,
    Open,
    ConfirmWrite,
    RspWrite,
    Connected,
    Data,
    DataRx,
    DataTx,
    DataTxComplete,
    EofWrite,
    CloseWrite,
    Closed,
    OpenFailureWrite,
};

pub const Channel = struct {
    const Self = @This();

    local_id: u32,
    remote_id: u32,
    peer_window: u32,
    remote_max_packet_size: u32,
    local_window: u32,
    write_buf: [Protocol.MaxChannelDataLen]u8 = undefined,
    write_buf_nbytes: usize,
    eof_sent: bool,
    eof_received: bool,
    close_sent: bool,
    close_received: bool,
    client_open_mode: ClientChannelOpenMode,
    channel_type: ChannelType,
    tcpip_open: TcpipOpen,
    open_failure_reason_code: u32,
    open_failure_description: []const u8,
    state: ChannelState,

    pub fn init(local_id: u32, remote_id: u32, peer_window: u32, remote_max_packet_size: u32) Self {
        return Self{
            .local_id = local_id,
            .remote_id = remote_id,
            .peer_window = peer_window,
            .remote_max_packet_size = remote_max_packet_size,
            .local_window = Protocol.MaxPayload,
            .write_buf_nbytes = 0,
            .eof_sent = false,
            .eof_received = false,
            .close_sent = false,
            .close_received = false,
            .client_open_mode = .RawSession,
            .channel_type = .Session,
            .tcpip_open = .{},
            .open_failure_reason_code = 4,
            .open_failure_description = "too many channels",
            .state = .Open,
        };
    }

    pub fn secureZero(self: *Self) void {
        std.crypto.secureZero(u8, &self.write_buf);
    }

    /// Decrement local_window by the amount of data received.
    pub fn consumeLocalWindow(self: *Self, len: u32) void {
        self.local_window -|= len; // saturating subtract
    }

    /// Returns true if local_window has dropped below the replenish threshold.
    pub fn needsWindowAdjust(self: *const Self) bool {
        return self.local_window < Protocol.MaxPayload / 2;
    }

    /// Returns the number of bytes to add to bring local_window back to MaxPayload.
    pub fn windowAdjustAmount(self: *const Self) u32 {
        return Protocol.MaxPayload - self.local_window;
    }
};

pub const ChannelTable = struct {
    const Self = @This();

    channels: [MaxChannels]?Channel = .{null} ** MaxChannels,
    next_local_id: u32 = 0,
    last_serviced_slot: usize = 0,

    pub fn allocChannel(self: *Self, remote_id: u32, peer_window: u32, remote_max_packet_size: u32) ?*Channel {
        const local_id = self.next_local_id;
        for (&self.channels) |*slot| {
            if (slot.* == null) {
                slot.* = Channel.init(local_id, remote_id, peer_window, remote_max_packet_size);
                self.next_local_id +%= 1;
                return &(slot.*.?);
            }
        }
        return null; // table full
    }

    pub fn findByLocalId(self: *Self, local_id: u32) ?*Channel {
        for (&self.channels) |*slot| {
            if (slot.*) |*ch| {
                if (ch.local_id == local_id) return ch;
            }
        }
        return null;
    }

    pub fn findByRemoteId(self: *Self, remote_id: u32) ?*Channel {
        for (&self.channels) |*slot| {
            if (slot.*) |*ch| {
                if (ch.remote_id == remote_id) return ch;
            }
        }
        return null;
    }

    pub fn freeChannel(self: *Self, local_id: u32) void {
        for (&self.channels) |*slot| {
            if (slot.*) |*ch| {
                if (ch.local_id == local_id) {
                    ch.secureZero();
                    slot.* = null;
                    return;
                }
            }
        }
    }

    pub fn activeCount(self: *const Self) u32 {
        var count: u32 = 0;
        for (self.channels) |slot| {
            if (slot != null) count += 1;
        }
        return count;
    }

    pub fn secureZeroAll(self: *Self) void {
        for (&self.channels) |*slot| {
            if (slot.*) |*ch| {
                ch.secureZero();
                slot.* = null;
            }
        }
    }

    fn isRunnable(state: ChannelState) bool {
        return switch (state) {
            .OpenWrite, .ConfirmWrite, .RspWrite, .CloseWrite, .OpenFailureWrite, .EofWrite => true,
            .Connected => true,
            .Data => true,
            .DataTx, .DataTxComplete => true,
            .DataRx, .Open, .Closed => false,
        };
    }

    /// Find the next channel that has pending work, using round-robin
    /// starting after `last_serviced_slot` to ensure fairness.
    pub fn findNextRunnable(self: *Self) ?*Channel {
        var i: usize = 0;
        while (i < MaxChannels) : (i += 1) {
            const slot_idx = (self.last_serviced_slot + 1 + i) % MaxChannels;
            if (self.channels[slot_idx]) |*ch| {
                if (isRunnable(ch.state)) {
                    self.last_serviced_slot = slot_idx;
                    return ch;
                }
            }
        }
        return null;
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

test "allocChannel assigns monotonic local IDs" {
    var table = ChannelTable{};
    const ch0 = table.allocChannel(100, 32768, 32768).?;
    try std.testing.expectEqual(@as(u32, 0), ch0.local_id);
    try std.testing.expectEqual(@as(u32, 100), ch0.remote_id);

    const ch1 = table.allocChannel(200, 32768, 32768).?;
    try std.testing.expectEqual(@as(u32, 1), ch1.local_id);

    try std.testing.expectEqual(@as(u32, 2), table.activeCount());
}

test "findByLocalId and findByRemoteId" {
    var table = ChannelTable{};
    _ = table.allocChannel(100, 32768, 32768);
    _ = table.allocChannel(200, 16384, 16384);

    const found = table.findByLocalId(1).?;
    try std.testing.expectEqual(@as(u32, 200), found.remote_id);

    const found2 = table.findByRemoteId(100).?;
    try std.testing.expectEqual(@as(u32, 0), found2.local_id);

    try std.testing.expect(table.findByLocalId(99) == null);
    try std.testing.expect(table.findByRemoteId(999) == null);
}

test "freeChannel removes channel and allows reuse of slot" {
    var table = ChannelTable{};
    _ = table.allocChannel(100, 32768, 32768);
    _ = table.allocChannel(200, 32768, 32768);
    try std.testing.expectEqual(@as(u32, 2), table.activeCount());

    table.freeChannel(0);
    try std.testing.expectEqual(@as(u32, 1), table.activeCount());
    try std.testing.expect(table.findByLocalId(0) == null);

    // slot is reused but ID continues monotonically
    const ch = table.allocChannel(300, 32768, 32768).?;
    try std.testing.expectEqual(@as(u32, 2), ch.local_id);
}

test "allocChannel returns null when table is full" {
    var table = ChannelTable{};
    var i: u32 = 0;
    while (i < MaxChannels) : (i += 1) {
        try std.testing.expect(table.allocChannel(i + 100, 32768, 32768) != null);
    }
    try std.testing.expect(table.allocChannel(999, 32768, 32768) == null);
}

test "Channel init sets default values" {
    const ch = Channel.init(0, 42, 65535, 32768);
    try std.testing.expectEqual(@as(u32, 0), ch.local_id);
    try std.testing.expectEqual(@as(u32, 42), ch.remote_id);
    try std.testing.expectEqual(@as(u32, 65535), ch.peer_window);
    try std.testing.expectEqual(@as(u32, 32768), ch.remote_max_packet_size);
    try std.testing.expectEqual(Protocol.MaxPayload, ch.local_window);
    try std.testing.expectEqual(@as(usize, 0), ch.write_buf_nbytes);
    try std.testing.expect(!ch.eof_sent);
    try std.testing.expect(!ch.eof_received);
    try std.testing.expect(!ch.close_sent);
    try std.testing.expect(!ch.close_received);
    try std.testing.expectEqual(ClientChannelOpenMode.RawSession, ch.client_open_mode);
    try std.testing.expectEqual(ChannelType.Session, ch.channel_type);
    try std.testing.expectEqualStrings("", ch.tcpip_open.host);
    try std.testing.expectEqual(@as(u32, 0), ch.tcpip_open.port);
    try std.testing.expectEqualStrings("", ch.tcpip_open.originator_host);
    try std.testing.expectEqual(@as(u32, 0), ch.tcpip_open.originator_port);
    try std.testing.expectEqual(@as(u32, 4), ch.open_failure_reason_code);
    try std.testing.expectEqualStrings("too many channels", ch.open_failure_description);
    try std.testing.expectEqual(ChannelState.Open, ch.state);
}

test "ChannelType maps SSH names" {
    try std.testing.expectEqual(ChannelType.Session, ChannelType.fromName("session").?);
    try std.testing.expectEqual(ChannelType.DirectTcpip, ChannelType.fromName("direct-tcpip").?);
    try std.testing.expectEqual(ChannelType.ForwardedTcpip, ChannelType.fromName("forwarded-tcpip").?);
    try std.testing.expect(ChannelType.fromName("x11") == null);
    try std.testing.expectEqualStrings("direct-tcpip", ChannelType.DirectTcpip.name());
    try std.testing.expect(ChannelType.DirectTcpip.hasTcpipOpenPayload());
    try std.testing.expect(!ChannelType.Session.hasTcpipOpenPayload());
}

test "closing one channel does not affect another" {
    var table = ChannelTable{};
    _ = table.allocChannel(100, 32768, 32768);
    const ch1 = table.allocChannel(200, 16384, 16384).?;
    ch1.state = .DataRx;

    table.freeChannel(0);
    try std.testing.expectEqual(@as(u32, 1), table.activeCount());

    const remaining = table.findByLocalId(1).?;
    try std.testing.expectEqual(@as(u32, 200), remaining.remote_id);
    try std.testing.expectEqual(ChannelState.DataRx, remaining.state);
}

test "per-channel window management is independent" {
    var table = ChannelTable{};
    const ch0 = table.allocChannel(10, 1000, 32768).?;
    const ch1 = table.allocChannel(20, 5000, 32768).?;

    try std.testing.expectEqual(@as(u32, 1000), ch0.peer_window);
    try std.testing.expectEqual(@as(u32, 5000), ch1.peer_window);

    ch0.peer_window +|= 2000;
    try std.testing.expectEqual(@as(u32, 3000), ch0.peer_window);
    try std.testing.expectEqual(@as(u32, 5000), ch1.peer_window);
}

test "secureZeroAll clears all channels" {
    var table = ChannelTable{};
    const ch0 = table.allocChannel(10, 32768, 32768).?;
    ch0.write_buf[0] = 0xAA;
    _ = table.allocChannel(20, 32768, 32768);

    table.secureZeroAll();
    try std.testing.expectEqual(@as(u32, 0), table.activeCount());
}

test "findNextRunnable round-robin alternates between two runnable channels" {
    var table = ChannelTable{};
    const ch0 = table.allocChannel(10, 32768, 32768).?;
    const ch1 = table.allocChannel(20, 32768, 32768).?;
    ch0.state = .Data;
    ch1.state = .Data;

    // First call should return one channel
    const first = table.findNextRunnable().?;
    const first_id = first.local_id;

    // Second call should return the other channel
    const second = table.findNextRunnable().?;
    const second_id = second.local_id;

    try std.testing.expect(first_id != second_id);

    // Third call wraps back to the first
    const third = table.findNextRunnable().?;
    try std.testing.expectEqual(first_id, third.local_id);
}

test "findNextRunnable returns single runnable regardless of cursor" {
    var table = ChannelTable{};
    _ = table.allocChannel(10, 32768, 32768); // slot 0, state Open (not runnable)
    const ch1 = table.allocChannel(20, 32768, 32768).?; // slot 1
    ch1.state = .Data;

    // Should always find ch1
    const r1 = table.findNextRunnable().?;
    try std.testing.expectEqual(@as(u32, 1), r1.local_id);

    const r2 = table.findNextRunnable().?;
    try std.testing.expectEqual(@as(u32, 1), r2.local_id);
}

test "findNextRunnable skips freed slots" {
    var table = ChannelTable{};
    const ch0 = table.allocChannel(10, 32768, 32768).?;
    ch0.state = .Data;
    const ch1 = table.allocChannel(20, 32768, 32768).?;
    ch1.state = .Data;

    // Service ch0 first
    _ = table.findNextRunnable();

    // Free ch0
    table.freeChannel(0);

    // Should find ch1
    const r = table.findNextRunnable().?;
    try std.testing.expectEqual(@as(u32, 1), r.local_id);
}

test "findNextRunnable wraps from last slot to slot 0" {
    var table = ChannelTable{};
    // Fill all slots
    var i: u32 = 0;
    while (i < MaxChannels) : (i += 1) {
        const ch = table.allocChannel(i + 100, 32768, 32768).?;
        ch.state = .DataRx; // not runnable
    }
    // Make only slot 0 runnable
    table.channels[0].?.state = .Data;
    // Set cursor to last slot so next scan wraps to 0
    table.last_serviced_slot = MaxChannels - 1;

    const r = table.findNextRunnable().?;
    try std.testing.expectEqual(@as(u32, 0), r.local_id);
    try std.testing.expectEqual(@as(usize, 0), table.last_serviced_slot);
}

test "findNextRunnable returns null when no channels runnable" {
    var table = ChannelTable{};
    const ch0 = table.allocChannel(10, 32768, 32768).?;
    ch0.state = .DataRx;
    const ch1 = table.allocChannel(20, 32768, 32768).?;
    ch1.state = .DataRx;
    try std.testing.expect(table.findNextRunnable() == null);
}

test "OpenWrite channel state is runnable" {
    var table = ChannelTable{};
    const ch = table.allocChannel(10, 32768, 32768).?;
    ch.state = .OpenWrite;

    const runnable = table.findNextRunnable().?;
    try std.testing.expectEqual(ch.local_id, runnable.local_id);
}

test "consumeLocalWindow decrements local_window" {
    var ch = Channel.init(0, 1, 32768, 32768);
    const initial = ch.local_window;
    ch.consumeLocalWindow(100);
    try std.testing.expectEqual(initial - 100, ch.local_window);
}

test "consumeLocalWindow saturates at zero" {
    var ch = Channel.init(0, 1, 32768, 32768);
    ch.local_window = 50;
    ch.consumeLocalWindow(200);
    try std.testing.expectEqual(@as(u32, 0), ch.local_window);
}

test "needsWindowAdjust triggers below half MaxPayload" {
    var ch = Channel.init(0, 1, 32768, 32768);
    // At full window — no adjust needed
    try std.testing.expect(!ch.needsWindowAdjust());

    // Just above threshold — no adjust
    ch.local_window = Protocol.MaxPayload / 2;
    try std.testing.expect(!ch.needsWindowAdjust());

    // Below threshold — adjust needed
    ch.local_window = Protocol.MaxPayload / 2 - 1;
    try std.testing.expect(ch.needsWindowAdjust());
}

test "windowAdjustAmount replenishes to MaxPayload" {
    var ch = Channel.init(0, 1, 32768, 32768);
    ch.local_window = 100;
    const adjust = ch.windowAdjustAmount();
    try std.testing.expectEqual(Protocol.MaxPayload - 100, adjust);

    // After applying the adjust, window should be MaxPayload
    ch.local_window += adjust;
    try std.testing.expectEqual(Protocol.MaxPayload, ch.local_window);
}

test "EofWrite is a runnable state" {
    var table = ChannelTable{};
    const ch = table.allocChannel(10, 32768, 32768).?;
    ch.state = .EofWrite;
    const runnable = table.findNextRunnable();
    try std.testing.expect(runnable != null);
    try std.testing.expectEqual(@as(u32, 0), runnable.?.local_id);
}

test "eof_sent and eof_received start false" {
    const ch = Channel.init(0, 1, 32768, 32768);
    try std.testing.expect(!ch.eof_sent);
    try std.testing.expect(!ch.eof_received);
}
