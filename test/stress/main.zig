const std = @import("std");
const misshod = @import("misshod");

const MiB: u64 = 1024 * 1024;
const channel_count = 4;
const chunk_size: usize = 16 * 1024;
const transfer_bytes_per_direction: u64 = 32 * MiB;
const pipe_capacity = 128 * 1024;
const host_key = @embedFile("stress_host_key");

const BytePipe = struct {
    data: [pipe_capacity]u8 = undefined,
    len: usize = 0,

    fn append(self: *BytePipe, bytes: []const u8) !void {
        if (bytes.len > self.data.len - self.len) return error.TransportQueueFull;
        @memcpy(self.data[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn consume(self: *BytePipe, count: usize) void {
        std.debug.assert(count <= self.len);
        std.mem.copyForwards(u8, &self.data, self.data[count..self.len]);
        self.len -= count;
    }
};

const Direction = enum(u8) {
    client_to_server = 1,
    server_to_client = 2,
};

const DirectionDigests = struct {
    sent: [32]u8,
    received: [32]u8,
};

const DirectionState = struct {
    direction: Direction,
    seed: u64,
    sent: [channel_count]u64 = .{0} ** channel_count,
    received: [channel_count]u64 = .{0} ** channel_count,
    sent_hashers: [channel_count]std.crypto.hash.sha2.Sha256,
    received_hashers: [channel_count]std.crypto.hash.sha2.Sha256,
    next_channel: usize = 0,

    fn init(direction: Direction, seed: u64) DirectionState {
        return .{
            .direction = direction,
            .seed = seed,
            .sent_hashers = initHashers(),
            .received_hashers = initHashers(),
        };
    }

    fn initHashers() [channel_count]std.crypto.hash.sha2.Sha256 {
        var result: [channel_count]std.crypto.hash.sha2.Sha256 = undefined;
        for (&result) |*hasher| hasher.* = std.crypto.hash.sha2.Sha256.init(.{});
        return result;
    }

    fn channelTarget() u64 {
        return transfer_bytes_per_direction / channel_count;
    }

    fn done(self: *const DirectionState) bool {
        for (self.received) |count| {
            if (count != channelTarget()) return false;
        }
        return true;
    }

    fn allSent(self: *const DirectionState) bool {
        for (self.sent) |count| {
            if (count != channelTarget()) return false;
        }
        return true;
    }

    fn fillNext(self: *DirectionState, buf: []u8) ?struct { channel: usize, len: usize } {
        if (self.allSent()) return null;
        const channel = self.next_channel;
        if (self.sent[channel] == channelTarget()) return errorRoundRobinInvariant();

        const remaining = channelTarget() - self.sent[channel];
        const len: usize = @intCast(@min(remaining, chunk_size));
        const payload = buf[0..len];
        fillPayload(payload, self.seed, self.direction, channel, self.sent[channel]);
        return .{ .channel = channel, .len = len };
    }

    fn commitSent(self: *DirectionState, channel: usize, payload: []const u8) void {
        std.debug.assert(channel == self.next_channel);
        self.sent_hashers[channel].update(payload);
        self.sent[channel] += payload.len;
        self.next_channel = (channel + 1) % channel_count;
    }

    fn receive(self: *DirectionState, data: []const u8) !void {
        if (data.len < 16 or !std.mem.eql(u8, data[0..4], "MSH1"))
            return error.InvalidStressFrame;
        if (data[4] != @intFromEnum(self.direction)) return error.WrongDirection;
        const channel: usize = data[5];
        if (channel >= channel_count) return error.InvalidStressChannel;
        const offset = readU64(data[8..16]);
        if (offset != self.received[channel]) return error.OutOfOrderStressData;
        if (data.len > channelTarget() - self.received[channel])
            return error.ExcessStressData;

        for (data[16..], 16..) |byte, index| {
            if (byte != patternByte(self.seed, self.direction, channel, offset + index))
                return error.StressDataMismatch;
        }
        self.received_hashers[channel].update(data);
        self.received[channel] += data.len;
    }

    fn combinedDigests(self: *DirectionState) DirectionDigests {
        var sent_combined = std.crypto.hash.sha2.Sha256.init(.{});
        var received_combined = std.crypto.hash.sha2.Sha256.init(.{});
        for (0..channel_count) |channel| {
            var sent_digest: [32]u8 = undefined;
            var received_digest: [32]u8 = undefined;
            self.sent_hashers[channel].final(&sent_digest);
            self.received_hashers[channel].final(&received_digest);
            sent_combined.update(&sent_digest);
            received_combined.update(&received_digest);
        }
        var result: DirectionDigests = undefined;
        sent_combined.final(&result.sent);
        received_combined.final(&result.received);
        return result;
    }
};

fn errorRoundRobinInvariant() noreturn {
    @panic("round-robin channel selection invariant violated");
}

fn writeU64(dest: []u8, value: u64) void {
    std.debug.assert(dest.len == 8);
    for (0..8) |index| dest[index] = @truncate(value >> @intCast(index * 8));
}

fn readU64(src: []const u8) u64 {
    std.debug.assert(src.len == 8);
    var value: u64 = 0;
    for (src, 0..) |byte, index| value |= @as(u64, byte) << @intCast(index * 8);
    return value;
}

fn mix64(input: u64) u64 {
    var value = input;
    value = (value ^ (value >> 30)) *% 0xbf58476d1ce4e5b9;
    value = (value ^ (value >> 27)) *% 0x94d049bb133111eb;
    return value ^ (value >> 31);
}

fn patternByte(seed: u64, direction: Direction, channel: usize, position: u64) u8 {
    const mixed = mix64(seed ^ (@as(u64, @intFromEnum(direction)) << 56) ^
        (@as(u64, channel) << 48) ^ position);
    return @truncate(mixed >> 24);
}

fn fillPayload(buf: []u8, seed: u64, direction: Direction, channel: usize, offset: u64) void {
    std.debug.assert(buf.len >= 16);
    @memcpy(buf[0..4], "MSH1");
    buf[4] = @intFromEnum(direction);
    buf[5] = @intCast(channel);
    buf[6] = 0;
    buf[7] = 0;
    writeU64(buf[8..16], offset);
    for (buf[16..], 16..) |*byte, index|
        byte.* = patternByte(seed, direction, channel, offset + index);
}

const Pair = struct {
    client: misshod.MisshodClient,
    server: misshod.MisshodServer,
    c2s: BytePipe = .{},
    s2c: BytePipe = .{},
    transport_state: u64,
    client_connected: bool = false,
    server_connected: bool = false,
    client_ended: bool = false,
    server_ended: bool = false,
    auth_events: u32 = 0,
    client_channels: [channel_count]u32 = .{0} ** channel_count,
    server_channels: [channel_count]u32 = .{0} ** channel_count,
    client_channel_count: usize = 0,
    server_channel_count: usize = 0,
    open_pending: bool = false,
    c2s_transfer: ?*DirectionState = null,
    s2c_transfer: ?*DirectionState = null,
    client_window_exhausted: [channel_count]bool = .{false} ** channel_count,
    server_window_exhausted: [channel_count]bool = .{false} ** channel_count,
    window_exhaustions: u64 = 0,
    window_replenishments: u64 = 0,

    fn init(
        client_random: std.Random,
        server_random: std.Random,
        transport_seed: u64,
        allocator: std.mem.Allocator,
        client_limits: misshod.ResourceLimits,
        server_limits: misshod.ResourceLimits,
    ) !Pair {
        var client = try misshod.MisshodClient.initWithLimits(
            client_random,
            "stress-user",
            allocator,
            client_limits,
        );
        errdefer client.deinit();
        try client.setTryNoneAuth(true);
        var server = try misshod.MisshodServer.initWithLimits(
            server_random,
            host_key,
            allocator,
            server_limits,
        );
        errdefer server.deinit();
        return .{
            .client = client,
            .server = server,
            .transport_state = transport_seed,
        };
    }

    fn deinitClientFirst(self: *Pair) void {
        self.client.deinit();
        self.server.deinit();
    }

    fn deinitServerFirst(self: *Pair) void {
        self.server.deinit();
        self.client.deinit();
    }

    fn contains(channels: []const u32, channel: u32) bool {
        for (channels) |existing| {
            if (existing == channel) return true;
        }
        return false;
    }

    fn noteClientChannel(self: *Pair, channel: u32) !void {
        if (contains(self.client_channels[0..self.client_channel_count], channel)) return;
        if (self.client_channel_count == channel_count) return error.TooManyStressChannels;
        self.client_channels[self.client_channel_count] = channel;
        self.client_channel_count += 1;
        self.open_pending = false;
    }

    fn noteServerChannel(self: *Pair, channel: u32) !void {
        if (contains(self.server_channels[0..self.server_channel_count], channel)) return;
        if (self.server_channel_count == channel_count) return error.TooManyStressChannels;
        self.server_channels[self.server_channel_count] = channel;
        self.server_channel_count += 1;
    }

    fn produceClient(self: *Pair) !bool {
        const data = try self.client.peek(pipe_capacity);
        if (data.len == 0) return false;
        try self.c2s.append(data);
        try self.client.consumed(data.len);
        return true;
    }

    fn produceServer(self: *Pair) !bool {
        const data = try self.server.peek(pipe_capacity);
        if (data.len == 0) return false;
        try self.s2c.append(data);
        try self.server.consumed(data.len);
        return true;
    }

    fn consumeClient(self: *Pair, requested: usize) !bool {
        if (self.s2c.len == 0) return false;
        const count = @min(requested, self.s2c.len);
        try self.client.write(self.s2c.data[0..count]);
        self.s2c.consume(count);
        return true;
    }

    fn consumeServer(self: *Pair, requested: usize) !bool {
        if (self.c2s.len == 0) return false;
        const count = @min(requested, self.c2s.len);
        try self.server.write(self.c2s.data[0..count]);
        self.c2s.consume(count);
        return true;
    }

    fn serviceClient(self: *Pair) !bool {
        if (self.client_ended) return false;
        const event = self.client.getNextEvent() catch |err| switch (err) {
            error.NotReady => return false,
            else => return err,
        };
        return switch (event) {
            .ReadyToProduce => self.produceClient(),
            .ReadyToConsume => |count| self.consumeClient(count),
            .ReadyToConsumeAndProduce => |ready| blk: {
                const produced = try self.produceClient();
                const consumed = try self.consumeClient(ready.consume);
                break :blk produced or consumed;
            },
            .Event => |code| blk: {
                switch (code) {
                    .CheckHostKey => try self.client.acceptHostKey(),
                    .Connected => {
                        self.client_connected = true;
                        try self.noteClientChannel(0);
                        try self.client.clearEvent(code);
                    },
                    .ChannelOpened => |channel| {
                        try self.noteClientChannel(channel);
                        try self.client.clearEvent(code);
                    },
                    .RxData => |channel_data| {
                        const transfer = self.s2c_transfer orelse return error.UnexpectedClientData;
                        try transfer.receive(channel_data.data);
                        try self.client.clearEvent(code);
                    },
                    .EndSession => self.client_ended = true,
                    else => try self.client.clearEvent(code),
                }
                break :blk true;
            },
        };
    }

    fn serviceServer(self: *Pair) !bool {
        if (self.server_ended) return false;
        const event = self.server.getNextEvent() catch |err| switch (err) {
            error.NotReady => return false,
            else => return err,
        };
        return switch (event) {
            .ReadyToProduce => self.produceServer(),
            .ReadyToConsume => |count| self.consumeServer(count),
            .ReadyToConsumeAndProduce => |ready| blk: {
                const produced = try self.produceServer();
                const consumed = try self.consumeServer(ready.consume);
                break :blk produced or consumed;
            },
            .Event => |code| blk: {
                switch (code) {
                    .UserAuth => {
                        self.auth_events += 1;
                        try self.server.grantAccess(true);
                        try self.server.clearEvent(code);
                    },
                    .ChannelOpenRequest => |request| try self.server.acceptChannelOpen(request.channel),
                    .Connected => |channel| {
                        self.server_connected = true;
                        try self.noteServerChannel(channel);
                        try self.server.clearEvent(code);
                    },
                    .RxData => |channel_data| {
                        const transfer = self.c2s_transfer orelse return error.UnexpectedServerData;
                        try transfer.receive(channel_data.data);
                        try self.server.clearEvent(code);
                    },
                    .EndSession => self.server_ended = true,
                    else => try self.server.clearEvent(code),
                }
                break :blk true;
            },
        };
    }

    fn observeWindowState(self: *Pair) void {
        for (self.client_channels[0..self.client_channel_count], 0..) |channel_id, index| {
            const channel = self.client.session.channel_table.findByLocalId(channel_id) orelse continue;
            if (channel.peer_window == 0) {
                if (!self.client_window_exhausted[index]) {
                    self.client_window_exhausted[index] = true;
                    self.window_exhaustions += 1;
                }
            } else if (self.client_window_exhausted[index]) {
                self.client_window_exhausted[index] = false;
                self.window_replenishments += 1;
            }
        }
        for (self.server_channels[0..self.server_channel_count], 0..) |channel_id, index| {
            const channel = self.server.session.channel_table.findByLocalId(channel_id) orelse continue;
            if (channel.peer_window == 0) {
                if (!self.server_window_exhausted[index]) {
                    self.server_window_exhausted[index] = true;
                    self.window_exhaustions += 1;
                }
            } else if (self.server_window_exhausted[index]) {
                self.server_window_exhausted[index] = false;
                self.window_replenishments += 1;
            }
        }
    }

    fn step(self: *Pair) !bool {
        self.transport_state +%= 0x9e3779b97f4a7c15;
        if ((mix64(self.transport_state) & 1) == 0) {
            const client_progress = try self.serviceClient();
            self.observeWindowState();
            const server_progress = try self.serviceServer();
            self.observeWindowState();
            return client_progress or server_progress;
        } else {
            const server_progress = try self.serviceServer();
            self.observeWindowState();
            const client_progress = try self.serviceClient();
            self.observeWindowState();
            return client_progress or server_progress;
        }
    }

    fn driveConnected(self: *Pair) !void {
        for (0..50_000) |_| {
            if (self.client_connected and self.server_connected and
                self.auth_events == 1 and self.client.isActive() and self.server.isActive())
                return;
            _ = try self.step();
        }
        return error.HandshakeStepLimit;
    }

    fn openFourChannels(self: *Pair) !void {
        while (self.client_channel_count < channel_count or
            self.server_channel_count < channel_count)
        {
            if (self.client_channel_count < channel_count and !self.open_pending) {
                const channel = self.client.openSessionChannel() catch |err| switch (err) {
                    error.NotReady, error.cannotAcceptWrite => null,
                    else => return err,
                };
                if (channel) |_| self.open_pending = true;
            }
            _ = try self.step();
        }
    }

    fn queueClientChunk(self: *Pair, state: *DirectionState) !bool {
        const channel = state.next_channel;
        const buf = try self.client.getChannelWriteBuffer(self.client_channels[channel]);
        if (buf.len < chunk_size) return false;
        const next = state.fillNext(buf) orelse return false;
        std.debug.assert(next.channel == channel);
        self.client.channelWriteComplete(self.client_channels[channel], next.len) catch |err| switch (err) {
            error.cannotAcceptWrite, error.NotReady => return false,
            else => return err,
        };
        state.commitSent(channel, buf[0..next.len]);
        return true;
    }

    fn queueServerChunk(self: *Pair, state: *DirectionState) !bool {
        const channel = state.next_channel;
        const buf = try self.server.getChannelWriteBuffer(self.server_channels[channel]);
        if (buf.len < chunk_size) return false;
        const next = state.fillNext(buf) orelse return false;
        std.debug.assert(next.channel == channel);
        self.server.channelWriteComplete(self.server_channels[channel], next.len) catch |err| switch (err) {
            error.cannotAcceptWrite, error.NotReady => return false,
            else => return err,
        };
        state.commitSent(channel, buf[0..next.len]);
        return true;
    }
};

fn stressLimits(rekey_after_bytes: ?u64) misshod.ResourceLimits {
    return .{
        .initial_channel_window = 2 * chunk_size,
        .max_channel_window = 2 * chunk_size,
        .channel_packet_size = chunk_size,
        .max_peer_packet_size = chunk_size,
        .max_channel_buffered_data = chunk_size,
        .max_key_exchanges = 8,
        .key_lifetime = .{
            .rekey_after_encrypted_bytes = rekey_after_bytes orelse 1024 * MiB,
            .rekey_after_encrypted_packets = 1 << 30,
        },
    };
}

fn runCycles(seed: u64, allocator: std.mem.Allocator, io: std.Io, started: std.Io.Clock.Timestamp) !void {
    const cycles = 100;
    for (0..cycles) |cycle| {
        var client_prng = std.Random.DefaultPrng.init(mix64(seed ^ cycle ^ 0xc11e17));
        var server_prng = std.Random.DefaultPrng.init(mix64(seed ^ cycle ^ 0x5e7e17));
        var pair = try Pair.init(
            client_prng.random(),
            server_prng.random(),
            mix64(seed ^ cycle ^ 0x7a4a5),
            allocator,
            stressLimits(null),
            stressLimits(null),
        );
        try pair.driveConnected();
        if (pair.auth_events != 1) return error.UnexpectedAuthCount;
        if (cycle % 2 == 0)
            pair.deinitClientFirst()
        else
            pair.deinitServerFirst();

        if ((cycle + 1) % 10 == 0)
            heartbeat(io, started, "connect-auth-disconnect", cycle + 1, cycles);
    }
    std.debug.print("scenario connect-auth-disconnect cycles={d} auth_successes={d}\n", .{ cycles, cycles });
}

fn runTransfer(seed: u64, allocator: std.mem.Allocator, io: std.Io, started: std.Io.Clock.Timestamp) !void {
    var client_prng = std.Random.DefaultPrng.init(mix64(seed ^ 0x1111));
    var server_prng = std.Random.DefaultPrng.init(mix64(seed ^ 0x2222));
    var pair = try Pair.init(
        client_prng.random(),
        server_prng.random(),
        mix64(seed ^ 0x3333),
        allocator,
        stressLimits(null),
        stressLimits(null),
    );
    defer pair.deinitClientFirst();
    try pair.driveConnected();
    try pair.openFourChannels();

    var c2s = DirectionState.init(.client_to_server, mix64(seed ^ 0xc2c2));
    var s2c = DirectionState.init(.server_to_client, mix64(seed ^ 0x52c2));
    pair.c2s_transfer = &c2s;
    pair.s2c_transfer = &s2c;

    var last_heartbeat_bytes: u64 = 0;
    for (0..500_000) |_| {
        if (!c2s.allSent()) _ = try pair.queueClientChunk(&c2s);
        if (c2s.done() and !s2c.allSent()) _ = try pair.queueServerChunk(&s2c);
        _ = pair.step() catch |err| {
            std.debug.print(
                "stress failure scenario=bidirectional-transfer error={s} c2s_sent={d} c2s_received={d} s2c_sent={d} s2c_received={d} queued={d}/{d}\n",
                .{
                    @errorName(err),
                    sumCounts(c2s.sent),
                    sumCounts(c2s.received),
                    sumCounts(s2c.sent),
                    sumCounts(s2c.received),
                    pair.c2s.len,
                    pair.s2c.len,
                },
            );
            return err;
        };

        const received_total = sumCounts(c2s.received) + sumCounts(s2c.received);
        if (received_total - last_heartbeat_bytes >= 8 * MiB) {
            last_heartbeat_bytes = received_total;
            heartbeat(io, started, "bidirectional-transfer", received_total, 2 * transfer_bytes_per_direction);
        }
        if (c2s.done() and s2c.done() and pair.c2s.len == 0 and pair.s2c.len == 0) {
            const client_keys = pair.client.keyLifetimeStatus();
            const server_keys = pair.server.keyLifetimeStatus();
            if (!client_keys.rekey_in_progress and !server_keys.rekey_in_progress and
                !client_keys.local_rekey_pending and !server_keys.local_rekey_pending and
                pair.window_exhaustions == pair.window_replenishments)
                break;
        }
    }

    if (!c2s.done() or !s2c.done()) {
        std.debug.print(
            "stress failure scenario=bidirectional-transfer error=TransferStepLimit c2s_sent={d} c2s_received={d} s2c_sent={d} s2c_received={d} queued={d}/{d}\n",
            .{
                sumCounts(c2s.sent),
                sumCounts(c2s.received),
                sumCounts(s2c.sent),
                sumCounts(s2c.received),
                pair.c2s.len,
                pair.s2c.len,
            },
        );
        return error.TransferStepLimit;
    }
    const c2s_digests = c2s.combinedDigests();
    const s2c_digests = s2c.combinedDigests();
    if (!std.mem.eql(u8, &c2s_digests.sent, &c2s_digests.received) or
        !std.mem.eql(u8, &s2c_digests.sent, &s2c_digests.received))
        return error.TransferHashMismatch;
    if (pair.window_exhaustions == 0 or
        pair.window_exhaustions != pair.window_replenishments)
        return error.WindowReplenishmentMismatch;

    const c2s_hex = std.fmt.bytesToHex(c2s_digests.received, .lower);
    const s2c_hex = std.fmt.bytesToHex(s2c_digests.received, .lower);
    std.debug.print(
        "scenario channels active={d} scheduling=round-robin rounds_per_direction={d}\n",
        .{ channel_count, transfer_bytes_per_direction / chunk_size / channel_count },
    );
    std.debug.print(
        "scenario windows initial={d} chunk={d} exhaustions={d} replenishments={d}\n",
        .{
            2 * chunk_size,
            chunk_size,
            pair.window_exhaustions,
            pair.window_replenishments,
        },
    );
    std.debug.print(
        "scenario transfer c2s_bytes={d} c2s_sha256={s} s2c_bytes={d} s2c_sha256={s}\n",
        .{ sumCounts(c2s.received), &c2s_hex, sumCounts(s2c.received), &s2c_hex },
    );
}

fn sumCounts(counts: [channel_count]u64) u64 {
    var result: u64 = 0;
    for (counts) |count| result += count;
    return result;
}

fn runRekey(seed: u64, allocator: std.mem.Allocator, io: std.Io, started: std.Io.Clock.Timestamp) !void {
    const threshold = 2 * MiB;
    var client_prng = std.Random.DefaultPrng.init(mix64(seed ^ 0x4b455943));
    var server_prng = std.Random.DefaultPrng.init(mix64(seed ^ 0x45504f43));
    var pair = try Pair.init(
        client_prng.random(),
        server_prng.random(),
        mix64(seed ^ 0x52454b45),
        allocator,
        stressLimits(threshold),
        stressLimits(null),
    );
    defer pair.deinitClientFirst();
    try pair.driveConnected();

    var traffic = DirectionState.init(.client_to_server, mix64(seed ^ 0x53555354));
    pair.c2s_transfer = &traffic;

    var progressed = false;
    for (0..100_000) |_| {
        const before = pair.client.keyLifetimeStatus();
        if (before.outbound.epoch < 2) _ = try pair.queueClientChunk(&traffic);
        _ = try pair.step();

        const client_keys = pair.client.keyLifetimeStatus();
        const server_keys = pair.server.keyLifetimeStatus();
        const minimum_epoch = @min(
            @min(client_keys.inbound.epoch, client_keys.outbound.epoch),
            @min(server_keys.inbound.epoch, server_keys.outbound.epoch),
        );
        if (minimum_epoch >= 2) progressed = true;
        if (progressed and !client_keys.rekey_in_progress and !server_keys.rekey_in_progress and
            !client_keys.local_rekey_pending and !server_keys.local_rekey_pending and
            sumCounts(traffic.sent) == sumCounts(traffic.received) and pair.c2s.len == 0)
            break;
    }

    const client_keys = pair.client.keyLifetimeStatus();
    const server_keys = pair.server.keyLifetimeStatus();
    const minimum_epoch = @min(
        @min(client_keys.inbound.epoch, client_keys.outbound.epoch),
        @min(server_keys.inbound.epoch, server_keys.outbound.epoch),
    );
    if (minimum_epoch < 2) return error.RekeyDidNotProgress;
    if (sumCounts(traffic.received) < threshold) return error.InsufficientRekeyTraffic;
    if (sumCounts(traffic.sent) != sumCounts(traffic.received)) return error.RekeyTrafficNotDrained;
    const digests = traffic.combinedDigests();
    if (!std.mem.eql(u8, &digests.sent, &digests.received))
        return error.RekeyTrafficHashMismatch;
    const digest_hex = std.fmt.bytesToHex(digests.received, .lower);
    heartbeat(io, started, "automatic-rekey", sumCounts(traffic.received), sumCounts(traffic.sent));
    std.debug.print(
        "scenario rekey count={d} sustained_bytes={d} sha256={s} client_epochs={d}/{d} server_epochs={d}/{d}\n",
        .{
            minimum_epoch - 1,
            sumCounts(traffic.received),
            &digest_hex,
            client_keys.inbound.epoch,
            client_keys.outbound.epoch,
            server_keys.inbound.epoch,
            server_keys.outbound.epoch,
        },
    );
}

const RaceAction = enum {
    client_eof,
    server_eof,
    client_close,
    server_close,
};

fn doRaceAction(pair: *Pair, action: RaceAction) !void {
    for (0..20_000) |_| {
        const result = switch (action) {
            .client_eof => pair.client.sendChannelEof(pair.client_channels[0]),
            .server_eof => pair.server.sendChannelEof(pair.server_channels[0]),
            .client_close => pair.client.sendChannelClose(pair.client_channels[0]),
            .server_close => pair.server.sendChannelClose(pair.server_channels[0]),
        };
        result catch |err| switch (err) {
            error.cannotAcceptWrite, error.NotReady => {
                _ = try pair.step();
                continue;
            },
            error.UnexpectedResponse => return,
            else => return err,
        };
        return;
    }
    return error.RaceActionStepLimit;
}

fn pump(pair: *Pair, steps: usize) !void {
    for (0..steps) |_| _ = try pair.step();
}

fn runRaceSchedule(seed: u64, allocator: std.mem.Allocator, schedule: usize) !void {
    var client_prng = std.Random.DefaultPrng.init(mix64(seed ^ schedule ^ 0xca11));
    var server_prng = std.Random.DefaultPrng.init(mix64(seed ^ schedule ^ 0x5e12));
    var pair = try Pair.init(
        client_prng.random(),
        server_prng.random(),
        mix64(seed ^ schedule ^ 0xd15c),
        allocator,
        stressLimits(null),
        stressLimits(null),
    );
    var live = true;
    defer if (live) pair.deinitClientFirst();
    try pair.driveConnected();

    switch (schedule) {
        0 => {
            try doRaceAction(&pair, .client_eof);
            try doRaceAction(&pair, .client_close);
            try doRaceAction(&pair, .server_close);
        },
        1 => {
            try doRaceAction(&pair, .server_eof);
            try doRaceAction(&pair, .server_close);
            try doRaceAction(&pair, .client_close);
        },
        2 => {
            try doRaceAction(&pair, .client_eof);
            try doRaceAction(&pair, .server_eof);
            try doRaceAction(&pair, .client_close);
            try doRaceAction(&pair, .server_close);
        },
        3 => {
            try doRaceAction(&pair, .client_eof);
            try pump(&pair, 1);
            try doRaceAction(&pair, .server_close);
            try doRaceAction(&pair, .client_close);
        },
        4 => {
            try doRaceAction(&pair, .server_eof);
            try pump(&pair, 7);
            try doRaceAction(&pair, .client_close);
            try doRaceAction(&pair, .server_close);
        },
        5 => {
            try doRaceAction(&pair, .client_close);
            try doRaceAction(&pair, .server_close);
        },
        6 => {
            try doRaceAction(&pair, .client_eof);
            try doRaceAction(&pair, .client_close);
            live = false;
            pair.deinitClientFirst();
            return;
        },
        7 => {
            try doRaceAction(&pair, .server_eof);
            try doRaceAction(&pair, .server_close);
            live = false;
            pair.deinitServerFirst();
            return;
        },
        else => unreachable,
    }

    for (0..50_000) |_| {
        if (pair.client_ended and pair.server_ended) return;
        _ = try pair.step();
    }
    return error.CloseRaceStepLimit;
}

fn runRaces(seed: u64, allocator: std.mem.Allocator) !void {
    const schedules = 8;
    for (0..schedules) |schedule| try runRaceSchedule(seed, allocator, schedule);
    std.debug.print(
        "scenario eof-close-disconnect schedules={d} graceful={d} transport_disconnect={d}\n",
        .{ schedules, schedules - 2, 2 },
    );
}

fn elapsedMilliseconds(io: std.Io, started: std.Io.Clock.Timestamp) i64 {
    return started.untilNow(io).raw.toMilliseconds();
}

fn heartbeat(
    io: std.Io,
    started: std.Io.Clock.Timestamp,
    scenario: []const u8,
    completed: u64,
    total: u64,
) void {
    std.debug.print(
        "heartbeat scenario={s} completed={d} total={d} elapsed_ms={d}\n",
        .{ scenario, completed, total, elapsedMilliseconds(io, started) },
    );
}

fn parseSeed(args: []const []const u8) !u64 {
    var seed: u64 = 0x68_5eed_cafe;
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--seed")) {
            index += 1;
            if (index == args.len) return error.MissingSeed;
            seed = try std.fmt.parseInt(u64, args[index], 0);
        } else if (std.mem.eql(u8, args[index], "--help")) {
            std.debug.print("usage: zig build stress -Doptimize=ReleaseSafe -- --seed <u64>\n", .{});
            std.process.exit(0);
        } else {
            return error.UnknownArgument;
        }
    }
    return seed;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const seed = parseSeed(args) catch |err| {
        std.debug.print("stress argument error: {s}\n", .{@errorName(err)});
        std.debug.print("usage: zig build stress -Doptimize=ReleaseSafe -- --seed <u64>\n", .{});
        return err;
    };
    const started = std.Io.Clock.Timestamp.now(init.io, .awake);

    std.debug.print("misshod deterministic stress seed={d}\n", .{seed});
    std.debug.print(
        "acceptance cycles=100 channels=4 bytes_per_direction={d} race_schedules=8 rekey_threshold_bytes={d}\n",
        .{ transfer_bytes_per_direction, 2 * MiB },
    );
    std.debug.print(
        "rerun: zig build stress -Doptimize=ReleaseSafe -- --seed {d}\n",
        .{seed},
    );

    try runCycles(seed, init.gpa, init.io, started);
    try runTransfer(seed, init.gpa, init.io, started);
    try runRekey(seed, init.gpa, init.io, started);
    try runRaces(seed, init.gpa);

    std.debug.print(
        "stress PASS seed={d} elapsed_ms={d}\n",
        .{ seed, elapsedMilliseconds(init.io, started) },
    );
}
