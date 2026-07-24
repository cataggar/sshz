const std = @import("std");
const misshod = @import("misshod");
const common = @import("common.zig");

pub const Policy = struct {
    context: *anyopaque,
    authenticate_fn: *const fn (*anyopaque, misshod.UserCredentials) anyerror!bool,
    channel_open_fn: *const fn (*anyopaque, misshod.ChannelOpenRequestEvent) anyerror!bool,
    channel_request_fn: *const fn (*anyopaque, misshod.ChannelRequestEvent) anyerror!bool,
    window_change_fn: *const fn (*anyopaque, misshod.WindowSize) anyerror!bool,
    signal_fn: *const fn (*anyopaque, misshod.ChannelSignal) anyerror!bool,
    data_fn: *const fn (*anyopaque, misshod.ChannelData) anyerror!void,
    extended_data_fn: *const fn (*anyopaque, misshod.ChannelExtendedData) anyerror!void,
};

pub const Config = struct {
    limits: misshod.ResourceLimits,
    policy: Policy,
};

pub fn init(
    random: std.Random,
    host_private_key: []const u8,
    allocator: std.mem.Allocator,
    config: *const Config,
    now: u64,
) !misshod.MisshodServer {
    if (host_private_key.len == 0) return error.InvalidConfiguration;
    try common.requireProductionLimits(config.limits);

    var server = try misshod.MisshodServer.initWithLimits(
        random,
        host_private_key,
        allocator,
        config.limits,
    );
    errdefer server.deinit();
    try server.initializeDeadlines(now);
    return server;
}

fn handleEvent(
    server: *misshod.MisshodServer,
    config: *const Config,
    event: misshod.MisshodServerEventCodes,
) !common.PumpResult {
    switch (event) {
        .UserAuth => |credentials| {
            const accepted = try config.policy.authenticate_fn(
                config.policy.context,
                credentials,
            );
            try server.decideUserAuth(if (accepted) .Allow else .Deny);
        },
        .ChannelOpenRequest => |request| {
            const accepted = try config.policy.channel_open_fn(
                config.policy.context,
                request,
            );
            if (accepted) {
                try server.acceptChannelOpen(request.channel);
            } else {
                try server.rejectChannelOpen(
                    request.channel,
                    misshod.SshOpenFailureReason.AdministrativelyProhibited,
                    "channel denied by application policy",
                );
            }
        },
        .ChannelRequest => |request| {
            const accepted = try config.policy.channel_request_fn(
                config.policy.context,
                request,
            );
            if (!accepted) try server.sendChannelClose(request.channel);
            try server.clearEvent(event);
        },
        .RxData => |data| {
            try config.policy.data_fn(config.policy.context, data);
            try server.clearEvent(event);
        },
        .RxExtendedData => |data| {
            try config.policy.extended_data_fn(config.policy.context, data);
            try server.clearEvent(event);
        },
        .WindowChange => |window| {
            const accepted = try config.policy.window_change_fn(
                config.policy.context,
                window,
            );
            if (!accepted) try server.sendChannelClose(window.channel);
            try server.clearEvent(event);
        },
        .Signal => |signal| {
            const accepted = try config.policy.signal_fn(
                config.policy.context,
                signal,
            );
            if (!accepted) try server.sendChannelClose(signal.channel);
            try server.clearEvent(event);
        },
        .TcpipForward => try server.rejectTcpipForward(),
        .CancelTcpipForward => try server.rejectCancelTcpipForward(),
        .GetPubkeyForUser => return error.UnsupportedAuthenticationEvent,
        .ChannelOpened,
        .ChannelOpenFailure,
        .AgentChannelOpen,
        .AgentChannelClosed,
        => return error.UnexpectedOutboundChannelEvent,
        .EndSession => return .finished,
        .Connected,
        => try server.clearEvent(event),
    }
    return .progress;
}

fn consume(
    server: *misshod.MisshodServer,
    transport: common.Transport,
    scratch: []u8,
    requested: usize,
    now: u64,
) !common.PumpResult {
    if (scratch.len == 0) return error.EmptyScratchBuffer;
    const count = try transport.read(scratch[0..@min(scratch.len, requested)]);
    try server.write(scratch[0..count]);
    try server.noteActivity(now);
    return .progress;
}

fn produce(
    server: *misshod.MisshodServer,
    transport: common.Transport,
    requested: usize,
    now: u64,
) !common.PumpResult {
    const bytes = try server.peek(requested);
    const count = try transport.write(bytes);
    try server.consumed(count);
    try server.noteActivity(now);
    return .progress;
}

/// Call only after polling the transport. The caller owns transport closure
/// and must `defer server.deinit()`; any returned error is terminal.
pub fn pumpOnce(
    server: *misshod.MisshodServer,
    config: *const Config,
    transport: common.Transport,
    scratch: []u8,
    readiness: common.Readiness,
    now: u64,
) !common.PumpResult {
    if (try server.tick(now) != null) return error.DeadlineExpired;
    const next = server.getNextEvent() catch |err| switch (err) {
        error.NotReady => return .wait_read_or_write,
        else => return err,
    };
    return switch (next) {
        .Event => |event| try handleEvent(server, config, event),
        .ReadyToConsume => |count| if (readiness.readable)
            try consume(server, transport, scratch, count, now)
        else
            .wait_read,
        .ReadyToProduce => |count| if (readiness.writable)
            try produce(server, transport, count, now)
        else
            .wait_write,
        .ReadyToConsumeAndProduce => |counts| if (readiness.writable)
            try produce(server, transport, counts.produce, now)
        else if (readiness.readable)
            try consume(server, transport, scratch, counts.consume, now)
        else
            .wait_read_or_write,
    };
}

pub fn sendChannelData(
    server: *misshod.MisshodServer,
    channel: u32,
    data: []const u8,
) !usize {
    if (data.len == 0) return 0;
    const destination = try server.getChannelWriteBuffer(channel);
    if (destination.len == 0) return error.NotReady;
    const count = @min(destination.len, data.len);
    @memcpy(destination[0..count], data[0..count]);
    try server.channelWriteComplete(channel, count);
    return count;
}

pub fn main(_: std.process.Init) !void {
    common.printCompileOnly("production server");
}

test "production server pump is compile-checked without network I/O" {
    const Mock = struct {
        fn authenticate(_: *anyopaque, _: misshod.UserCredentials) !bool {
            return false;
        }

        fn channelOpen(_: *anyopaque, _: misshod.ChannelOpenRequestEvent) !bool {
            return false;
        }

        fn channelRequest(_: *anyopaque, _: misshod.ChannelRequestEvent) !bool {
            return false;
        }

        fn windowChange(_: *anyopaque, _: misshod.WindowSize) !bool {
            return false;
        }

        fn signal(_: *anyopaque, _: misshod.ChannelSignal) !bool {
            return false;
        }

        fn data(_: *anyopaque, _: misshod.ChannelData) !void {}

        fn extendedData(_: *anyopaque, _: misshod.ChannelExtendedData) !void {}

        fn read(_: *anyopaque, _: []u8) !usize {
            return error.UnexpectedRead;
        }

        fn write(_: *anyopaque, bytes: []const u8) !usize {
            return bytes.len;
        }

        fn close(_: *anyopaque) void {}
    };

    var context: u8 = 0;
    const config: Config = .{
        .limits = .{
            .deadlines = .{
                .handshake = 100,
                .authentication = 100,
                .idle = 100,
                .total_session = 100,
            },
            .key_lifetime = .{ .rekey_after_monotonic_ticks = 100 },
        },
        .policy = .{
            .context = &context,
            .authenticate_fn = Mock.authenticate,
            .channel_open_fn = Mock.channelOpen,
            .channel_request_fn = Mock.channelRequest,
            .window_change_fn = Mock.windowChange,
            .signal_fn = Mock.signal,
            .data_fn = Mock.data,
            .extended_data_fn = Mock.extendedData,
        },
    };
    const transport: common.Transport = .{
        .context = &context,
        .read_fn = Mock.read,
        .write_fn = Mock.write,
        .close_fn = Mock.close,
    };

    var random = std.Random.DefaultPrng.init(2);
    var server = try init(
        random.random(),
        @embedFile("production_test_host_key"),
        std.testing.allocator,
        &config,
        0,
    );
    defer server.deinit();
    var scratch: [8]u8 = undefined;
    try std.testing.expectEqual(
        common.PumpResult.wait_read,
        try pumpOnce(&server, &config, transport, &scratch, .{}, 0),
    );
}
