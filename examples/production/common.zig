const std = @import("std");

pub const Readiness = struct {
    readable: bool = false,
    writable: bool = false,
};

pub const Transport = struct {
    context: *anyopaque,
    read_fn: *const fn (*anyopaque, []u8) anyerror!usize,
    write_fn: *const fn (*anyopaque, []const u8) anyerror!usize,
    close_fn: *const fn (*anyopaque) void,

    pub fn read(self: Transport, destination: []u8) !usize {
        const count = try self.read_fn(self.context, destination);
        if (count > destination.len) return error.InvalidTransportCount;
        if (count == 0) return error.EndOfStream;
        return count;
    }

    pub fn write(self: Transport, source: []const u8) !usize {
        const count = try self.write_fn(self.context, source);
        if (count > source.len) return error.InvalidTransportCount;
        if (count == 0) return error.EndOfStream;
        return count;
    }

    pub fn close(self: Transport) void {
        self.close_fn(self.context);
    }
};

pub const PumpResult = enum {
    progress,
    wait_read,
    wait_write,
    wait_read_or_write,
    finished,
};

pub fn requireProductionLimits(limits: anytype) !void {
    try limits.validate();
    if (limits.deadlines.handshake == null or
        limits.deadlines.authentication == null or
        limits.deadlines.idle == null or
        limits.deadlines.total_session == null or
        limits.key_lifetime.rekey_after_monotonic_ticks == null)
    {
        return error.ProductionLimitsRequired;
    }
}

pub fn printCompileOnly(comptime role: []const u8) void {
    std.debug.print(
        "{s} integration skeleton: provide a transport, monotonic clock, and explicit policy callbacks; see doc/api-production.md\n",
        .{role},
    );
}
