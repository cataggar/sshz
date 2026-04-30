const std = @import("std");
const posix = std.posix;
const MisshodClient = @import("misshod").MisshodClient;

// Turn off echo and read a password
fn readPassphrase(password_buf: []u8) ![]u8 {
    const stdin_fd = std.c.STDIN_FILENO;

    if (std.c.isatty(stdin_fd) != 0) {
        // disable terminal echo
        var termios = try std.posix.tcgetattr(stdin_fd);
        termios.lflag.ECHO = false;
        try std.posix.tcsetattr(stdin_fd, .FLUSH, termios);
        const password = try readLine(stdin_fd, password_buf);
        // re-enable echo
        termios.lflag.ECHO = true;
        try std.posix.tcsetattr(stdin_fd, .FLUSH, termios);
        try writeAllFd(std.c.STDOUT_FILENO, "\n");
        return password;
    } else {
        return try readLine(stdin_fd, password_buf);
    }
}

var original_termios: ?std.posix.termios = null;
const MaxAgentSockets = 4;

const AgentSocket = struct {
    channel: u32,
    fd: std.c.fd_t,
};

pub fn raw_mode_start() !void {
    const handle = std.c.STDIN_FILENO;

    if (std.c.isatty(handle) != 0) {
        var termios = try std.posix.tcgetattr(handle);
        original_termios = termios;

        termios.iflag.BRKINT = false;
        termios.iflag.ICRNL = true;
        termios.iflag.INPCK = false;
        termios.iflag.ISTRIP = false;
        termios.iflag.IXON = false;
        termios.oflag.OPOST = true;
        termios.lflag.ECHO = false;
        termios.lflag.ICANON = false;
        termios.lflag.IEXTEN = false;
        termios.lflag.ISIG = false;
        termios.cflag.CSIZE = .CS8;
        termios.cc[@intFromEnum(std.posix.V.TIME)] = 0;
        termios.cc[@intFromEnum(std.posix.V.MIN)] = 1;

        try std.posix.tcsetattr(handle, .FLUSH, termios);
    }
}

pub fn raw_mode_stop() void {
    if (original_termios) |termios| {
        std.posix.tcsetattr(std.c.STDIN_FILENO, .FLUSH, termios) catch {};
    }
    writeAllFd(std.c.STDOUT_FILENO, "\n") catch {};
}

fn connectAgentSocket(path: []const u8) !std.c.fd_t {
    const fd = std.c.socket(std.c.AF.UNIX, std.c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer _ = std.c.close(fd);

    var addr: std.c.sockaddr.un = .{ .family = std.c.AF.UNIX, .path = .{0} ** 108 };
    if (path.len >= addr.path.len) return error.NameTooLong;
    @memcpy(addr.path[0..path.len], path);

    const addr_len: std.c.socklen_t = @intCast(@offsetOf(std.c.sockaddr.un, "path") + path.len + 1);
    if (std.c.connect(fd, @ptrCast(&addr), addr_len) != 0) return error.ConnectFailed;
    return fd;
}

fn connectTcp(io: std.Io, host: []const u8, port: u16) !std.Io.net.Stream {
    if (std.Io.net.IpAddress.parse(host, port)) |address| {
        return try address.connect(io, .{ .mode = .stream });
    } else |_| {}

    const host_name = try std.Io.net.HostName.init(host);
    var results_buffer: [16]std.Io.net.IpAddress.ConnectError!std.Io.net.Stream = undefined;
    var results: std.Io.Queue(std.Io.net.IpAddress.ConnectError!std.Io.net.Stream) = .init(&results_buffer);
    try std.Io.net.HostName.connectMany(host_name, io, port, &results, .{ .mode = .stream });

    var last_err: ?anyerror = null;
    while (true) {
        const result = results.getOne(io) catch |err| switch (err) {
            error.Closed => break,
            else => |e| return e,
        };
        const stream = result catch |err| {
            last_err = err;
            continue;
        };
        return stream;
    }
    if (last_err) |err| return err;
    return error.NoAddressReturned;
}

fn readFd(fd: std.c.fd_t, buf: []u8) !usize {
    if (buf.len == 0) return 0;
    const n = std.c.read(fd, buf.ptr, buf.len);
    if (n < 0) return error.ReadFailed;
    return @intCast(n);
}

fn readLine(fd: std.c.fd_t, buf: []u8) ![]u8 {
    var n: usize = 0;
    while (n < buf.len) {
        const count = try readFd(fd, buf[n .. n + 1]);
        if (count == 0) break;
        if (buf[n] == '\n') break;
        n += 1;
    }
    return buf[0..n];
}

fn writeFd(fd: std.c.fd_t, data: []const u8) !usize {
    if (data.len == 0) return 0;
    const n = std.c.write(fd, data.ptr, data.len);
    if (n < 0) return error.WriteFailed;
    return @intCast(n);
}

fn writeAllFd(fd: std.c.fd_t, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        const n = std.c.write(fd, data[off..].ptr, data.len - off);
        if (n <= 0) return error.WriteFailed;
        off += @intCast(n);
    }
}

fn addAgentSocket(sockets: *[MaxAgentSockets]?AgentSocket, channel: u32, path: []const u8) !void {
    var free_slot: ?*?AgentSocket = null;
    for (sockets) |*slot| {
        if (slot.* == null) {
            free_slot = slot;
            break;
        }
    }
    const slot = free_slot orelse return error.AgentSocketTableFull;
    slot.* = .{ .channel = channel, .fd = try connectAgentSocket(path) };
}

fn findAgentSocket(sockets: *[MaxAgentSockets]?AgentSocket, channel: u32) ?*AgentSocket {
    for (sockets) |*slot| {
        if (slot.*) |*agent| {
            if (agent.channel == channel) return agent;
        }
    }
    return null;
}

fn closeAgentSocket(sockets: *[MaxAgentSockets]?AgentSocket, channel: u32) void {
    for (sockets) |*slot| {
        if (slot.*) |agent| {
            if (agent.channel == channel) {
                _ = std.c.close(agent.fd);
                slot.* = null;
                return;
            }
        }
    }
}

fn closeAllAgentSockets(sockets: *[MaxAgentSockets]?AgentSocket) void {
    for (sockets) |*slot| {
        if (slot.*) |agent| {
            _ = std.c.close(agent.fd);
            slot.* = null;
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    if (args.len < 3) {
        std.debug.print("{s} <username@host> <port> [-A|--agent-forward] [idfile]\n", .{args[0]});
        std.process.exit(1);
    }

    const user_host = args[1];
    const port = try std.fmt.parseInt(u16, args[2], 10);
    var agent_forwarding = false;
    var idfile: ?[]const u8 = null;
    var host_opt: ?[]u8 = null;
    var user_opt: ?[]u8 = null;

    var arg_i: usize = 3;
    while (arg_i < args.len) : (arg_i += 1) {
        if (std.mem.eql(u8, args[arg_i], "-A") or std.mem.eql(u8, args[arg_i], "--agent-forward")) {
            agent_forwarding = true;
        } else if (idfile == null) {
            idfile = args[arg_i];
        } else {
            std.debug.print("{s} <username@host> <port> [-A|--agent-forward] [idfile]\n", .{args[0]});
            std.process.exit(1);
        }
    }

    const agent_sock_path = if (agent_forwarding)
        init.environ_map.get("SSH_AUTH_SOCK") orelse {
            std.debug.print("Agent forwarding requested but SSH_AUTH_SOCK is not set\n", .{});
            std.process.exit(1);
        }
    else
        null;

    var iter = std.mem.tokenizeSequence(u8, user_host, "@");
    var i: usize = 0;
    while (iter.next()) |item| {
        switch (i) {
            0 => user_opt = try allocator.dupe(u8, item),
            1 => host_opt = try allocator.dupe(u8, item),
            else => {
                std.debug.print("Bad user@host\n", .{});
                std.process.exit(1);
            },
        }
        i += 1;
    }

    if (host_opt) |host| {
        if (user_opt) |user| {
            var stream = connectTcp(init.io, host, port) catch |err| {
                switch (err) {
                    error.ConnectionRefused => std.debug.print("ConnectionRefused\n", .{}),
                    else => std.debug.print("{any}\n", .{err}),
                }
                return;
            };
            defer stream.close(init.io);

            // make a reasonable prng
            var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
            if (std.c.getrandom(&seed, seed.len, 0) != seed.len) return error.RandomSeedFailed;
            var prng = std.Random.DefaultCsprng.init(seed);

            var misshod = try MisshodClient.init(prng.random(), user, allocator);
            defer misshod.deinit();
            if (agent_forwarding) {
                try misshod.enableAgentForwarding();
            }

            defer raw_mode_stop();

            var iobuf: [8]u8 = undefined; // could be any size
            var agent_sockets: [MaxAgentSockets]?AgentSocket = .{null} ** MaxAgentSockets;
            defer closeAllAgentSockets(&agent_sockets);
            var quit = false;
            const stdin_fd = std.c.STDIN_FILENO;

            outer: while (!quit) {
                const ev = try misshod.getNextEvent();
                switch (ev) {
                    .Event => |eventCode| {
                        switch (eventCode) {
                            .Connected => {
                                std.debug.print("Connected!\n", .{});
                                try misshod.clearEvent(eventCode);
                                try raw_mode_start();
                            },
                            .RxData => |buf| {
                                try writeAllFd(std.c.STDOUT_FILENO, buf);
                                try misshod.clearEvent(eventCode);
                            },
                            .RxExtendedData => |ext| {
                                _ = ext;
                                try misshod.clearEvent(eventCode);
                            },
                            .Banner => |banner| {
                                std.debug.print("{s}\n", .{banner});
                                try misshod.clearEvent(eventCode);
                            },
                            .EndSession => |reason| {
                                std.debug.print("Session ended: {any}\n", .{reason});
                                quit = true;
                                continue :outer;
                            },
                            .CheckHostKey => |keydata| {
                                // make a decision about whether to accept host key
                                // a real client could check ~/.ssh/known_hosts
                                var fingerprint_buf: [44]u8 = undefined;
                                const fingerprint = keydata.fingerprintStr(&fingerprint_buf);
                                std.debug.print("Auto accepting host key {s}\n", .{fingerprint});
                                try misshod.clearEvent(eventCode);
                            },
                            .GetPrivateKey => {
                                if (idfile) |path| {
                                    const keydata_ascii = std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(1024)) catch {
                                        std.debug.print("Failed to open idfile {s}\n", .{path});
                                        std.process.exit(1);
                                    };
                                    try misshod.setPrivateKey(keydata_ascii);
                                    allocator.free(keydata_ascii);
                                }
                                try misshod.clearEvent(eventCode);
                            },
                            .GetKeyPassphrase => {
                                var password_buf: [128]u8 = undefined;
                                std.debug.print("Password for private key decrypt: ", .{});
                                try misshod.setPrivateKeyPassphrase(try readPassphrase(&password_buf));
                                try misshod.clearEvent(eventCode);
                            },
                            .GetAuthPassphrase => {
                                var password_buf: [128]u8 = undefined;
                                std.debug.print("Password for auth: ", .{});
                                try misshod.setAuthPassphrase(try readPassphrase(&password_buf));
                                try misshod.clearEvent(eventCode);
                            },
                            .KeyboardInteractive => |prompt| {
                                var password_buf: [128]u8 = undefined;
                                std.debug.print("{s}", .{prompt.prompt});
                                try misshod.session.setKeyboardInteractiveResponse(try readPassphrase(&password_buf));
                                try misshod.clearEvent(eventCode);
                            },
                            .AgentChannelOpen => |channel| {
                                try misshod.clearEvent(eventCode);
                                addAgentSocket(&agent_sockets, channel, agent_sock_path.?) catch |err| {
                                    std.debug.print("Failed to connect SSH_AUTH_SOCK for agent channel {d}: {any}\n", .{ channel, err });
                                    try misshod.sendChannelEof(channel);
                                };
                            },
                            .AgentData => |agent_data| {
                                var close_channel = false;
                                if (findAgentSocket(&agent_sockets, agent_data.channel)) |agent| {
                                    writeAllFd(agent.fd, agent_data.data) catch |err| {
                                        std.debug.print("Failed to write agent data for channel {d}: {any}\n", .{ agent_data.channel, err });
                                        closeAgentSocket(&agent_sockets, agent_data.channel);
                                        close_channel = true;
                                    };
                                } else {
                                    close_channel = true;
                                }
                                try misshod.clearEvent(eventCode);
                                if (close_channel) try misshod.sendChannelEof(agent_data.channel);
                            },
                            .AgentChannelClosed => |channel| {
                                closeAgentSocket(&agent_sockets, channel);
                                try misshod.clearEvent(eventCode);
                            },
                        }
                    },
                    .ReadyToConsume, .ReadyToProduce, .ReadyToConsumeAndProduce => {
                        const consume_len: usize = switch (ev) {
                            .ReadyToConsume => |n| n,
                            .ReadyToConsumeAndProduce => |s| s.consume,
                            else => 0,
                        };
                        const produce_len: usize = switch (ev) {
                            .ReadyToProduce => |n| n,
                            .ReadyToConsumeAndProduce => |s| s.produce,
                            else => 0,
                        };
                        _ = produce_len;

                        var pollevts: i16 = 0;
                        if (consume_len > 0) pollevts |= std.posix.POLL.IN;
                        if (ev == .ReadyToProduce or ev == .ReadyToConsumeAndProduce) pollevts |= std.posix.POLL.OUT;

                        var fds: [2 + MaxAgentSockets]std.posix.pollfd = undefined;
                        fds[0] = .{
                                .fd = stream.socket.handle,
                            .events = pollevts,
                            .revents = undefined,
                        };
                        fds[1] = .{
                            .fd = stdin_fd,
                            .events = std.posix.POLL.IN,
                            .revents = undefined,
                        };
                        var fd_count: usize = 2;
                        for (agent_sockets) |agent_opt| {
                            if (agent_opt) |agent| {
                                fds[fd_count] = .{
                                    .fd = agent.fd,
                                    .events = std.posix.POLL.IN,
                                    .revents = undefined,
                                };
                                fd_count += 1;
                            }
                        }

                        const ready = std.posix.poll(fds[0..fd_count], 1000) catch 0;
                        if (ready > 0) {
                            if (fds[0].revents & std.posix.POLL.IN > 0) { // socket is readable
                                var bytes_to_read = consume_len;
                                if (bytes_to_read > iobuf.len) {
                                    bytes_to_read = iobuf.len;
                                }
                                const nbytes = try readFd(stream.socket.handle, iobuf[0..bytes_to_read]);
                                if (nbytes > 0) {
                                    try misshod.write(iobuf[0..nbytes]);
                                    continue :outer;
                                }
                            }
                            if (fds[0].revents & std.posix.POLL.OUT > 0) { // socket is writeable
                                const towrite = try misshod.peek(4);
                                const bytes_written = try writeFd(stream.socket.handle, towrite);
                                try misshod.consumed(bytes_written);
                                continue :outer;
                            }
                            if (fds[1].revents & std.posix.POLL.IN > 0) { // keyboard data in
                                const buf = try misshod.getChannelWriteBuffer(0);
                                if (buf.len > 0) {
                                    const count = readFd(stdin_fd, buf) catch 0;
                                    if (count > 0) {
                                        try misshod.channelWriteComplete(0, count);
                                        continue :outer;
                                    }
                                }
                            }
                            var poll_idx: usize = 2;
                            for (&agent_sockets) |*agent_slot| {
                                if (agent_slot.*) |agent| {
                                    const revents = fds[poll_idx].revents;
                                    poll_idx += 1;
                                    if (revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR) > 0) {
                                        const buf = try misshod.getChannelWriteBuffer(agent.channel);
                                        if (buf.len > 0) {
                                            const count = readFd(agent.fd, buf) catch |err| {
                                                std.debug.print("Failed to read SSH_AUTH_SOCK for channel {d}: {any}\n", .{ agent.channel, err });
                                                closeAgentSocket(&agent_sockets, agent.channel);
                                                try misshod.sendChannelEof(agent.channel);
                                                continue;
                                            };
                                            if (count > 0) {
                                                try misshod.channelWriteComplete(agent.channel, count);
                                                continue :outer;
                                            }
                                            closeAgentSocket(&agent_sockets, agent.channel);
                                            try misshod.sendChannelEof(agent.channel);
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
        } else {
            std.debug.print("Bad/missing user\n", .{});
        }
    } else {
        std.debug.print("Bad/missing user\n", .{});
    }
}
