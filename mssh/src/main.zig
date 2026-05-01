const std = @import("std");
const posix = std.posix;
const MisshodClient = @import("misshod").MisshodClient;

// Turn off echo and read a password
fn readPassphrase(password_buf: []u8) ![]u8 {
    const handle = std.posix.STDIN_FILENO;
    var old_termios: ?std.posix.termios = null;

    if (std.c.isatty(handle) != 0) {
        // disable terminal echo
        var termios = try std.posix.tcgetattr(handle);
        old_termios = termios;
        termios.lflag.ECHO = false;
        try std.posix.tcsetattr(handle, .FLUSH, termios);
    }
    defer if (old_termios) |termios| {
        std.posix.tcsetattr(handle, .FLUSH, termios) catch {};
        _ = std.c.write(std.posix.STDOUT_FILENO, "\n", 1);
    };

    var len: usize = 0;
    while (len < password_buf.len) {
        var ch: [1]u8 = undefined;
        const nread = std.c.read(handle, &ch, 1);
        if (nread < 0) return error.StdinReadFailed;
        if (nread == 0 or ch[0] == '\n') break;
        password_buf[len] = ch[0];
        len += 1;
    }
    return password_buf[0..len];
}

fn resolveTcpAddress(io: std.Io, host: []const u8, port: u16) !std.Io.net.IpAddress {
    if (std.Io.net.IpAddress.resolve(io, host, port)) |address| {
        return address;
    } else |_| {}

    const host_name = try std.Io.net.HostName.init(host);
    var lookup_storage: [16]std.Io.net.HostName.LookupResult = undefined;
    var lookup_results = std.Io.Queue(std.Io.net.HostName.LookupResult).init(&lookup_storage);
    try std.Io.net.HostName.lookup(host_name, io, &lookup_results, .{ .port = port });

    while (true) {
        var result_storage: [1]std.Io.net.HostName.LookupResult = undefined;
        const result_count = lookup_results.getUncancelable(io, &result_storage, 1) catch |err| switch (err) {
            error.Closed => break,
        };
        if (result_count == 0) break;

        switch (result_storage[0]) {
            .address => |address| return address,
            .canonical_name => {},
        }
    }

    return error.NoAddressReturned;
}

var original_termios: ?std.posix.termios = null;

pub fn raw_mode_start() !void {
    const handle = std.posix.STDIN_FILENO;

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
        std.posix.tcsetattr(std.posix.STDIN_FILENO, .FLUSH, termios) catch {};
    }
    _ = std.c.write(std.posix.STDOUT_FILENO, "\n", 1);
}

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try init.minimal.args.toSlice(allocator);

    if (args.len < 3) {
        std.debug.print("{s} <username@host> <port> [idfile]\n", .{args[0]});
        std.process.exit(1);
    }

    const user_host = args[1];
    const port = try std.fmt.parseInt(u16, args[2], 10);
    var host_opt: ?[]u8 = null;
    var user_opt: ?[]u8 = null;

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
            var address = resolveTcpAddress(init.io, host, port) catch |err| {
                std.debug.print("{any}\n", .{err});
                return;
            };
            var stream = std.Io.net.IpAddress.connect(&address, init.io, .{ .mode = .stream }) catch |err| {
                switch (err) {
                    error.ConnectionRefused => std.debug.print("ConnectionRefused\n", .{}),
                    else => std.debug.print("{any}\n", .{err}),
                }
                return;
            };
            defer stream.close(init.io);

            // make a reasonable prng
            var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
            try init.io.randomSecure(&seed);
            var prng = std.Random.DefaultCsprng.init(seed);

            var misshod = try MisshodClient.init(prng.random(), user, allocator);
            defer misshod.deinit(allocator);

            defer raw_mode_stop();

            var iobuf: [8]u8 = undefined; // could be any size
            var quit = false;
            const stdin_fd = std.posix.STDIN_FILENO;

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
                                const nwritten = std.c.write(std.posix.STDOUT_FILENO, buf.ptr, buf.len);
                                if (nwritten < 0) return error.StdoutWriteFailed;
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
                                var fingerprint_buf: [512]u8 = undefined;
                                std.debug.assert(std.base64.standard.Encoder.calcSize(keydata.?.len) <= fingerprint_buf.len);
                                const fingerprint = std.base64.standard.Encoder.encode(&fingerprint_buf, keydata.?);
                                std.debug.print("Auto accepting host key {s}\n", .{fingerprint});
                                try misshod.clearEvent(eventCode);
                            },
                            .GetPrivateKey => {
                                if (args.len >= 4) { // id file provided
                                    const keydata_ascii = std.Io.Dir.cwd().readFileAlloc(init.io, args[3], allocator, .limited(1024)) catch {
                                        std.debug.print("Failed to open idfile {s}\n", .{args[3]});
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
                        }
                    },
                    .ReadyToConsume, .ReadyToProduce => |len| {
                        var pollevts: i16 = 0;

                        if (ev == .ReadyToConsume) {
                            pollevts |= std.posix.POLL.IN;
                        } else {
                            pollevts |= std.posix.POLL.OUT;
                        }

                        var fds = [_]std.posix.pollfd{
                            .{
                                .fd = stream.socket.handle,
                                .events = pollevts,
                                .revents = undefined,
                            },
                            .{
                                .fd = stdin_fd,
                                .events = std.posix.POLL.IN,
                                .revents = undefined,
                            },
                        };

                        const ready = std.posix.poll(&fds, 1000) catch 0;
                        if (ready > 0) {
                            if (fds[0].revents & std.posix.POLL.IN > 0) { // socket is readable
                                var bytes_to_read = len;
                                if (bytes_to_read > iobuf.len) {
                                    bytes_to_read = iobuf.len;
                                }
                                const nread = std.c.read(stream.socket.handle, &iobuf, bytes_to_read);
                                if (nread > 0) {
                                    const nbytes: usize = @intCast(nread);
                                    // misshod may not get as much as it asked for, but it can req more later
                                    //std.debug.print("Can consume {d}\n", .{len});
                                    try misshod.write(iobuf[0..nbytes]);
                                    continue :outer;
                                } else if (nread < 0) {
                                    return error.SocketReadFailed;
                                }
                            }
                            if (fds[0].revents & std.posix.POLL.OUT > 0) { // socket is writeable
                                const towrite = try misshod.peek(4); // get data it wants to send up to a limit
                                const nwritten = std.c.write(stream.socket.handle, towrite.ptr, towrite.len);
                                if (nwritten < 0) return error.SocketWriteFailed;
                                const bytes_written: usize = @intCast(nwritten);
                                //std.debug.print("bytes_written = {d} towrite={d}\n", .{bytes_written, towrite.len});
                                // socket may not have accepted all of the bytes
                                try misshod.consumed(bytes_written);
                                continue :outer;
                            }
                            if (fds[1].revents & std.posix.POLL.IN > 0) { // keyboard data in
                                const buf = try misshod.getChannelWriteBuffer();
                                if (buf.len > 0) {
                                    const count = std.c.read(stdin_fd, buf.ptr, buf.len);
                                    if (count > 0) {
                                        try misshod.channelWriteComplete(@intCast(count));
                                        continue :outer;
                                    } else if (count < 0) {
                                        return error.StdinReadFailed;
                                    }
                                }
                            }
                        } else {
                            //std.debug.print("timeout\n", .{});
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
