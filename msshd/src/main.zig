const std = @import("std");
const MisshodServer = @import("misshod").MisshodServer;

fn readFd(fd: std.c.fd_t, buf: []u8) !usize {
    if (buf.len == 0) return 0;
    const n = std.c.read(fd, buf.ptr, buf.len);
    if (n < 0) return error.ReadFailed;
    return @intCast(n);
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
        const n = try writeFd(fd, data[off..]);
        if (n == 0) return error.WriteFailed;
        off += n;
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    if (args.len < 3) {
        std.debug.print("{s} <port> <hostkey>\n", .{args[0]});
        std.process.exit(1);
    }

    const hostkey_ascii = std.Io.Dir.cwd().readFileAlloc(init.io, args[2], allocator, .limited(1024)) catch {
        std.debug.print("Failed to open hostkey file {s}\n", .{args[2]});
        std.process.exit(1);
    };
    defer allocator.free(hostkey_ascii);

    const port = try std.fmt.parseInt(u16, args[1], 10);

    const addr: std.Io.net.IpAddress = .{ .ip4 = .unspecified(port) };
    var server = try addr.listen(init.io, .{ .reuse_address = true });
    defer server.deinit(init.io);

    std.debug.print("Server listening on port {d}\n", .{port});

    nextclient: while(true) {
        var stream = try server.accept(init.io);
        defer stream.close(init.io);

        // make a reasonable prng
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        if (std.c.getrandom(&seed, seed.len, 0) != seed.len) return error.RandomSeedFailed;
        var prng = std.Random.DefaultCsprng.init(seed);

        var misshod = try MisshodServer.init(prng.random(), hostkey_ascii, allocator);
        defer misshod.deinit();

        var iobuf: [8]u8 = undefined; // could be any size
        var quit = false;
        var pipe: [2]std.c.fd_t = undefined;
        if (std.c.pipe(&pipe) != 0) return error.PipeFailed;
        defer _ = std.c.close(pipe[0]);
        defer _ = std.c.close(pipe[1]);

        ioloop: while (!quit) {
            const ev = try misshod.getNextEvent();
            switch (ev) {
                .Event => |eventCode| {
                    switch (eventCode) {
                        .Connected => {
                            std.debug.print("Connected!\n", .{});
                            try misshod.clearEvent(eventCode);
                        },
                        .RxData => |rxdata| {
                            try writeAllFd(std.c.STDOUT_FILENO, rxdata.data);

                            var response_buf: [1024]u8 = undefined;
                            const response = try std.fmt.bufPrint(&response_buf, "You said '{s}'\r\n", .{rxdata.data});
                            try writeAllFd(pipe[1], response);

                            try misshod.clearEvent(eventCode);
                        },
                        .EndSession => |reason| {
                            std.debug.print("Session ended: {any}\n", .{reason});
                            quit = true;
                            continue :ioloop;
                        },
                        .UserAuth => |credentials| {
                            //std.debug.print("credentials: {any}\n", .{credentials});
                            if (credentials.auth) |auth| {
                                switch(auth) {
                                    .Password => |password| {
                                        // FIXME, some kind of username/password lookup
                                        // for now, rule is password must match username
                                        try misshod.grantAccess(std.mem.eql(u8, credentials.username, password));
                                    },
                                    .Pubkey => |pubkey| {
                                        var fingerprint_buf: [512]u8 = undefined;
                                        std.debug.assert(std.base64.standard.Encoder.calcSize(pubkey.blob.len) <= fingerprint_buf.len);
                                        const fingerprint = std.base64.standard.Encoder.encode(&fingerprint_buf, pubkey.blob);
                                        std.debug.print("FIXME decide whether to allow username={s} pubkey_alg={s} pubkey={s}\n", .{ credentials.username, pubkey.algorithm, fingerprint });

                                        try misshod.grantAccess(true);  // FIXME
                                    },
                                    .KeyboardInteractive => {
                                        try misshod.grantAccess(false);
                                    },
                                }
                            } else {
                                try misshod.grantAccess(false); // "none"
                            }
                            try misshod.clearEvent(eventCode);
                        },
                        .GetPubkeyForUser => |username| {
                            std.debug.print(".GetPubkeyForUser: {s}\n", .{username});
                            std.debug.assert(false);
                        },
                        .ChannelRequest, .WindowChange, .Signal, .RxExtendedData, .AgentChannelOpen, .AgentChannelClosed => {
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

                    var fds = [_]std.posix.pollfd{
                        .{
                            .fd = stream.socket.handle,
                            .events = pollevts,
                            .revents = undefined,
                        },
                        .{
                            .fd = pipe[0],
                            .events = std.posix.POLL.IN,
                            .revents = undefined,
                        },
                    };

                    const ready = std.posix.poll(&fds, 1000) catch 0;
                    if (ready > 0) {
                        if (fds[0].revents & std.posix.POLL.IN > 0 and consume_len > 0) { // socket is readable
                            var bytes_to_read = consume_len;
                            if (bytes_to_read > iobuf.len) {
                                bytes_to_read = iobuf.len;
                            }
                            const nbytes = try readFd(stream.socket.handle, iobuf[0..bytes_to_read]);
                            if (nbytes > 0) {
                                try misshod.write(iobuf[0..nbytes]);
                                continue :ioloop;
                            } else {
                                continue :nextclient;
                            }
                        }
                        if (fds[0].revents & std.posix.POLL.OUT > 0) { // socket is writeable
                            const towrite = try misshod.peek(4);
                            const bytes_written = try writeFd(stream.socket.handle, towrite);
                            try misshod.consumed(bytes_written);
                            continue :ioloop;
                        }
                        if (fds[1].revents & std.posix.POLL.IN > 0) { // data to be sent (from pipe)
                            const buf = try misshod.getChannelWriteBuffer(0);
                            if (buf.len > 0) {
                                const count = readFd(pipe[0], buf) catch 0;
                                if (count > 0) {
                                    try misshod.channelWriteComplete(0, count);
                                    continue :ioloop;
                                }
                            }
                        }
                    }
                },
            }
        }
    }
}
