const std = @import("std");
const posix = std.posix;
const MisshodServer = @import("misshod").MisshodServer;

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

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

    var addr = std.Io.net.IpAddress{ .ip4 = .unspecified(port) };
    var server = try std.Io.net.IpAddress.listen(&addr, init.io, .{ .reuse_address = true });

    std.debug.print("Server listening on port {d}\n", .{port});

    nextclient: while(true) {
        var stream = try server.accept(init.io);
        defer stream.close(init.io);

        // make a reasonable prng
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        try init.io.randomSecure(&seed);
        var prng = std.Random.DefaultCsprng.init(seed);

        var misshod = try MisshodServer.init(prng.random(), hostkey_ascii, allocator);
        defer misshod.deinit(allocator);

        var iobuf: [8]u8 = undefined; // could be any size
        var quit = false;
        var pipe: [2]std.c.fd_t = undefined;
        if (std.c.pipe(&pipe) != 0) return error.PipeFailed;
        defer _ = std.posix.system.close(pipe[0]);
        defer _ = std.posix.system.close(pipe[1]);

        ioloop: while (!quit) {
            const ev = try misshod.getNextEvent();
            switch (ev) {
                .Event => |eventCode| {
                    switch (eventCode) {
                        .Connected => {
                            std.debug.print("Connected!\n", .{});
                            try misshod.clearEvent(eventCode);
                        },
                        .RxData => |rbuf| {
                            if (std.c.write(std.posix.STDOUT_FILENO, rbuf.ptr, rbuf.len) < 0) {
                                return error.StdoutWriteFailed;
                            }

                            var response_buf: [1024]u8 = undefined;
                            const response = try std.fmt.bufPrint(&response_buf, "You said '{s}'\r\n", .{rbuf});
                            if (std.c.write(pipe[1], response.ptr, response.len) < 0) {
                                return error.PipeWriteFailed;
                            }

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
                                        std.debug.assert(std.base64.standard.Encoder.calcSize(pubkey.len) <= fingerprint_buf.len);
                                        const fingerprint = std.base64.standard.Encoder.encode(&fingerprint_buf, pubkey);
                                        std.debug.print("FIXME decide whether to allow username={s} pubkey={s}\n", .{credentials.username, fingerprint});

                                        try misshod.grantAccess(true);  // FIXME
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
                            .fd = pipe[0],
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
                                continue :ioloop;
                            } else if (nread < 0) {
                                return error.SocketReadFailed;
                            } else {
                                continue :nextclient;
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
                            continue :ioloop;
                        }
                        if (fds[1].revents & std.posix.POLL.IN > 0) { // data to be sent (from pipe)
                            const buf = try misshod.getChannelWriteBuffer();
                            if (buf.len > 0) {
                                const count = std.c.read(pipe[0], buf.ptr, buf.len);
                                if (count > 0) {
                                    try misshod.channelWriteComplete(@intCast(count));
                                    continue :ioloop;
                                } else if (count < 0) {
                                    return error.PipeReadFailed;
                                }
                            }
                        }
                    } else {
                        //std.debug.print("timeout\n", .{});
                    }
                },
            }
        }
    }
}
