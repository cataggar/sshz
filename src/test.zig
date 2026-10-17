const std = @import("std");
const Sshz = @import("sshz.zig");
const SshzClient = Sshz.SshzClient;
const SshzServer = Sshz.SshzServer;
const IoError = Sshz.IoError;
const MacInputError = Sshz.MacInputError;
const Protocol = @import("protocol.zig");
const Key = @import("key.zig");
const privkey = @import("privkey.zig");

comptime {
    _ = @import("privkey.zig");
    _ = @import("util.zig");
    _ = @import("client_session.zig");
    _ = @import("server_session.zig");
    _ = @import("buffer.zig");
    _ = @import("hasher.zig");
    _ = @import("aesctr.zig");
    _ = @import("protocol.zig");
    _ = @import("sshz.zig");
    _ = @import("channel.zig");
    _ = @import("key.zig");
    _ = @import("known_hosts.zig");
    _ = @import("receive_completion_test.zig");
}

fn offersForCombo(
    kex: Protocol.KexAlgorithm,
    enc_c2s: Protocol.CipherAlgorithm,
    enc_s2c: Protocol.CipherAlgorithm,
    mac_c2s: Protocol.MacAlgorithm,
    mac_s2c: Protocol.MacAlgorithm,
    host_key: []const u8,
) Protocol.AlgorithmOffers {
    return .{
        .kex = kex.name(),
        .host_key = host_key,
        .encryption_c2s = enc_c2s.name(),
        .encryption_s2c = enc_s2c.name(),
        .mac_c2s = mac_c2s.name(),
        .mac_s2c = mac_s2c.name(),
        .compression_c2s = "none",
        .compression_s2c = "none",
    };
}

fn runLoopbackHandshakeAndRekey(
    initial_kex: Protocol.KexAlgorithm,
    rekey_kex: ?Protocol.KexAlgorithm,
    enc_c2s: Protocol.CipherAlgorithm,
    enc_s2c: Protocol.CipherAlgorithm,
    mac_c2s: Protocol.MacAlgorithm,
    mac_s2c: Protocol.MacAlgorithm,
) !void {
    var cprng = std.Random.DefaultPrng.init(8101);
    var sprng = std.Random.DefaultPrng.init(8102);

    var client = try SshzClient.init(cprng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    var server = try SshzServer.init(sprng.random(), privkey.testkey_valid, std.testing.allocator);
    defer server.deinit();

    client.session.algorithm_offers_override = offersForCombo(
        initial_kex,
        enc_c2s,
        enc_s2c,
        mac_c2s,
        mac_s2c,
        Key.client_hostkey_algorithms,
    );

    var c2s_buf: [65536]u8 = undefined;
    var s2c_buf: [65536]u8 = undefined;
    var c2s_len: usize = 0;
    var s2c_len: usize = 0;

    var connected_client = false;
    var sent_first_payload = false;
    var server_received_first = false;
    var rekey_started = false;
    var sent_second_payload = false;
    var server_received_second = false;
    var initial_session_id: [48]u8 = @splat(0);
    var initial_session_id_len: usize = 0;

    const Endpoint = enum { client_ep, server_ep };
    const endpoints = [_]Endpoint{ .client_ep, .server_ep };

    var steps: usize = 0;
    while (steps < 4000) : (steps += 1) {
        if (rekey_kex == null and connected_client and server_received_first) break;
        if (rekey_kex != null and connected_client and server_received_second) break;

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
                        if (connected_client and !sent_first_payload) {
                            const buf = client.getChannelWriteBuffer(0) catch continue;
                            const msg = "payload-before-rekey";
                            @memcpy(buf[0..msg.len], msg);
                            try client.channelWriteComplete(0, msg.len);
                            sent_first_payload = true;
                        } else if (server_received_first and rekey_kex != null and !rekey_started) {
                            client.session.algorithm_offers_override = offersForCombo(
                                rekey_kex.?,
                                enc_c2s,
                                enc_s2c,
                                mac_c2s,
                                mac_s2c,
                                Key.client_hostkey_algorithms,
                            );
                            client.iostate_rd = .Idle;
                            client.session.startLocalRekey();
                            rekey_started = true;
                        } else if (rekey_started and !client.session.is_rekeying and !sent_second_payload) {
                            const buf = client.getChannelWriteBuffer(0) catch continue;
                            const msg = "payload-after-rekey";
                            @memcpy(buf[0..msg.len], msg);
                            try client.channelWriteComplete(0, msg.len);
                            sent_second_payload = true;
                        }
                        if (s2c_len > 0) {
                            const feed = @min(n, s2c_len);
                            try client.write(s2c_buf[0..feed]);
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
                            try client.write(s2c_buf[0..feed]);
                            std.mem.copyForwards(u8, &s2c_buf, s2c_buf[feed..s2c_len]);
                            s2c_len -= feed;
                        }
                    },
                    .Event => |code| switch (code) {
                        .CheckHostKey => try client.acceptHostKey(),
                        .GetPrivateKey => try client.clearEvent(.GetPrivateKey),
                        .GetAuthPassphrase => {
                            try client.session.setAuthPassphrase("testpass");
                            try client.clearEvent(.GetAuthPassphrase);
                        },
                        .Connected => {
                            connected_client = true;
                            const sid = client.session.sessionIdSlice();
                            initial_session_id_len = sid.len;
                            @memcpy(initial_session_id[0..sid.len], sid);
                            try client.clearEvent(.Connected);
                        },
                        .RxData => try client.clearEvent(code),
                        .EndSession => return error.UnexpectedEndSession,
                        else => try client.clearEvent(code),
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
                            try server.write(c2s_buf[0..feed]);
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
                            try server.write(c2s_buf[0..feed]);
                            std.mem.copyForwards(u8, &c2s_buf, c2s_buf[feed..c2s_len]);
                            c2s_len -= feed;
                        }
                    },
                    .Event => |code| switch (code) {
                        .UserAuth => {
                            try server.grantAccess(true);
                            try server.clearEvent(.{ .UserAuth = .{ .username = "", .auth = null } });
                        },
                        .ChannelOpenRequest => |request| {
                            try server.acceptChannelOpen(request.channel);
                        },
                        .RxData => |rx| {
                            if (!server_received_first) {
                                try std.testing.expectEqualStrings("payload-before-rekey", rx.data);
                                server_received_first = true;
                            } else {
                                try std.testing.expectEqualStrings("payload-after-rekey", rx.data);
                                server_received_second = true;
                            }
                            try server.clearEvent(code);
                        },
                        .EndSession => return error.UnexpectedEndSession,
                        else => try server.clearEvent(code),
                    },
                }
            }
        }
    }

    try std.testing.expect(connected_client);
    try std.testing.expect(server_received_first);
    try std.testing.expectEqual(initial_kex.digestLength(), initial_session_id_len);
    try std.testing.expectEqualSlices(u8, initial_session_id[0..initial_session_id_len], client.session.sessionIdSlice());
    try std.testing.expectEqualSlices(u8, initial_session_id[0..initial_session_id_len], server.session.sessionIdSlice());

    if (rekey_kex) |rk| {
        try std.testing.expect(server_received_second);
        try std.testing.expectEqual(rk, client.session.selected_kex_algorithm);
        try std.testing.expectEqual(rk, server.session.selected_kex_algorithm);
    } else {
        try std.testing.expectEqual(initial_kex, client.session.selected_kex_algorithm);
        try std.testing.expectEqual(initial_kex, server.session.selected_kex_algorithm);
    }
    try std.testing.expectEqual(enc_c2s, client.session.selected_encryption_c2s);
    try std.testing.expectEqual(enc_s2c, client.session.selected_encryption_s2c);
}

test "all 7 KEX algorithms complete full handshake, data transfer, and rekey" {
    const kex_list = [_]Protocol.KexAlgorithm{
        .mlkem1024nistp384_sha384,
        .mlkem768nistp256_sha256,
        .mlkem768x25519_sha256,
        .curve25519_sha256,
        .curve25519_sha256_libssh,
        .ecdh_sha2_nistp384,
        .ecdh_sha2_nistp256,
    };
    for (kex_list) |kex| {
        try runLoopbackHandshakeAndRekey(
            kex,
            kex,
            .aes256_gcm,
            .aes256_gcm,
            .hmac_sha2_256,
            .hmac_sha2_256,
        );
    }
}

test "cross-hash rekey preserves session_id across SHA-256 and SHA-384 KEX transitions" {
    try runLoopbackHandshakeAndRekey(
        .curve25519_sha256,
        .mlkem1024nistp384_sha384,
        .aes256_gcm,
        .chacha20_poly1305,
        .hmac_sha2_512_etm,
        .hmac_sha2_256_etm,
    );
    try runLoopbackHandshakeAndRekey(
        .mlkem1024nistp384_sha384,
        .curve25519_sha256,
        .chacha20_poly1305,
        .aes128_gcm,
        .hmac_sha2_512_etm,
        .hmac_sha2_256,
    );
}

test "all 6 ciphers and 4 MACs complete full handshake and data transfer including asymmetric combinations" {
    const aead_ciphers = [_]Protocol.CipherAlgorithm{
        .aes256_gcm,
        .chacha20_poly1305,
        .aes128_gcm,
    };
    for (aead_ciphers) |cipher| {
        try runLoopbackHandshakeAndRekey(
            .curve25519_sha256,
            null,
            cipher,
            cipher,
            .hmac_sha2_256,
            .hmac_sha2_256,
        );
    }

    const ctr_ciphers = [_]Protocol.CipherAlgorithm{
        .aes256_ctr,
        .aes192_ctr,
        .aes128_ctr,
    };
    const macs = [_]Protocol.MacAlgorithm{
        .hmac_sha2_512_etm,
        .hmac_sha2_256_etm,
        .hmac_sha2_512,
        .hmac_sha2_256,
    };
    for (ctr_ciphers) |cipher| {
        for (macs) |mac| {
            try runLoopbackHandshakeAndRekey(
                .curve25519_sha256,
                null,
                cipher,
                cipher,
                mac,
                mac,
            );
        }
    }

    // Asymmetric c2s AEAD + s2c CTR+EtM and vice versa
    try runLoopbackHandshakeAndRekey(
        .mlkem768x25519_sha256,
        null,
        .aes256_gcm,
        .aes256_ctr,
        .hmac_sha2_256,
        .hmac_sha2_512_etm,
    );
    try runLoopbackHandshakeAndRekey(
        .ecdh_sha2_nistp384,
        null,
        .aes192_ctr,
        .chacha20_poly1305,
        .hmac_sha2_256_etm,
        .hmac_sha2_512,
    );
}

test "negative KEX tests reject wrong C_INIT/S_REPLY lengths and invalid P-256/P-384 SEC1 points" {
    var prng = std.Random.DefaultPrng.init(9001);
    var rand = prng.random();

    var ephem: Protocol.EphemeralKexMaterial = .{};
    defer ephem.clear();

    var shared: [48]u8 = undefined;
    var bad_reply: [1200]u8 = @splat(0x42);
    // Wrong S_REPLY length
    _ = try ephem.initClient(.mlkem768nistp256_sha256, &rand);
    try std.testing.expectError(
        IoError.UnexpectedResponse,
        ephem.finishClient(bad_reply[0..1152], &shared),
    );
    // Compressed SEC1 prefix (0x02 instead of 0x04) in P-256 S_PK1
    _ = try ephem.initClient(.mlkem768nistp256_sha256, &rand);
    bad_reply[1088] = 0x02;
    try std.testing.expectError(
        IoError.InvalidEcdhKey,
        ephem.finishClient(bad_reply[0..1153], &shared),
    );
    // Uncompressed prefix 0x04 with off-curve P-256 coordinates
    _ = try ephem.initClient(.mlkem768nistp256_sha256, &rand);
    bad_reply[1088] = 0x04;
    try std.testing.expectError(
        IoError.InvalidEcdhKey,
        ephem.finishClient(bad_reply[0..1153], &shared),
    );

    // Server side: wrong C_INIT length and invalid P-384 SEC1 point
    var s_reply_buf: [Protocol.MaxKexServerReplyBytes]u8 = undefined;
    var bad_init: [1700]u8 = @splat(0x11);
    try std.testing.expectError(
        IoError.UnexpectedResponse,
        Protocol.EphemeralKexMaterial.respondServer(.ecdh_sha2_nistp384, &rand, bad_init[0..96], &s_reply_buf, &shared),
    );
    bad_init[0] = 0x03;
    try std.testing.expectError(
        IoError.InvalidEcdhKey,
        Protocol.EphemeralKexMaterial.respondServer(.ecdh_sha2_nistp384, &rand, bad_init[0..97], &s_reply_buf, &shared),
    );
    bad_init[0] = 0x04;
    try std.testing.expectError(
        IoError.InvalidEcdhKey,
        Protocol.EphemeralKexMaterial.respondServer(.ecdh_sha2_nistp384, &rand, bad_init[0..97], &s_reply_buf, &shared),
    );
}

test "negative transport tests reject AEAD tag tamper and EtM MAC tamper before decryption" {
    var prng = std.Random.DefaultPrng.init(9101);
    var rand = prng.random();
    const secret = "0123456789abcdef0123456789abcdef";
    const hash = "fedcba9876543210fedcba9876543210";

    // 1. AEAD tag tamper (aes256-gcm@openssh.com and chacha20-poly1305@openssh.com)
    for ([_]Protocol.CipherAlgorithm{ .aes256_gcm, .chacha20_poly1305 }) |cipher| {
        var sender_bi = Protocol.KeyDataBi.init();
        defer sender_bi.clear();
        try sender_bi.genKeysForAlgorithms(hash, secret, hash, .curve25519_sha256, cipher, cipher, null, null);

        var receiver = try SshzServer.init(rand, privkey.testkey_valid, std.testing.allocator);
        defer receiver.deinit();
        try receiver.session.keydata.genKeysForAlgorithms(hash, secret, hash, .curve25519_sha256, cipher, cipher, null, null);
        receiver.session.inbound_encrypted = true;
        receiver.session.setSessionState(.ChannelActive);
        receiver.session.setIoSessionState(.ReadPktHdr);

        var packet_buf: [Protocol.MaxSSHPacket]u8 = undefined;
        const payload = &[_]u8{ @intFromEnum(Protocol.MsgId.SSH_MSG_IGNORE), 0, 0, 0, 4, 't', 'e', 's', 't' };
        const pkt = try Protocol.wrapPayload(&rand, true, &sender_bi.c2s, payload, &packet_buf);

        var tampered: [Protocol.MaxSSHPacket]u8 = undefined;
        @memcpy(tampered[0..pkt.len], pkt);
        tampered[pkt.len - 1] ^= 0x01; // flip last bit of AEAD tag

        _ = try receiver.getNextEvent(); // arms ReadPktHdr (4 bytes)
        try receiver.write(tampered[0..4]);
        _ = try receiver.getNextEvent(); // transitions ReadPktBody -> ReadPktCompletion
        try std.testing.expectError(IoError.InvalidMac, receiver.write(tampered[4..pkt.len]));
    }

    // 2. EtM MAC tamper verified BEFORE decrypting payload (AES-CTR state and ciphertext buffer must not be touched before MAC check)
    var sender_bi = Protocol.KeyDataBi.init();
    defer sender_bi.clear();
    try sender_bi.genKeysForAlgorithms(
        hash,
        secret,
        hash,
        .curve25519_sha256,
        .aes256_ctr,
        .aes256_ctr,
        .hmac_sha2_512_etm,
        .hmac_sha2_512_etm,
    );

    var receiver = try SshzServer.init(rand, privkey.testkey_valid, std.testing.allocator);
    defer receiver.deinit();
    try receiver.session.keydata.genKeysForAlgorithms(
        hash,
        secret,
        hash,
        .curve25519_sha256,
        .aes256_ctr,
        .aes256_ctr,
        .hmac_sha2_512_etm,
        .hmac_sha2_512_etm,
    );
    receiver.session.inbound_encrypted = true;
    receiver.session.setSessionState(.ChannelActive);
    receiver.session.setIoSessionState(.ReadPktHdr);

    var packet_buf: [Protocol.MaxSSHPacket]u8 = undefined;
    const payload = &[_]u8{ @intFromEnum(Protocol.MsgId.SSH_MSG_IGNORE), 0, 0, 0, 4, 't', 'e', 's', 't' };
    const pkt = try Protocol.wrapPayload(&rand, true, &sender_bi.c2s, payload, &packet_buf);

    var tampered: [Protocol.MaxSSHPacket]u8 = undefined;
    @memcpy(tampered[0..pkt.len], pkt);
    tampered[pkt.len - 1] ^= 0x80; // flip bit in EtM HMAC tag

    // Verify directly via getRecvBuffer that EtM MAC failure happens before AES-CTR decryption
    const ctr_before = receiver.session.keydata.c2s.aesctr;
    var ciphertext_before: [Protocol.MaxSSHPacket]u8 = undefined;
    @memcpy(ciphertext_before[0..pkt.len], tampered[0..pkt.len]);
    receiver.session.keydata.c2s.seq = 1;
    try std.testing.expectError(
        IoError.InvalidMac,
        receiver.getRecvBuffer(tampered[0..pkt.len], &receiver.session.keydata.c2s),
    );
    try std.testing.expectEqualSlices(
        u8,
        std.mem.asBytes(&ctr_before),
        std.mem.asBytes(&receiver.session.keydata.c2s.aesctr),
    );
    try std.testing.expectEqualSlices(
        u8,
        ciphertext_before[4..pkt.len],
        tampered[4..pkt.len],
    );

    // And verify full session write path rejects tampered EtM packet with InvalidMac
    receiver.session.keydata.c2s.seq = 0;
    _ = try receiver.getNextEvent();
    try receiver.write(tampered[0..4]);
    _ = try receiver.getNextEvent();
    try std.testing.expectError(IoError.InvalidMac, receiver.write(tampered[4..pkt.len]));
}

