const std = @import("std");
const Sshz = @import("sshz.zig");
const SshzClient = Sshz.SshzClient;
const SshzServer = Sshz.SshzServer;
const IoError = Sshz.IoError;
const Protocol = @import("protocol.zig");
const privkey = @import("privkey.zig");

comptime {
    if (!Protocol.KexAlgorithm.mlkem1024nistp384_sha384.isEnabled()) @compileError("expected mlkem1024nistp384-sha384 enabled");
    if (!Protocol.KexAlgorithm.mlkem768nistp256_sha256.isEnabled()) @compileError("expected mlkem768nistp256-sha256 enabled");
    if (!Protocol.KexAlgorithm.ecdh_sha2_nistp384.isEnabled()) @compileError("expected ecdh-sha2-nistp384 enabled");
    if (Protocol.KexAlgorithm.mlkem768x25519_sha256.isEnabled()) @compileError("expected mlkem768x25519-sha256 disabled");
    if (Protocol.KexAlgorithm.curve25519_sha256.isEnabled()) @compileError("expected curve25519-sha256 disabled");
    if (Protocol.KexAlgorithm.curve25519_sha256_libssh.isEnabled()) @compileError("expected curve25519-sha256@libssh.org disabled");
    if (Protocol.KexAlgorithm.ecdh_sha2_nistp256.isEnabled()) @compileError("expected ecdh-sha2-nistp256 disabled");

    if (!Protocol.CipherAlgorithm.aes256_gcm.isEnabled()) @compileError("expected aes256-gcm@openssh.com enabled");
    if (!Protocol.CipherAlgorithm.aes256_ctr.isEnabled()) @compileError("expected aes256-ctr enabled");
    if (Protocol.CipherAlgorithm.chacha20_poly1305.isEnabled()) @compileError("expected chacha20-poly1305@openssh.com disabled");
    if (Protocol.CipherAlgorithm.aes128_gcm.isEnabled()) @compileError("expected aes128-gcm@openssh.com disabled");
    if (Protocol.CipherAlgorithm.aes192_ctr.isEnabled()) @compileError("expected aes192-ctr disabled");
    if (Protocol.CipherAlgorithm.aes128_ctr.isEnabled()) @compileError("expected aes128-ctr disabled");

    if (!Protocol.MacAlgorithm.hmac_sha2_512_etm.isEnabled()) @compileError("expected hmac-sha2-512-etm@openssh.com enabled");
    if (Protocol.MacAlgorithm.hmac_sha2_256_etm.isEnabled()) @compileError("expected hmac-sha2-256-etm@openssh.com disabled");
    if (Protocol.MacAlgorithm.hmac_sha2_512.isEnabled()) @compileError("expected hmac-sha2-512 disabled");
    if (Protocol.MacAlgorithm.hmac_sha2_256.isEnabled()) @compileError("expected hmac-sha2-256 disabled");

    if (!Sshz.SignatureAlgorithm.Mldsa87P384.isEnabled()) @compileError("expected ssh-mldsa87-p384 enabled");
    if (!Sshz.SignatureAlgorithm.EcdsaP384Sha384.isEnabled()) @compileError("expected ecdsa-sha2-nistp384 enabled");
    if (Sshz.SignatureAlgorithm.Mldsa44Ed25519.isEnabled()) @compileError("expected ssh-mldsa44-ed25519 disabled");
    if (Sshz.SignatureAlgorithm.Ed25519.isEnabled()) @compileError("expected ssh-ed25519 disabled");
    if (Sshz.SignatureAlgorithm.EcdsaP256Sha256.isEnabled()) @compileError("expected ecdsa-sha2-nistp256 disabled");
    if (Sshz.SignatureAlgorithm.RsaSha512.isEnabled()) @compileError("expected rsa-sha2-512 disabled");
    if (Sshz.SignatureAlgorithm.RsaSha256.isEnabled()) @compileError("expected rsa-sha2-256 disabled");
}

test "restricted CNSA/NIST algorithm build advertises only enabled algorithms and rejects disabled algorithms" {
    const offers = Protocol.localAlgorithmOffers("ssh-mldsa87-p384,ecdsa-sha2-nistp384");
    try std.testing.expectEqualStrings(
        "mlkem1024nistp384-sha384,mlkem768nistp256-sha256,ecdh-sha2-nistp384",
        offers.kex,
    );
    try std.testing.expectEqualStrings(
        "aes256-gcm@openssh.com,aes256-ctr",
        offers.encryption_c2s,
    );
    try std.testing.expectEqualStrings(
        "hmac-sha2-512-etm@openssh.com",
        offers.mac_c2s,
    );

    const valid_peer: Protocol.KexInit = .{
        .offers = .{
            .kex = "ecdh-sha2-nistp384",
            .host_key = "ssh-mldsa87-p384,ecdsa-sha2-nistp384",
            .encryption_c2s = "aes256-ctr",
            .encryption_s2c = "aes256-gcm@openssh.com",
            .mac_c2s = "hmac-sha2-512-etm@openssh.com",
            .mac_s2c = "hmac-sha2-256",
            .compression_c2s = "none",
            .compression_s2c = "none",
        },
        .language_c2s = "",
        .language_s2c = "",
        .first_kex_packet_follows = false,
    };

    for ([_]Protocol.AlgorithmRole{ .Client, .Server }) |role| {
        const negotiated = try Protocol.negotiateAlgorithms(valid_peer, role, "ssh-mldsa87-p384,ecdsa-sha2-nistp384");
        try std.testing.expectEqual(Protocol.KexAlgorithm.ecdh_sha2_nistp384, negotiated.kex);
        try std.testing.expectEqualStrings("ssh-mldsa87-p384", negotiated.host_key);
        try std.testing.expectEqual(Protocol.CipherAlgorithm.aes256_ctr, negotiated.encryption_c2s);
        try std.testing.expectEqual(Protocol.CipherAlgorithm.aes256_gcm, negotiated.encryption_s2c);
        try std.testing.expectEqual(@as(?Protocol.MacAlgorithm, .hmac_sha2_512_etm), negotiated.mac_c2s);
        try std.testing.expectEqual(@as(?Protocol.MacAlgorithm, null), negotiated.mac_s2c);

        var disabled_kex = valid_peer;
        disabled_kex.offers.kex = "curve25519-sha256";
        try std.testing.expectError(
            IoError.AlgorithmNegotiationFailed,
            Protocol.negotiateAlgorithms(disabled_kex, role, "ssh-mldsa87-p384,ecdsa-sha2-nistp384"),
        );

        var disabled_sig = valid_peer;
        disabled_sig.offers.host_key = "ssh-ed25519";
        try std.testing.expectError(
            IoError.AlgorithmNegotiationFailed,
            Protocol.negotiateAlgorithms(disabled_sig, role, "ssh-mldsa87-p384,ecdsa-sha2-nistp384"),
        );

        var disabled_cipher = valid_peer;
        disabled_cipher.offers.encryption_c2s = "aes128-ctr";
        try std.testing.expectError(
            IoError.AlgorithmNegotiationFailed,
            Protocol.negotiateAlgorithms(disabled_cipher, role, "ssh-mldsa87-p384,ecdsa-sha2-nistp384"),
        );

        var disabled_mac = valid_peer;
        disabled_mac.offers.mac_c2s = "hmac-sha2-256";
        try std.testing.expectError(
            IoError.AlgorithmNegotiationFailed,
            Protocol.negotiateAlgorithms(disabled_mac, role, "ssh-mldsa87-p384,ecdsa-sha2-nistp384"),
        );
    }
}

test "restricted CNSA/NIST algorithm build completes full client-server handshake and data transfer" {
    var cprng = std.Random.DefaultPrng.init(3101);
    var sprng = std.Random.DefaultPrng.init(3102);

    var host_key = privkey.testKeyMldsa87P384();
    defer host_key.clear();
    var host_pem_buf: [16384]u8 = undefined;
    const host_pem = try privkey.encodeTestOpenSshPrivateKeyPem(&host_key, null, &host_pem_buf);

    var client = try SshzClient.init(cprng.random(), "testuser", std.testing.allocator);
    defer client.deinit();
    var server = try SshzServer.init(sprng.random(), host_pem, std.testing.allocator);
    defer server.deinit();

    var c2s_buf: [65536]u8 = undefined;
    var s2c_buf: [65536]u8 = undefined;
    var c2s_len: usize = 0;
    var s2c_len: usize = 0;

    var connected_client = false;
    var sent_payload = false;
    var server_received = false;

    const Endpoint = enum { client_ep, server_ep };
    const endpoints = [_]Endpoint{ .client_ep, .server_ep };

    var steps: usize = 0;
    while (steps < 2000) : (steps += 1) {
        if (connected_client and server_received) break;

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
                        if (connected_client and !sent_payload) {
                            const buf = client.getChannelWriteBuffer(0) catch continue;
                            const msg = "cnsa-mlkem1024-aes256gcm-payload";
                            @memcpy(buf[0..msg.len], msg);
                            try client.channelWriteComplete(0, msg.len);
                            sent_payload = true;
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
                            try client.clearEvent(.Connected);
                        },
                        else => try client.clearEvent(code),
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
                            try std.testing.expectEqualStrings("cnsa-mlkem1024-aes256gcm-payload", rx.data);
                            server_received = true;
                            try server.clearEvent(code);
                        },
                        else => try server.clearEvent(code),
                    },
                }
            }
        }
    }

    try std.testing.expect(connected_client);
    try std.testing.expect(server_received);
    try std.testing.expectEqual(Protocol.KexAlgorithm.mlkem1024nistp384_sha384, client.session.selected_kex_algorithm);
    try std.testing.expectEqual(Protocol.CipherAlgorithm.aes256_gcm, client.session.selected_encryption_c2s);
    try std.testing.expectEqual(@as(usize, 48), client.session.sessionIdSlice().len);
    try std.testing.expectEqualSlices(u8, client.session.sessionIdSlice(), server.session.sessionIdSlice());
}
