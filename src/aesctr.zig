const std = @import("std");
const crypto = std.crypto;
const aes = std.crypto.core.aes;
const ctr_mode = crypto.core.modes.ctr;

pub const Aes192 = struct {
    pub const key_bits: usize = 192;
    pub const rounds: usize = 12;

    pub const EncryptCtx = struct {
        pub const block = aes.Block;
        pub const block_length = aes.Block.block_length;
        round_keys: [rounds + 1]aes.Block,

        fn subWord(w: u32) u32 {
            var in_bytes: [16]u8 = undefined;
            defer std.crypto.secureZero(u8, &in_bytes);
            inline for (0..4) |col| {
                std.mem.writeInt(u32, in_bytes[col * 4 ..][0..4], w, .big);
            }
            const zero_block = aes.Block.fromBytes(&@as([16]u8, @splat(0)));
            var sub_bytes = aes.Block.fromBytes(&in_bytes).encryptLast(zero_block).toBytes();
            defer std.crypto.secureZero(u8, &sub_bytes);
            return std.mem.readInt(u32, sub_bytes[0..4], .big);
        }

        pub fn init(key: [key_bits / 8]u8) EncryptCtx {
            const words_in_key = (key_bits / 8) / 4;
            const total_words = (rounds + 1) * 4;
            const rcon = [_]u8{ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };

            var words: [total_words]u32 = undefined;
            defer std.crypto.secureZero(u32, &words);
            inline for (0..words_in_key) |i| {
                words[i] = std.mem.readInt(u32, key[4 * i ..][0..4], .big);
            }
            inline for (words_in_key..total_words) |i| {
                var t = words[i - 1];
                if (i % words_in_key == 0) {
                    t = subWord(std.math.rotl(u32, t, 8)) ^ (@as(u32, rcon[i / words_in_key - 1]) << 24);
                }
                words[i] = words[i - words_in_key] ^ t;
            }

            var round_keys: [rounds + 1]block = undefined;
            var rk_bytes: [16]u8 = undefined;
            defer std.crypto.secureZero(u8, &rk_bytes);
            inline for (0..rounds + 1) |r| {
                inline for (0..4) |c| {
                    std.mem.writeInt(u32, rk_bytes[c * 4 ..][0..4], words[r * 4 + c], .big);
                }
                round_keys[r] = block.fromBytes(&rk_bytes);
            }
            return .{ .round_keys = round_keys };
        }

        pub fn encrypt(ctx: EncryptCtx, dst: *[16]u8, src: *const [16]u8) void {
            var t = block.fromBytes(src).xorBlocks(ctx.round_keys[0]);
            inline for (1..rounds) |i| {
                t = t.encrypt(ctx.round_keys[i]);
            }
            t = t.encryptLast(ctx.round_keys[rounds]);
            dst.* = t.toBytes();
        }

        pub fn xor(ctx: EncryptCtx, dst: *[16]u8, src: *const [16]u8, counter: [16]u8) void {
            var t = block.fromBytes(&counter).xorBlocks(ctx.round_keys[0]);
            inline for (1..rounds) |i| {
                t = t.encrypt(ctx.round_keys[i]);
            }
            t = t.encryptLast(ctx.round_keys[rounds]);
            dst.* = t.xorBytes(src);
        }

        pub fn encryptWide(ctx: EncryptCtx, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8) void {
            var ts: [count]block = undefined;
            inline for (0..count) |j| {
                ts[j] = block.fromBytes(src[j * 16 ..][0..16]).xorBlocks(ctx.round_keys[0]);
            }
            inline for (1..rounds) |i| {
                ts = block.parallel.encryptWide(count, ts, ctx.round_keys[i]);
            }
            ts = block.parallel.encryptLastWide(count, ts, ctx.round_keys[rounds]);
            inline for (0..count) |j| {
                dst[16 * j ..][0..16].* = ts[j].toBytes();
            }
        }

        pub fn xorWide(ctx: EncryptCtx, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8, counters: [16 * count]u8) void {
            var ts: [count]block = undefined;
            inline for (0..count) |j| {
                ts[j] = block.fromBytes(counters[j * 16 ..][0..16]).xorBlocks(ctx.round_keys[0]);
            }
            inline for (1..rounds) |i| {
                ts = block.parallel.encryptWide(count, ts, ctx.round_keys[i]);
            }
            ts = block.parallel.encryptLastWide(count, ts, ctx.round_keys[rounds]);
            inline for (0..count) |j| {
                dst[16 * j ..][0..16].* = ts[j].xorBytes(src[j * 16 ..][0..16]);
            }
        }
    };

    pub fn initEnc(key: [key_bits / 8]u8) EncryptCtx {
        return EncryptCtx.init(key);
    }
};

// convenience wrapper, defining block_size, iv_size, key_size
// ensures that the ctr mode counter matches the number of bytes sent
pub fn AesCtr(enc_algo: anytype) type {
    return struct {
        const Self = @This();
        pub const block_size = 16;
        pub const iv_size = 16;
        pub const key_size = enc_algo.key_bits / 8;
        pub const max_bytes_per_key: u64 = std.math.maxInt(u32);
        pub const Error = error{CounterExhausted};
        const CtxType = @TypeOf(enc_algo.initEnc(@as([key_size]u8, undefined)));
        ctx: CtxType,
        iv: [iv_size]u8,
        origiv: [iv_size]u8,
        bytecount: u64,

        pub fn init(iv: [iv_size]u8, key: [key_size]u8) Self {
            return Self{
                .ctx = enc_algo.initEnc(key),
                .iv = iv,
                .bytecount = 0,
                .origiv = iv,
            };
        }

        pub fn encrypt(self: *Self, in: []const u8, out: []u8) Error!void {
            std.debug.assert(out.len == in.len); // equal sizes only
            if (in.len > max_bytes_per_key - self.bytecount) return error.CounterExhausted;

            // fixup the counter iv according to the bytecount
            // readInt(.big) already yields a host-native integer; byte-swapping it
            // again would corrupt the counter base on big-endian targets.
            const orig = std.mem.readInt(u128, &self.origiv, .big);
            var in_rest = in;
            var out_rest = out;

            const block_offset: usize = @intCast(self.bytecount % iv_size);
            if (block_offset != 0 and in_rest.len > 0) {
                const take = @min(in_rest.len, iv_size - block_offset);
                var counter_bytes: [iv_size]u8 = undefined;
                std.mem.writeInt(u128, &counter_bytes, @as(u128, self.bytecount / iv_size) +% orig, .big);
                const zero_block: [iv_size]u8 = @splat(0);
                var keystream_block: [iv_size]u8 = undefined;
                defer crypto.secureZero(u8, &keystream_block);
                ctr_mode(CtxType, self.ctx, &keystream_block, &zero_block, counter_bytes, std.builtin.Endian.big);
                for (0..take) |i| {
                    out_rest[i] = in_rest[i] ^ keystream_block[block_offset + i];
                }
                self.bytecount += take;
                in_rest = in_rest[take..];
                out_rest = out_rest[take..];
            }

            if (in_rest.len > 0) {
                std.mem.writeInt(u128, &self.iv, @as(u128, self.bytecount / iv_size) +% orig, .big);
                ctr_mode(CtxType, self.ctx, out_rest, in_rest, self.iv, std.builtin.Endian.big);
                self.bytecount += in_rest.len;
            }
            std.mem.writeInt(u128, &self.iv, @as(u128, self.bytecount / iv_size) +% orig, .big);
        }

        pub fn clear(self: *Self) void {
            crypto.secureZero(u8, std.mem.asBytes(self));
        }
    };
}

const util = @import("util.zig");
const TRACE = util.trace;
const UNSAFE_TRACEDUMP = util.unsafeTracedump;

const testalgos = .{ aes.Aes128, Aes192, aes.Aes256 };

test "Aes192 FIPS-197 Appendix C.2 vector" {
    const key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    const in = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const expected = [_]u8{
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
    };
    var out: [16]u8 = undefined;
    const ctx = Aes192.initEnc(key);
    ctx.encrypt(&out, &in);
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "aesctr clear wipes the expanded key and counter state" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);
        const iv: [AesCtrT.iv_size]u8 = @splat(0xA5);
        const key: [AesCtrT.key_size]u8 = @splat(0x5A);
        var ctx = AesCtrT.init(iv, key);

        ctx.clear();

        for (std.mem.asBytes(&ctx)) |byte| {
            try std.testing.expectEqual(@as(u8, 0), byte);
        }
    }
}

test "aesctr fails before its historical u32 byte counter would wrap" {
    const AesCtrT = AesCtr(aes.Aes256);
    const iv: [AesCtrT.iv_size]u8 = @splat(0x11);
    const key: [AesCtrT.key_size]u8 = @splat(0x22);
    var ctx = AesCtrT.init(iv, key);
    defer ctx.clear();
    var input: [AesCtrT.block_size]u8 = @splat(0);
    var output: [AesCtrT.block_size]u8 = undefined;

    ctx.bytecount = AesCtrT.max_bytes_per_key - (2 * AesCtrT.block_size - 1);
    try ctx.encrypt(&input, &output);
    try std.testing.expectEqual(
        AesCtrT.max_bytes_per_key - (AesCtrT.block_size - 1),
        ctx.bytecount,
    );
    try std.testing.expectError(error.CounterExhausted, ctx.encrypt(&input, &output));
    try std.testing.expectEqual(
        AesCtrT.max_bytes_per_key - (AesCtrT.block_size - 1),
        ctx.bytecount,
    );
}

test "aesctr-bigblock-twostage" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);

        const iv: [AesCtrT.iv_size]u8 = @splat('I');
        const key: [AesCtrT.key_size]u8 = @splat('K');
        var aesctx_enc = AesCtrT.init(iv, key);
        defer aesctx_enc.clear();
        const block0_plaintext: [AesCtrT.block_size * 10]u8 = @splat('0');
        var block0_ciphertext: [AesCtrT.block_size * 10]u8 = undefined;
        try aesctx_enc.encrypt(&block0_plaintext, &block0_ciphertext);

        //        UNSAFE_TRACEDUMP(.Debug, "plaintext0", .{}, &block0_plaintext);
        //        UNSAFE_TRACEDUMP(.Debug, "ciphertext0", .{}, &block0_ciphertext);

        const block1_plaintext: [AesCtrT.block_size * 10]u8 = @splat('1');
        var block1_ciphertext: [AesCtrT.block_size * 10]u8 = undefined;
        try aesctx_enc.encrypt(&block1_plaintext, &block1_ciphertext);

        //        UNSAFE_TRACEDUMP(.Debug, "plaintext1", .{}, &block1_plaintext);
        //        UNSAFE_TRACEDUMP(.Debug, "ciphertext1", .{}, &block1_ciphertext);

        var aesctx_dec = AesCtrT.init(iv, key);
        defer aesctx_dec.clear();
        var block0_recovered_plaintext: [AesCtrT.block_size * 10]u8 = undefined;
        try aesctx_dec.encrypt(&block0_ciphertext, &block0_recovered_plaintext);

        //        UNSAFE_TRACEDUMP(.Debug, "ciphertext0", .{}, &block0_ciphertext);
        //        UNSAFE_TRACEDUMP(.Debug, "recovered plaintext0", .{}, &block0_recovered_plaintext);

        try std.testing.expect(std.mem.eql(u8, &block0_plaintext, &block0_recovered_plaintext));

        var block1_recovered_plaintext: [AesCtrT.block_size * 10]u8 = undefined;
        try aesctx_dec.encrypt(&block1_ciphertext, &block1_recovered_plaintext);

        //        UNSAFE_TRACEDUMP(.Debug, "ciphertext1", .{}, &block1_ciphertext);
        //        UNSAFE_TRACEDUMP(.Debug, "recovered plaintext1", .{}, &block1_recovered_plaintext);

        try std.testing.expect(std.mem.eql(u8, &block1_plaintext, &block1_recovered_plaintext));
    }
}

test "aesctr-doubleblock-twostage" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);

        const iv: [AesCtrT.iv_size]u8 = @splat('I');
        const key: [AesCtrT.key_size]u8 = @splat('K');
        var aesctx_enc = AesCtrT.init(iv, key);
        defer aesctx_enc.clear();
        const block0_plaintext: [AesCtrT.block_size]u8 = @splat('0');
        var block0_ciphertext: [AesCtrT.block_size]u8 = undefined;
        try aesctx_enc.encrypt(&block0_plaintext, &block0_ciphertext);

        //        UNSAFE_TRACEDUMP(.Debug, "plaintext0", .{}, &block0_plaintext);
        //        UNSAFE_TRACEDUMP(.Debug, "ciphertext0", .{}, &block0_ciphertext);

        const block1_plaintext: [AesCtrT.block_size]u8 = @splat('1');
        var block1_ciphertext: [AesCtrT.block_size]u8 = undefined;
        try aesctx_enc.encrypt(&block1_plaintext, &block1_ciphertext);

        //        UNSAFE_TRACEDUMP(.Debug, "plaintext1", .{}, &block1_plaintext);
        //        UNSAFE_TRACEDUMP(.Debug, "ciphertext1", .{}, &block1_ciphertext);

        var aesctx_dec = AesCtrT.init(iv, key);
        defer aesctx_dec.clear();
        var block0_recovered_plaintext: [AesCtrT.block_size]u8 = undefined;
        try aesctx_dec.encrypt(&block0_ciphertext, &block0_recovered_plaintext);

        //        UNSAFE_TRACEDUMP(.Debug, "ciphertext0", .{}, &block0_ciphertext);
        //        UNSAFE_TRACEDUMP(.Debug, "recovered plaintext0", .{}, &block0_recovered_plaintext);

        try std.testing.expect(std.mem.eql(u8, &block0_plaintext, &block0_recovered_plaintext));

        var block1_recovered_plaintext: [AesCtrT.block_size]u8 = undefined;
        try aesctx_dec.encrypt(&block1_ciphertext, &block1_recovered_plaintext);

        //        UNSAFE_TRACEDUMP(.Debug, "ciphertext1", .{}, &block1_ciphertext);
        //        UNSAFE_TRACEDUMP(.Debug, "recovered plaintext1", .{}, &block1_recovered_plaintext);

        try std.testing.expect(std.mem.eql(u8, &block1_plaintext, &block1_recovered_plaintext));
    }
}

test "aesctr-singleblock-normal" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);

        const iv: [AesCtrT.iv_size]u8 = @splat('I');
        const key: [AesCtrT.key_size]u8 = @splat('K');
        var aesctx_enc = AesCtrT.init(iv, key);
        defer aesctx_enc.clear();
        const block_plaintext: [AesCtrT.block_size]u8 = @splat('D');
        var block_ciphertext: [AesCtrT.block_size]u8 = undefined;
        try aesctx_enc.encrypt(&block_plaintext, &block_ciphertext);

        //    UNSAFE_TRACEDUMP(.Debug, "plaintext", .{}, &block_plaintext);
        //    UNSAFE_TRACEDUMP(.Debug, "ciphertext", .{}, &block_ciphertext);

        var aesctx_dec = AesCtrT.init(iv, key);
        defer aesctx_dec.clear();
        var block_recovered_plaintext: [AesCtrT.block_size]u8 = undefined;
        try aesctx_dec.encrypt(&block_ciphertext, &block_recovered_plaintext);

        //    UNSAFE_TRACEDUMP(.Debug, "ciphertext", .{}, &block_ciphertext);
        //    UNSAFE_TRACEDUMP(.Debug, "recovered plaintext", .{}, &block_recovered_plaintext);

        try std.testing.expect(std.mem.eql(u8, &block_plaintext, &block_recovered_plaintext));
    }
}

test "aesctr-doubleblock-normal" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);

        const iv: [AesCtrT.iv_size]u8 = @splat('I');
        const key: [AesCtrT.key_size]u8 = @splat('K');
        var aesctx_enc = AesCtrT.init(iv, key);
        defer aesctx_enc.clear();
        const plaintext: [AesCtrT.block_size * 2]u8 = @splat('D');
        var ciphertext: [AesCtrT.block_size * 2]u8 = undefined;
        try aesctx_enc.encrypt(&plaintext, &ciphertext);

        //        UNSAFE_TRACEDUMP(.Debug, "plaintext", .{}, &plaintext);
        //        UNSAFE_TRACEDUMP(.Debug, "ciphertext", .{}, &ciphertext);

        var aesctx_dec = AesCtrT.init(iv, key);
        defer aesctx_dec.clear();
        var recovered_plaintext: [AesCtrT.block_size * 2]u8 = undefined;
        try aesctx_dec.encrypt(&ciphertext, &recovered_plaintext);

        //        UNSAFE_TRACEDUMP(.Debug, "ciphertext", .{}, &ciphertext);
        //        UNSAFE_TRACEDUMP(.Debug, "recovered plaintext", .{}, &recovered_plaintext);

        try std.testing.expect(std.mem.eql(u8, &plaintext, &recovered_plaintext));
    }
}

test "aesctr-singleblock-wrongkey" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);

        const iv: [AesCtrT.iv_size]u8 = @splat('I');
        const key: [AesCtrT.key_size]u8 = @splat('K');
        var aesctx_enc = AesCtrT.init(iv, key);
        defer aesctx_enc.clear();
        const block_plaintext: [AesCtrT.block_size]u8 = @splat('D');
        var block_ciphertext: [AesCtrT.block_size]u8 = undefined;

        try aesctx_enc.encrypt(&block_plaintext, &block_ciphertext);

        const keywrong: [AesCtrT.key_size]u8 = @splat('L');
        var aesctx_dec = AesCtrT.init(iv, keywrong);
        defer aesctx_dec.clear();
        var block_recovered_plaintext: [AesCtrT.block_size]u8 = undefined;
        try aesctx_dec.encrypt(&block_ciphertext, &block_recovered_plaintext);

        try std.testing.expect(!std.mem.eql(u8, &block_plaintext, &block_recovered_plaintext));
    }
}

test "aesctr-singleblock-wrongiv" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);

        const iv: [AesCtrT.iv_size]u8 = @splat('I');
        const key: [AesCtrT.key_size]u8 = @splat('K');
        var aesctx_enc = AesCtrT.init(iv, key);
        defer aesctx_enc.clear();
        const block_plaintext: [AesCtrT.block_size]u8 = @splat('D');
        var block_ciphertext: [AesCtrT.block_size]u8 = undefined;

        try aesctx_enc.encrypt(&block_plaintext, &block_ciphertext);

        const ivwrong: [AesCtrT.iv_size]u8 = @splat('J');
        var aesctx_dec = AesCtrT.init(ivwrong, key);
        defer aesctx_dec.clear();
        var block_recovered_plaintext: [AesCtrT.block_size]u8 = undefined;
        try aesctx_dec.encrypt(&block_ciphertext, &block_recovered_plaintext);

        try std.testing.expect(!std.mem.eql(u8, &block_plaintext, &block_recovered_plaintext));
    }
}

test "aesctr sub-block chunking matches single-shot keystream without counter reuse" {
    inline for (testalgos) |algo| {
        const AesCtrT = AesCtr(algo);
        const iv: [AesCtrT.iv_size]u8 = @splat(0x3C);
        const key: [AesCtrT.key_size]u8 = @splat(0x7E);

        var plaintext: [48]u8 = undefined;
        for (&plaintext, 0..) |*b, idx| b.* = @truncate(idx *% 37 +% 11);

        var single_ctx = AesCtrT.init(iv, key);
        defer single_ctx.clear();
        var expected_ct: [plaintext.len]u8 = undefined;
        try single_ctx.encrypt(&plaintext, &expected_ct);

        var chunked_ctx = AesCtrT.init(iv, key);
        defer chunked_ctx.clear();
        var actual_ct: [plaintext.len]u8 = undefined;
        const chunks = [_]usize{ 5, 11, 3, 19, 10 };
        var offset: usize = 0;
        for (chunks) |chunk_len| {
            try chunked_ctx.encrypt(
                plaintext[offset .. offset + chunk_len],
                actual_ct[offset .. offset + chunk_len],
            );
            offset += chunk_len;
        }
        try std.testing.expectEqual(plaintext.len, offset);
        try std.testing.expectEqualSlices(u8, &expected_ct, &actual_ct);
    }
}
