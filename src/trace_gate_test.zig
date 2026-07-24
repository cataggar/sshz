const util = @import("util.zig");

comptime {
    if (util.unsafe_secret_tracing) {
        @compileError("default builds must compile out unsafe secret tracing");
    }
}

test "default build compiles out unsafe secret tracing" {
    _ = util;
}
