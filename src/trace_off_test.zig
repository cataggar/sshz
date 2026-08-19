//! A default build must not write to the host's stderr.
//!
//! Compiled with the same options a dependent gets, so this fails if `-Dtrace`
//! ever defaults to anything but `off`. The check is at comptime because
//! `trace` writes through `std.debug.print`, which a test cannot intercept --
//! and because the gate should cost nothing at runtime.

const util = @import("util.zig");

comptime {
    if (util.traces_are_printed) {
        @compileError("default builds must not print traces: an application that " ++
            "links misshod owns its own stderr, and a terminal UI owns its screen");
    }
}

test "default build prints nothing" {
    _ = util;
}
