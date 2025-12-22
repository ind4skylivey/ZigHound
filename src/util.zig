const std = @import("std");
const builtin = @import("builtin");

pub fn sleep(ns: u64) void {
    if (builtin.os.tag == .windows) {
        std.os.windows.kernel32.Sleep(@as(u32, @intCast(ns / 1_000_000)));
        return;
    }
    
    // Try std.Thread.sleep (Modern Zig 0.15.2+)
    if (@hasDecl(std.Thread, "sleep")) {
        std.Thread.sleep(ns);
        return;
    }

    // Try std.time.sleep (Stable Zig 0.13.0)
    if (@hasDecl(std.time, "sleep")) {
        std.time.sleep(ns);
        return;
    }
    
    // Manual fallback for Linux
    if (builtin.os.tag == .linux) {
        const timespec = extern struct { tv_sec: isize, tv_nsec: isize };
        var req = timespec{ 
            .tv_sec = @as(isize, @intCast(ns / 1_000_000_000)), 
            .tv_nsec = @as(isize, @intCast(ns % 1_000_000_000)) 
        };
        _ = std.os.linux.syscall2(.nanosleep, @intFromPtr(&req), 0);
    }
}
