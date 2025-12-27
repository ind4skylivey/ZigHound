// Copyright (c) 2025 il1v3y. All Rights Reserved.
// Unauthorized copying or use of this file is strictly prohibited.
// Proprietary and confidential.

const std = @import("std");
const builtin = @import("builtin");
const os = if (@hasDecl(std, "posix")) std.posix else std.os;
const ArrayList = std.array_list.Managed;

pub const PrivEsc = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PrivEsc {
        return .{ .allocator = allocator };
    }

    pub fn audit(self: *PrivEsc) ![]u8 {
        var report: std.ArrayListUnmanaged(u8) = .empty;
        defer report.deinit(self.allocator);
        const writer = report.writer(self.allocator);

        try writer.print("=== Privilege Escalation Audit ===\n", .{});

        if (builtin.os.tag == .linux) {
            try self.auditLinux(writer);
        } else if (builtin.os.tag == .windows) {
            try self.auditWindows(writer);
        } else {
            try writer.print("[-] OS not supported for automated audit.\n", .{});
        }

        return report.toOwnedSlice(self.allocator);
    }

    fn auditLinux(self: *PrivEsc, writer: anytype) !void {
        _ = self;
        // 1. Check current user
        const uid = std.os.linux.getuid();
        try writer.print("[*] Current UID: {d}\n", .{uid});
        if (uid == 0) {
            try writer.print("[+] ALREADY ROOT!\n", .{});
            return;
        }

        // 2. Search for SUID binaries in common paths
        try writer.print("[*] Searching for SUID binaries...\n", .{});
        const paths = [_][]const u8{ "/usr/bin", "/bin", "/usr/sbin", "/sbin" };
        
        for (paths) |path| {
            var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch continue;
            defer dir.close();

            var iter = dir.iterate();
            while (iter.next() catch continue) |entry| {
                if (entry.kind == .file) {
                    const stat = dir.statFile(entry.name) catch continue;
                    // SUID bit is 0o4000
                    if (stat.mode & 0o4000 != 0) {
                        try writer.print("    [!] SUID Found: {s}/{s}\n", .{ path, entry.name });
                    }
                }
            }
        }
    }

    fn auditWindows(self: *PrivEsc, writer: anytype) !void {
        _ = self;
        try writer.print("[*] Checking for Unquoted Service Paths...\n", .{});
        try writer.print("    [i] Run manually: wmic service get name,displayname,pathname,startmode | findstr /i \"Auto\" | findstr /i /v \"C:\\Windows\\\" | findstr /i /v \"\"\"\n", .{});
        
        try writer.print("[*] Checking AlwaysInstallElevated...\n", .{});
        try writer.print("    [i] Run manually: reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n", .{});
    }
};
