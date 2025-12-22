// Copyright (c) 2025 il1v3y. All Rights Reserved.
// Unauthorized copying or use of this file is strictly prohibited.
// Proprietary and confidential.

const std = @import("std");

pub const ProxyManager = struct {
    allocator: std.mem.Allocator,
    sockets: std.AutoHashMap(u32, std.net.Stream),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) ProxyManager {
        return .{
            .allocator = allocator,
            .sockets = std.AutoHashMap(u32, std.net.Stream).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *ProxyManager) void {
        var iter = self.sockets.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.close();
        }
        self.sockets.deinit();
    }

    pub fn connect(self: *ProxyManager, id: u32, host: []const u8, port: u16) !void {
        const address = std.net.Address.parseIp(host, port) catch {
            // If DNS resolution needed, we'd do it here. For now assume IP.
            return error.InvalidAddress;
        };
        
        // Timeout handling is tricky here without async IO, so we rely on OS defaults or non-blocking later.
        const stream = try std.net.tcpConnectToAddress(address);
        
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.sockets.put(id, stream);
    }

    pub fn write(self: *ProxyManager, id: u32, data: []const u8) !void {
        self.mutex.lock();
        const stream = self.sockets.get(id) orelse {
            self.mutex.unlock();
            return error.SocketNotFound;
        };
        self.mutex.unlock();

        // Write might block, strictly speaking we should do this async or with short timeout
        try stream.writeAll(data);
    }

    pub fn read(self: *ProxyManager, id: u32) ![]u8 {
        self.mutex.lock();
        const stream = self.sockets.get(id) orelse {
            self.mutex.unlock();
            return error.SocketNotFound;
        };
        self.mutex.unlock();

        var buf: [4096]u8 = undefined;
        // Non-blocking read would be ideal.
        
        const len = try stream.read(&buf);
        return self.allocator.dupe(u8, buf[0..len]);
    }

    pub fn close(self: *ProxyManager, id: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.sockets.fetchRemove(id)) |kv| {
            kv.value.close();
        }
    }
};
