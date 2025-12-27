// Copyright (c) 2025 il1v3y. All Rights Reserved.
// Unauthorized copying or use of this file is strictly prohibited.
// Proprietary and confidential.

const std = @import("std");
const os = if (@hasDecl(std, "posix")) std.posix else std.os;

pub const Socks5Server = struct {
    allocator: std.mem.Allocator,
    port: u16,
    listener: ?std.net.Server = null,
    
    // Callbacks to bridge SOCKS <-> C2
    // We need to tell the C2 logic: "Hey, open a connection to X:Y" and "Send this data"
    // For now, we'll just focus on the SOCKS protocol parsing.

    pub fn init(allocator: std.mem.Allocator, port: u16) Socks5Server {
        return .{ 
            .allocator = allocator,
            .port = port,
        };
    }

    pub fn listen(self: *Socks5Server) !void {
        const addr = try std.net.Address.parseIp("0.0.0.0", self.port);
        self.listener = try addr.listen(.{ .reuse_address = true });
        std.debug.print("[*] SOCKS5 Server listening on 0.0.0.0:{d}\n", .{self.port});
    }

    pub fn accept(self: *Socks5Server) !std.net.Server.Connection {
        if (self.listener) |*l| {
            return l.accept();
        }
        return error.NotListening;
    }

    // Handles the initial SOCKS5 handshake (Client Auth negotiation)
    pub fn handleHandshake(reader: anytype, writer: anytype) !void {
        // Version (1 byte)
        const ver = try reader.takeByte();
        if (ver != 5) return error.InvalidSocksVersion;

        // Number of methods (1 byte)
        const nmethods = try reader.takeByte();
        
        // Methods (n bytes)
        var methods: [255]u8 = undefined;
        if (nmethods > 0) {
            _ = try reader.readSliceAll(methods[0..nmethods]);
        }

        // We only support NO AUTH (0x00) for now
        // Server response: VER (1 byte), METHOD (1 byte)
        try writer.writeByte(5);
        try writer.writeByte(0); // 0x00 = No Auth
    }

    pub const Request = struct {
        cmd: u8,
        addr: std.net.Address,
        domain: ?[]u8 = null, // If domain name was used
    };

    // Parses the connection request (CONNECT X:Y)
    pub fn handleRequest(allocator: std.mem.Allocator, reader: anytype, writer: anytype) !Request {
        const ver = try reader.takeByte();
        if (ver != 5) return error.InvalidSocksVersion;

        const cmd = try reader.takeByte(); // 1 = CONNECT
        _ = try reader.takeByte(); // RSV (Reserved)
        const atyp = try reader.takeByte(); // Address Type

        var addr: std.net.Address = undefined;
        var domain: ?[]u8 = null;

        if (atyp == 1) { // IPv4
            var ip: [4]u8 = undefined;
            _ = try reader.readSliceAll(&ip);
            const port = try reader.takeInt(u16, .big);
            addr = std.net.Address.initIp4(ip, port);
        } else if (atyp == 3) { // Domain Name
            const len = try reader.takeByte();
            const d = try allocator.alloc(u8, len);
            _ = try reader.readSliceAll(d);
            const port = try reader.takeInt(u16, .big);
            // We return the domain so the Agent can resolve it remotely!
            // But we need a dummy address for the struct.
            addr = std.net.Address.initIp4(.{0,0,0,0}, port);
            domain = d;
        } else {
            return error.UnsupportedAddressType;
        }

        // Send success reply immediately (fake it till you make it)
        // Ideally we wait for Agent confirmation, but for speed...
        // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
        try writer.writeAll(&[_]u8{ 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 });

        return Request{ .cmd = cmd, .addr = addr, .domain = domain };
    }
};
