// Copyright (c) 2025 il1v3y. All Rights Reserved.
// Unauthorized copying or use of this file is strictly prohibited.
// Proprietary and confidential.

const std = @import("std");

const builtin = @import("builtin");

const util = @import("util.zig");

const os = if (@hasDecl(std, "posix")) std.posix else std.os;



pub const Scanner = struct {

    allocator: std.mem.Allocator,

    results: std.ArrayListUnmanaged(ScanResult),



    pub const ReportFormat = enum {
        auto,
        json,
        csv,
        ndjson,
        sarif,
        none,
    };

    pub const ScanOptions = struct {
        stealth: bool = false,
        jitter_ms: u32 = 0,
        concurrency: u16 = 128,
        timeout_ms: u32 = 0,
        rate_limit: u32 = 0,
        output_file: ?[]const u8 = null,
        format: ReportFormat = .auto,
        verbose: bool = true,
        quiet: bool = false,
        color: bool = true,
        progress: bool = true,
    };

    const ScanResult = struct {
        ip: []const u8,
        ip_value: u32,
        port: u16,
        status: []const u8,
        service: []const u8,
        banner: ?[]const u8 = null,
    };

    const TargetRange = struct {
        start: u32,
        end: u32,
    };

    const ScanError = error{
        InvalidTarget,
        InvalidCidrPrefix,
        TargetRangeTooLarge,
        InvalidPortSpec,
        InvalidConcurrency,
    };

    const max_targets: u64 = 65_536;

    pub fn init(allocator: std.mem.Allocator) Scanner {
        return .{
            .allocator = allocator,
            .results = .empty,
        };
    }

    pub fn deinit(self: *Scanner) void {
        for (self.results.items) |result| {
            self.allocator.free(result.ip);
            if (result.banner) |b| self.allocator.free(b);
        }
        self.results.deinit(self.allocator);
    }

    pub fn scanTarget(
        self: *Scanner,
        target: []const u8,
        ports_str: []const u8,
        options: ScanOptions,
    ) !void {
        var ports_list = try parsePorts(self.allocator, ports_str);
        defer ports_list.deinit(self.allocator);

        const range = try parseTarget(target);
        const host_count: u64 = @as(u64, range.end) - @as(u64, range.start) + 1;

        if (options.concurrency == 0) return ScanError.InvalidConcurrency;
        const concurrency = @as(usize, options.concurrency);

        if (options.color) std.debug.print("\x1b[36m", .{});
        std.debug.print("[+] Starting scan on {s}\n", .{target});
        std.debug.print("[+] Targets: {d}\n", .{host_count});
        std.debug.print("[+] Scanning {d} ports\n", .{ports_list.items.len});
        std.debug.print("[+] Concurrency: {d}\n", .{concurrency});
        if (options.color) std.debug.print("\x1b[0m", .{});

        if (options.stealth) {
            const seed = std.crypto.random.int(u64);
            shufflePorts(ports_list.items, seed);
            if (options.color) std.debug.print("\x1b[33m", .{});
            std.debug.print("[*] Stealth mode enabled:\n", .{});
            std.debug.print("    - Timing jitter\n", .{});
            std.debug.print("    - Randomized port order\n", .{});
            if (options.color) std.debug.print("\x1b[0m", .{});
        }

        const total_tasks = host_count * @as(u64, ports_list.items.len);

        var shared = Shared{
            .allocator = self.allocator,
            .results = &self.results,
            .verbose = options.verbose,
            .quiet = options.quiet,
            .color = options.color,
            .total_tasks = total_tasks,
            .show_progress = options.progress and !options.quiet,
            .rate_limit = options.rate_limit,
            .timer = try std.time.Timer.start(),
        };

        var work = Work{
            .range = range,
            .ports = ports_list.items,
            .jitter_ms = options.jitter_ms,
            .timeout_ms = options.timeout_ms,
        };

        const threads = try self.allocator.alloc(std.Thread, concurrency);
        defer self.allocator.free(threads);

        var i: usize = 0;
        while (i < concurrency) : (i += 1) {
            threads[i] = try std.Thread.spawn(.{}, workerThread, .{ &shared, &work, total_tasks });
        }

        for (threads) |thread| {
            thread.join();
        }

        sortResults(self);

        if (shared.color) std.debug.print("\x1b[35m", .{});
        std.debug.print("[*] Scan complete: {d} open ports found\n", .{shared.open_count});
        if (shared.color) std.debug.print("\x1b[0m", .{});

        printSummary(self.results.items, shared.color, shared.quiet);

        const resolved_format = resolveFormat(options.format, options.output_file);
        if (options.output_file) |file| {
            switch (resolved_format) {
                .json => try exportJSON(self.results.items, file),
                .csv => try exportCSV(self.results.items, file),
                .ndjson => try exportNDJSON(self.results.items, file),
                .sarif => try exportSarif(self.results.items, file),
                .none => {},
                .auto => {},
            }
        }
    }

    const Shared = struct {
        allocator: std.mem.Allocator,
        results: *std.ArrayListUnmanaged(ScanResult),
        verbose: bool,
        quiet: bool,
        color: bool,
        next_index: u64 = 0,
        open_count: u64 = 0,
        total_tasks: u64 = 0,
        progress_done: u64 = 0,
        last_progress_percent: u8 = 0,
        show_progress: bool = false,
        rate_limit: u32 = 0,
        next_allowed_ns: u64 = 0,
        index_mutex: std.Thread.Mutex = .{},
        results_mutex: std.Thread.Mutex = .{},
        print_mutex: std.Thread.Mutex = .{},
        progress_mutex: std.Thread.Mutex = .{},
        rate_mutex: std.Thread.Mutex = .{},
        timer: std.time.Timer,
    };

    const Work = struct {
        range: TargetRange,
        ports: []const u16,
        jitter_ms: u32,
        timeout_ms: u32,
    };

    fn workerThread(shared: *Shared, work: *const Work, total_tasks: u64) void {
        while (true) {
            const task_index = nextTaskIndex(shared, total_tasks) orelse break;
            const port_index = @as(usize, @intCast(task_index % @as(u64, work.ports.len)));
            const host_index = @as(u64, @intCast(task_index / @as(u64, work.ports.len)));
            const ip_value = work.range.start + @as(u32, @intCast(host_index));
            const ip_bytes = u32ToIpv4(ip_value);
            const port = work.ports[port_index];

            applyJitter(work.jitter_ms);
            applyRateLimit(shared);

            if (isPortOpen(ip_bytes, port, work.timeout_ms)) {
                const service = serviceForPort(port);
                const ip_str = formatIpv4(shared.allocator, ip_bytes) catch continue;
                
                // Grab banner
                const banner = grabBanner(shared.allocator, ip_bytes, port, 2000) catch null;

                const result = ScanResult{
                    .ip = ip_str,
                    .ip_value = ip_value,
                    .port = port,
                    .status = "open",
                    .service = service,
                    .banner = banner,
                };

                var stored = false;
                shared.results_mutex.lock();
                shared.results.append(shared.allocator, result) catch {};
                shared.open_count += 1;
                stored = true;
                shared.results_mutex.unlock();

                if (shared.verbose) {
                    shared.print_mutex.lock();
                    if (shared.color) std.debug.print("\x1b[32m", .{});
                    if (banner) |b| {
                        std.debug.print("[+] Port {d}/{s} - OPEN ({s}) | {s}\n", .{ port, service, ip_str, b });
                    } else {
                        std.debug.print("[+] Port {d}/{s} - OPEN ({s})\n", .{ port, service, ip_str });
                    }
                    if (shared.color) std.debug.print("\x1b[0m", .{});
                    shared.print_mutex.unlock();
                }

                if (!stored) {
                    shared.allocator.free(ip_str);
                    if (banner) |b| shared.allocator.free(b);
                }
            }

            updateProgress(shared);
        }
    }

    fn applyRateLimit(shared: *Shared) void {
        if (shared.rate_limit == 0) return;
        const interval_ns: u64 = 1_000_000_000 / @as(u64, shared.rate_limit);
        if (interval_ns == 0) return;

        shared.rate_mutex.lock();
        const now_ns = shared.timer.read();

        var wait_ns: u64 = 0;
        if (now_ns >= shared.next_allowed_ns) {
            shared.next_allowed_ns = now_ns + interval_ns;
        } else {
            wait_ns = shared.next_allowed_ns - now_ns;
            shared.next_allowed_ns += interval_ns;
        }
        shared.rate_mutex.unlock();

        if (wait_ns > 0) {
            util.sleep(wait_ns);
        }
    }

    fn updateProgress(shared: *Shared) void {
        shared.progress_mutex.lock();
        defer shared.progress_mutex.unlock();

        shared.progress_done += 1;
        if (!shared.show_progress) return;

        const percent = @as(u8, @intCast((shared.progress_done * 100) / shared.total_tasks));
        if (percent < shared.last_progress_percent + 5 and percent != 100) return;
        shared.last_progress_percent = percent;

        var bar: [20]u8 = undefined;
        const filled = @as(usize, @intCast((@as(u64, percent) * 20) / 100));
        var i: usize = 0;
        while (i < bar.len) : (i += 1) {
            bar[i] = if (i < filled) '#' else '-';
        }

        shared.print_mutex.lock();
        if (shared.color) std.debug.print("\x1b[36m", .{});
        std.debug.print("[PROGRESS] [{s}] {d}% ({d}/{d})\n", .{ bar[0..], percent, shared.progress_done, shared.total_tasks });
        if (shared.color) std.debug.print("\x1b[0m", .{});
        shared.print_mutex.unlock();
    }

    fn nextTaskIndex(shared: *Shared, total_tasks: u64) ?u64 {
        shared.index_mutex.lock();
        defer shared.index_mutex.unlock();
        if (shared.next_index >= total_tasks) return null;
        const value = shared.next_index;
        shared.next_index += 1;
        return value;
    }

    fn resolveFormat(format: ReportFormat, output_file: ?[]const u8) ReportFormat {
        if (output_file == null) return .none;
        switch (format) {
            .json, .csv, .ndjson, .sarif, .none => return format,
            .auto => {},
        }

        const file = output_file.?;
        if (std.mem.endsWith(u8, file, ".csv")) return .csv;
        if (std.mem.endsWith(u8, file, ".json")) return .json;
        if (std.mem.endsWith(u8, file, ".ndjson")) return .ndjson;
        if (std.mem.endsWith(u8, file, ".sarif")) return .sarif;
        return .json;
    }

    fn printSummary(results: []const ScanResult, color: bool, quiet: bool) void {
        if (quiet) {
            if (color) std.debug.print("\x1b[34m", .{});
            std.debug.print("[SUMMARY] Open ports: {d}\n", .{results.len});
            if (color) std.debug.print("\x1b[0m", .{});
            return;
        }

        if (color) std.debug.print("\x1b[34m", .{});
        std.debug.print("\n[RESULTS]\n", .{});
        if (color) std.debug.print("\x1b[0m", .{});

        if (results.len == 0) {
            std.debug.print("No open ports found.\n", .{});
            return;
        }

        std.debug.print("{s:<15}  {s:>5}  {s}\n", .{"IP", "PORT", "SERVICE"});
        std.debug.print("{s:-<15}  {s:-<5}  {s:-<7}\n", .{"", "", ""});

        for (results) |result| {
            std.debug.print("{s:<15}  {d:>5}  {s}\n", .{ result.ip, result.port, result.service });
        }
    }

    fn parseTarget(target: []const u8) !TargetRange {
        var iter = std.mem.splitSequence(u8, target, "/");
        const ip_part_raw = iter.next() orelse return ScanError.InvalidTarget;
        const ip_part = std.mem.trim(u8, ip_part_raw, " ");
        const prefix_part = iter.next();
        if (iter.next() != null) return ScanError.InvalidTarget;

        const ip_bytes = try parseIpv4(ip_part);
        const base = ipv4ToU32(ip_bytes);

        var prefix: u8 = 32;
        if (prefix_part) |raw_prefix| {
            const trimmed = std.mem.trim(u8, raw_prefix, " ");
            prefix = std.fmt.parseInt(u8, trimmed, 10) catch return ScanError.InvalidCidrPrefix;
        }
        if (prefix > 32) return ScanError.InvalidCidrPrefix;

        var start = base;
        var end = base;
        if (prefix < 32) {
            const shift: u5 = @as(u5, @intCast(32 - prefix));
            const mask: u32 = if (prefix == 0) 0 else (@as(u32, std.math.maxInt(u32)) << shift);
            const network = base & mask;
            const broadcast = network | ~mask;
            start = network;
            end = broadcast;

            if (prefix <= 30) {
                start +%= 1;
                end -%= 1;
            }
        }

        if (end < start) return ScanError.InvalidTarget;

        const count: u64 = @as(u64, end) - @as(u64, start) + 1;
        if (count > max_targets) return ScanError.TargetRangeTooLarge;

        return .{ .start = start, .end = end };
    }

    fn parsePorts(allocator: std.mem.Allocator, ports_str: []const u8) !std.ArrayListUnmanaged(u16) {
        var ports: std.ArrayListUnmanaged(u16) = .empty;

        const included = try allocator.alloc(bool, 65_536);
        defer allocator.free(included);
        @memset(included, false);

        var iter = std.mem.splitSequence(u8, ports_str, ",");
        while (iter.next()) |token_raw| {
            const token = std.mem.trim(u8, token_raw, " ");
            if (token.len == 0) continue;

            if (std.mem.indexOfScalar(u8, token, '-')) |dash_index| {
                const start_str = std.mem.trim(u8, token[0..dash_index], " ");
                const end_str = std.mem.trim(u8, token[dash_index + 1 ..], " ");
                const start_port = try parsePortValue(start_str);
                const end_port = try parsePortValue(end_str);
                if (end_port < start_port) return ScanError.InvalidPortSpec;

                var port_value: u32 = start_port;
                const end_value: u32 = end_port;
                while (port_value <= end_value) : (port_value += 1) {
                    const port = @as(u16, @intCast(port_value));
                    const index = @as(usize, port);
                    if (!included[index]) {
                        try ports.append(allocator, port);
                        included[index] = true;
                    }
                }
            } else {
                const port = try parsePortValue(token);
                const index = @as(usize, port);
                if (!included[index]) {
                    try ports.append(allocator, port);
                    included[index] = true;
                }
            }
        }

        if (ports.items.len == 0) return ScanError.InvalidPortSpec;
        return ports;
    }

    fn parsePortValue(text: []const u8) !u16 {
        if (text.len == 0) return ScanError.InvalidPortSpec;
        const port = std.fmt.parseInt(u16, text, 10) catch return ScanError.InvalidPortSpec;
        if (port == 0) return ScanError.InvalidPortSpec;
        return port;
    }

    fn parseIpv4(ip_str: []const u8) ![4]u8 {
        var parts: [4]u8 = undefined;
        var part_index: usize = 0;

        var iter = std.mem.splitScalar(u8, ip_str, '.');
        while (iter.next()) |part_raw| : (part_index += 1) {
            if (part_index >= 4) return ScanError.InvalidTarget;
            const trimmed = std.mem.trim(u8, part_raw, " ");
            if (trimmed.len == 0) return ScanError.InvalidTarget;
            const value = std.fmt.parseInt(u8, trimmed, 10) catch return ScanError.InvalidTarget;
            parts[part_index] = value;
        }

        if (part_index != 4) return ScanError.InvalidTarget;
        return parts;
    }

    fn ipv4ToU32(ip: [4]u8) u32 {
        return (@as(u32, ip[0]) << 24) |
            (@as(u32, ip[1]) << 16) |
            (@as(u32, ip[2]) << 8) |
            @as(u32, ip[3]);
    }

    fn u32ToIpv4(value: u32) [4]u8 {
        return .{
            @as(u8, @intCast((value >> 24) & 0xff)),
            @as(u8, @intCast((value >> 16) & 0xff)),
            @as(u8, @intCast((value >> 8) & 0xff)),
            @as(u8, @intCast(value & 0xff)),
        };
    }

    fn formatIpv4(allocator: std.mem.Allocator, ip: [4]u8) ![]u8 {
        return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
    }

    fn serviceForPort(port: u16) []const u8 {
        return switch (port) {
            22 => "SSH",
            80 => "HTTP",
            443 => "HTTPS",
            445 => "SMB",
            3389 => "RDP",
            8080 => "HTTP-Alt",
            else => "Unknown",
        };
    }

    fn applyJitter(jitter_ms: u32) void {
        if (jitter_ms == 0) return;
        const delay_ms = std.crypto.random.uintAtMost(u32, jitter_ms);
        util.sleep(@as(u64, delay_ms) * 1_000_000);
    }

    fn shufflePorts(ports: []u16, seed: u64) void {
        if (ports.len < 2) return;
        var rng = XorShift64.init(seed);
        var i = ports.len;
        while (i > 1) {
            i -= 1;
            const j = @as(usize, @intCast(rng.next() % @as(u64, i + 1)));
            std.mem.swap(u16, &ports[i], &ports[j]);
        }
    }

    const XorShift64 = struct {
        state: u64,

        fn init(seed: u64) XorShift64 {
            return .{ .state = if (seed == 0) 0x9E3779B97F4A7C15 else seed };
        }

        fn next(self: *XorShift64) u64 {
            var x = self.state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state = x;
            return x;
        }
    };

    fn grabBanner(allocator: std.mem.Allocator, ip: [4]u8, port: u16, timeout_ms: u32) !?[]u8 {
        _ = timeout_ms; 
        const address = std.net.Address.initIp4(ip, port);
        
        const stream = std.net.tcpConnectToAddress(address) catch return null;
        defer stream.close();

        // Probes
        if (port == 80 or port == 443 or port == 8080) {
            stream.writeAll("HEAD / HTTP/1.0\r\n\r\n") catch {};
        }

        var buf: [128]u8 = undefined;
        const len = stream.read(&buf) catch return null;
        if (len == 0) return null;

        const raw = buf[0..len];
        const clean = try allocator.alloc(u8, len);
        for (raw, 0..) |c, i| {
            if (std.ascii.isPrint(c)) {
                clean[i] = c;
            } else {
                clean[i] = '.';
            }
        }
        return clean;
    }

    fn isPortOpen(ip: [4]u8, port: u16, timeout_ms: u32) bool {
        const address = std.net.Address.initIp4(ip, port);
        if (timeout_ms == 0) {
            const stream = std.net.tcpConnectToAddress(address) catch return false;
            stream.close();
            return true;
        }
        return connectWithTimeout(address, timeout_ms);
    }

    fn connectWithTimeout(address: std.net.Address, timeout_ms: u32) bool {
        const sock_flags = os.SOCK.STREAM | os.SOCK.NONBLOCK |
            (if (builtin.os.tag == .windows) 0 else os.SOCK.CLOEXEC);
        const sockfd = os.socket(address.any.family, sock_flags, os.IPPROTO.TCP) catch return false;
        defer os.close(sockfd);

        os.connect(sockfd, &address.any, address.getOsSockLen()) catch |err| switch (err) {
            error.WouldBlock, error.ConnectionPending => {},
            else => return false,
        };

        var fds = [_]os.pollfd{.{ .fd = sockfd, .events = os.POLL.OUT, .revents = 0 }};
        const timeout_i32: i32 = if (timeout_ms > @as(u32, std.math.maxInt(i32)))
            @as(i32, std.math.maxInt(i32))
        else
            @as(i32, @intCast(timeout_ms));

        const rc = os.poll(&fds, timeout_i32) catch return false;
        if (rc == 0) return false;

        os.getsockoptError(sockfd) catch return false;
        return true;
    }

    fn sortResults(self: *Scanner) void {
        const Context = struct {
            pub fn lessThan(_: void, a: ScanResult, b: ScanResult) bool {
                if (a.ip_value != b.ip_value) return a.ip_value < b.ip_value;
                return a.port < b.port;
            }
        };
        std.sort.block(ScanResult, self.results.items, {}, Context.lessThan);
    }

    fn exportJSON(results: []const ScanResult, filename: []const u8) !void {
        const file = try std.fs.cwd().createFile(filename, .{});
        defer file.close();

        var buffer: [4096]u8 = undefined;
        var writer = file.writer(&buffer);
        try writeJSON(&writer.interface, results);
        try writer.interface.flush();
        std.debug.print("[+] Results saved to {s}\n", .{filename});
    }

    fn exportCSV(results: []const ScanResult, filename: []const u8) !void {
        const file = try std.fs.cwd().createFile(filename, .{});
        defer file.close();

        var buffer: [4096]u8 = undefined;
        var writer = file.writer(&buffer);
        try writeCSV(&writer.interface, results);
        try writer.interface.flush();
        std.debug.print("[+] Results saved to {s}\n", .{filename});
    }

    fn exportNDJSON(results: []const ScanResult, filename: []const u8) !void {
        const file = try std.fs.cwd().createFile(filename, .{});
        defer file.close();

        var buffer: [4096]u8 = undefined;
        var writer = file.writer(&buffer);
        try writeNDJSON(&writer.interface, results);
        try writer.interface.flush();
        std.debug.print("[+] Results saved to {s}\n", .{filename});
    }

    fn exportSarif(results: []const ScanResult, filename: []const u8) !void {
        const file = try std.fs.cwd().createFile(filename, .{});
        defer file.close();

        var buffer: [4096]u8 = undefined;
        var writer = file.writer(&buffer);
        try writeSarif(&writer.interface, results);
        try writer.interface.flush();
        std.debug.print("[+] Results saved to {s}\n", .{filename});
    }

    fn writeJSON(writer: anytype, results: []const ScanResult) !void {
        try writer.writeAll("[\n");
        for (results, 0..) |result, i| {
            try writer.writeAll("  {\n");
            try writer.print("    \"ip\": \"{s}\",\n", .{result.ip});
            try writer.print("    \"port\": {d},\n", .{result.port});
            try writer.print("    \"status\": \"{s}\",\n", .{result.status});
            try writer.print("    \"service\": \"{s}\"\n", .{result.service});

            if (i < results.len - 1) {
                try writer.writeAll("  },\n");
            } else {
                try writer.writeAll("  }\n");
            }
        }
        try writer.writeAll("]\n");
    }

    fn writeCSV(writer: anytype, results: []const ScanResult) !void {
        try writer.print("ip,port,status,service\n", .{});
        for (results) |result| {
            try writer.print("{s},{d},{s},{s}\n", .{ result.ip, result.port, result.status, result.service });
        }
    }

    fn writeNDJSON(writer: anytype, results: []const ScanResult) !void {
        for (results) |result| {
            try writer.print("{{\"ip\":\"{s}\",\"port\":{d},\"status\":\"{s}\",\"service\":\"{s}\"}}\n", .{
                result.ip,
                result.port,
                result.status,
                result.service,
            });
        }
    }

    fn writeSarif(writer: anytype, results: []const ScanResult) !void {
        try writer.writeAll("{\n");
        try writer.writeAll("  \"version\": \"2.1.0\",\n");
        try writer.writeAll("  \"$schema\": \"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json\",\n");
        try writer.writeAll("  \"runs\": [\n");
        try writer.writeAll("    {\n");
        try writer.writeAll("      \"tool\": { \"driver\": { \"name\": \"ZigHound\" } },\n");
        try writer.writeAll("      \"results\": [\n");

        for (results, 0..) |result, i| {
            try writer.writeAll("        {\n");
            try writer.writeAll("          \"ruleId\": \"OPEN_PORT\",\n");
            try writer.writeAll("          \"level\": \"warning\",\n");
            try writer.print("          \"message\": {{ \"text\": \"Open port {d} ({s}) on {s}\" }},\n", .{
                result.port,
                result.service,
                result.ip,
            });
            try writer.print("          \"locations\": [ {{ \"physicalLocation\": {{ \"artifactLocation\": {{ \"uri\": \"{s}:{d}\" }} }} }} ]\n", .{
                result.ip,
                result.port,
            });

            if (i < results.len - 1) {
                try writer.writeAll("        },\n");
            } else {
                try writer.writeAll("        }\n");
            }
        }

        try writer.writeAll("      ]\n");
        try writer.writeAll("    }\n");
        try writer.writeAll("  ]\n");
        try writer.writeAll("}\n");
    }
};
