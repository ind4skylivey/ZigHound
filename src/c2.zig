const std = @import("std");
const ArrayList = std.array_list.Managed;

pub const default_state_file = ".zighound_c2_sim.txt";

pub const StateError = error{
    InvalidStateLine,
    InvalidField,
    BeaconNotFound,
    InvalidCommand,
};

pub const Beacon = struct {
    id: []const u8,
    listener: []const u8,
    jitter: u32,
    status: []const u8,
    last_callback: i64,
};

pub const Command = struct {
    id: u64,
    beacon_id: []const u8,
    command: []const u8,
    status: []const u8,
    created_at: i64,
    output: []const u8,
};

pub const C2State = struct {
    allocator: std.mem.Allocator,
    beacons: ArrayList(Beacon),
    commands: ArrayList(Command),
    next_command_id: u64,

    pub fn init(allocator: std.mem.Allocator) C2State {
        return .{
            .allocator = allocator,
            .beacons = ArrayList(Beacon).init(allocator),
            .commands = ArrayList(Command).init(allocator),
            .next_command_id = 1,
        };
    }

    pub fn deinit(self: *C2State) void {
        for (self.beacons.items) |beacon| {
            self.allocator.free(beacon.id);
            self.allocator.free(beacon.listener);
            self.allocator.free(beacon.status);
        }
        for (self.commands.items) |command| {
            self.allocator.free(command.beacon_id);
            self.allocator.free(command.command);
            self.allocator.free(command.status);
            self.allocator.free(command.output);
        }
        self.beacons.deinit();
        self.commands.deinit();
    }
};

pub fn loadState(allocator: std.mem.Allocator, path: []const u8) !C2State {
    var state = C2State.init(allocator);
    errdefer state.deinit();

    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        if (err == error.FileNotFound) return state;
        return err;
    };
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 1_048_576);
    defer allocator.free(data);

    var iter = std.mem.splitScalar(u8, data, '\n');
    while (iter.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \r\t");
        if (line.len == 0) continue;
        if (line[0] == '#') continue;

        var parts = std.mem.splitScalar(u8, line, '|');
        const kind = parts.next() orelse continue;

        if (std.mem.eql(u8, kind, "BEACON")) {
            const id = try dupField(allocator, parts.next() orelse return StateError.InvalidStateLine);
            const listener = try dupField(allocator, parts.next() orelse return StateError.InvalidStateLine);
            const jitter_str = parts.next() orelse return StateError.InvalidStateLine;
            const status = try dupField(allocator, parts.next() orelse return StateError.InvalidStateLine);
            const last_callback_str = parts.next() orelse return StateError.InvalidStateLine;
            if (parts.next() != null) return StateError.InvalidStateLine;

            const jitter = std.fmt.parseInt(u32, jitter_str, 10) catch return StateError.InvalidStateLine;
            const last_callback = std.fmt.parseInt(i64, last_callback_str, 10) catch return StateError.InvalidStateLine;

            try state.beacons.append(.{
                .id = id,
                .listener = listener,
                .jitter = jitter,
                .status = status,
                .last_callback = last_callback,
            });
        } else if (std.mem.eql(u8, kind, "COMMAND")) {
            const id_str = parts.next() orelse return StateError.InvalidStateLine;
            const beacon_id = try dupField(allocator, parts.next() orelse return StateError.InvalidStateLine);
            const command_text = try dupField(allocator, parts.next() orelse return StateError.InvalidStateLine);
            const status = try dupField(allocator, parts.next() orelse return StateError.InvalidStateLine);
            const created_at_str = parts.next() orelse return StateError.InvalidStateLine;
            const output = try dupField(allocator, parts.next() orelse "");
            if (parts.next() != null) return StateError.InvalidStateLine;

            const id = std.fmt.parseInt(u64, id_str, 10) catch return StateError.InvalidStateLine;
            const created_at = std.fmt.parseInt(i64, created_at_str, 10) catch return StateError.InvalidStateLine;

            if (id >= state.next_command_id) state.next_command_id = id + 1;

            try state.commands.append(.{
                .id = id,
                .beacon_id = beacon_id,
                .command = command_text,
                .status = status,
                .created_at = created_at,
                .output = output,
            });
        }
    }

    return state;
}

pub fn saveState(state: *const C2State, path: []const u8) !void {
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();

    var buffer: [4096]u8 = undefined;
    var writer = file.writer(&buffer);
    const io_writer = &writer.interface;

    try io_writer.print("# ZigHound C2 Simulation State v1\n", .{});
    for (state.beacons.items) |beacon| {
        try io_writer.print("BEACON|{s}|{s}|{d}|{s}|{d}\n", .{
            beacon.id,
            beacon.listener,
            beacon.jitter,
            beacon.status,
            beacon.last_callback,
        });
    }

    for (state.commands.items) |command| {
        try io_writer.print("COMMAND|{d}|{s}|{s}|{s}|{d}|{s}\n", .{
            command.id,
            command.beacon_id,
            command.command,
            command.status,
            command.created_at,
            command.output,
        });
    }

    try io_writer.flush();
}

pub fn registerBeacon(state: *C2State, listener: []const u8, jitter: u32) ![]const u8 {
    try validateField(listener);

    const id = try generateBeaconId(state.allocator);
    const listener_copy = try state.allocator.dupe(u8, listener);
    const status = try state.allocator.dupe(u8, "active");
    const now = std.time.timestamp() * 1000;

    try state.beacons.append(.{
        .id = id,
        .listener = listener_copy,
        .jitter = jitter,
        .status = status,
        .last_callback = now,
    });

    return id;
}

pub fn queueCommand(state: *C2State, beacon_id: []const u8, command: []const u8) !u64 {
    try validateField(beacon_id);
    try validateCommand(command);

    if (!beaconExists(state, beacon_id)) return StateError.BeaconNotFound;

    const command_id = state.next_command_id;
    state.next_command_id += 1;

    const beacon_copy = try state.allocator.dupe(u8, beacon_id);
    const command_copy = try state.allocator.dupe(u8, command);
    const status = try state.allocator.dupe(u8, "queued");
    const output = try state.allocator.dupe(u8, "");

    try state.commands.append(.{
        .id = command_id,
        .beacon_id = beacon_copy,
        .command = command_copy,
        .status = status,
        .created_at = std.time.timestamp() * 1000,
        .output = output,
    });

    return command_id;
}

pub fn listBeacons(state: *const C2State) void {
    if (state.beacons.items.len == 0) {
        std.debug.print("[*] No simulated beacons registered\n", .{});
        return;
    }

    std.debug.print("[*] Simulated Beacons:\n", .{});
    std.debug.print("┌─────────────────────┬────────────────────────────┬────────┬────────────┐\n", .{});
    std.debug.print("│ ID                  │ Listener                   │ Jitter │ Status     │\n", .{});
    std.debug.print("├─────────────────────┼────────────────────────────┼────────┼────────────┤\n", .{});

    for (state.beacons.items) |beacon| {
        std.debug.print("│ {s:<19} │ {s:<26} │ {d:<6} │ {s:<10} │\n", .{
            beacon.id,
            beacon.listener,
            beacon.jitter,
            beacon.status,
        });
    }

    std.debug.print("└─────────────────────┴────────────────────────────┴────────┴────────────┘\n", .{});
}

pub fn listCommands(state: *const C2State) void {
    if (state.commands.items.len == 0) {
        std.debug.print("[*] No queued commands\n", .{});
        return;
    }

    std.debug.print("[*] Simulated Commands:\n", .{});
    std.debug.print("┌────────┬─────────────────────┬──────────────────────────┬──────────┐\n", .{});
    std.debug.print("│ ID     │ Beacon ID            │ Command                  │ Status   │\n", .{});
    std.debug.print("├────────┼─────────────────────┼──────────────────────────┼──────────┤\n", .{});

    for (state.commands.items) |command| {
        std.debug.print("│ {d:<6} │ {s:<19} │ {s:<24} │ {s:<8} │\n", .{
            command.id,
            command.beacon_id,
            command.command,
            command.status,
        });
    }

    std.debug.print("└────────┴─────────────────────┴──────────────────────────┴──────────┘\n", .{});
}

fn beaconExists(state: *const C2State, beacon_id: []const u8) bool {
    for (state.beacons.items) |beacon| {
        if (std.mem.eql(u8, beacon.id, beacon_id)) return true;
    }
    return false;
}

fn generateBeaconId(allocator: std.mem.Allocator) ![]const u8 {
    var bytes: [6]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    const value = std.mem.bytesToValue(u48, &bytes);
    return std.fmt.allocPrint(allocator, "sim-{x}", .{value});
}

fn validateField(value: []const u8) !void {
    if (value.len == 0) return StateError.InvalidField;
    if (std.mem.indexOfScalar(u8, value, '|') != null) return StateError.InvalidField;
    if (std.mem.indexOfScalar(u8, value, '\n') != null) return StateError.InvalidField;
}

fn validateCommand(value: []const u8) !void {
    try validateField(value);
}

fn dupField(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    return allocator.dupe(u8, std.mem.trim(u8, value, " \r\t"));
}
