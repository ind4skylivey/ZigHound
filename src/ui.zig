const std = @import("std");

pub const Color = struct {
    pub const reset = "\x1b[0m";
    pub const bold = "\x1b[1m";
    pub const dim = "\x1b[2m";
    pub const red = "\x1b[31m";
    pub const green = "\x1b[32m";
    pub const yellow = "\x1b[33m";
    pub const blue = "\x1b[34m";
    pub const magenta = "\x1b[35m";
    pub const cyan = "\x1b[36m";
};

pub const Ui = struct {
    color: bool = true,

    pub fn banner(self: Ui) void {
        if (self.color) std.debug.print("{s}{s}", .{ Color.magenta, Color.bold });
        const lines = [_][]const u8{
            " _______ _________ _______           _______           _        ______  ",
            "/ ___   )\\__   __/(  ____ \\|\\     /|(  ___  )|\\     /|( (    /|(  __  \\ ",
            "\\/   )  |   ) (   | (    \\/| )   ( || (   ) || )   ( ||  \\  ( || (  \\  )",
            "    /   )   | |   | |      | (___) || |   | || |   | ||   \\ | || |   ) |",
            "   /   /    | |   | | ____ |  ___  || |   | || |   | || (\\ \\) || |   | |",
            "  /   /     | |   | | \\_  )| (   ) || |   | || |   | || | \\   || |   ) |",
            " /   (_/\\___) (___| (___) || )   ( || (___) || (___) || )  \\  || (__/  )",
            "(_______/\\_______/(_______)|/     \\|(_______)(_______)|/    )_)(______/ ",
        };

        for (lines) |line| {
            self.printCentered(line);
        }
        if (self.color) std.debug.print("{s}", .{Color.reset});
    }

    pub fn tagline(self: Ui, text: []const u8) void {
        if (self.color) std.debug.print("{s}", .{Color.cyan});
        self.printCentered(text);
        if (self.color) std.debug.print("{s}", .{Color.reset});
    }

    pub fn section(self: Ui, name: []const u8) void {
        if (self.color) std.debug.print("{s}{s}", .{ Color.blue, Color.bold });
        std.debug.print("\n==[ {s} ]==\n", .{name});
        if (self.color) std.debug.print("{s}", .{Color.reset});
    }

    pub fn kv(self: Ui, key: []const u8, value: []const u8) void {
        if (self.color) std.debug.print("{s}", .{Color.dim});
        std.debug.print("- {s}: ", .{key});
        if (self.color) std.debug.print("{s}", .{Color.reset});
        std.debug.print("{s}\n", .{value});
    }

    pub fn kvFormat(self: Ui, key: []const u8, comptime fmt: []const u8, args: anytype) void {
        if (self.color) std.debug.print("{s}", .{Color.dim});
        std.debug.print("- {s}: ", .{key});
        if (self.color) std.debug.print("{s}", .{Color.reset});
        std.debug.print(fmt, args);
        std.debug.print("\n", .{});
    }

    pub fn info(self: Ui, comptime fmt: []const u8, args: anytype) void {
        if (self.color) std.debug.print("{s}", .{Color.cyan});
        std.debug.print(fmt, args);
        if (self.color) std.debug.print("{s}", .{Color.reset});
    }

    pub fn success(self: Ui, comptime fmt: []const u8, args: anytype) void {
        if (self.color) std.debug.print("{s}", .{Color.green});
        std.debug.print(fmt, args);
        if (self.color) std.debug.print("{s}", .{Color.reset});
    }

    pub fn warn(self: Ui, comptime fmt: []const u8, args: anytype) void {
        if (self.color) std.debug.print("{s}", .{Color.yellow});
        std.debug.print(fmt, args);
        if (self.color) std.debug.print("{s}", .{Color.reset});
    }

    fn printCentered(self: Ui, line: []const u8) void {
        _ = self;
        const width = terminalWidth();
        const line_len = line.len;
        if (line_len >= width) {
            std.debug.print("{s}\n", .{line});
            return;
        }
        const pad = (width - line_len) / 2;
        printSpaces(pad);
        std.debug.print("{s}\n", .{line});
    }

    fn terminalWidth() usize {
        const allocator = std.heap.page_allocator;
        const cols = std.process.getEnvVarOwned(allocator, "COLUMNS") catch return 80;
        defer allocator.free(cols);
        const parsed = std.fmt.parseInt(usize, cols, 10) catch return 80;
        if (parsed < 40) return 40;
        return parsed;
    }

    fn printSpaces(count: usize) void {
        if (count == 0) return;
        var buffer: [64]u8 = undefined;
        @memset(&buffer, ' ');
        var remaining = count;
        while (remaining > 0) {
            const chunk = if (remaining > buffer.len) buffer.len else remaining;
            std.debug.print("{s}", .{buffer[0..chunk]});
            remaining -= chunk;
        }
    }
};
