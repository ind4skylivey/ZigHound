const std = @import("std");

/// A compile-time XOR obfuscator.
/// This ensures sensitive strings are never stored as plain text in the binary.
pub fn ObfuscatedString(comptime plaintext: []const u8, comptime key: u8) type {
    return struct {
        // The encrypted bytes are generated at compile time.
        const encrypted_data: [plaintext.len]u8 = encrypt();

        fn encrypt() [plaintext.len]u8 {
            var buffer: [plaintext.len]u8 = undefined;
            for (plaintext, 0..) |char, i| {
                buffer[i] = char ^ key;
            }
            return buffer;
        }

        /// Decrypts the string at runtime.
        /// Caller owns the returned slice and must free it.
        pub fn decrypt(allocator: std.mem.Allocator) ![]u8 {
            const result = try allocator.alloc(u8, plaintext.len);
            for (encrypted_data, 0..) |byte, i| {
                result[i] = byte ^ key;
            }
            return result;
        }
    };
}

test "obfuscation" {
    const allocator = std.testing.allocator;
    // '0xAA' is the key.
    const Secret = ObfuscatedString("ThisIsHidden", 0xAA);
    
    // In the binary, "ThisIsHidden" does not exist. Only the XOR'd bytes exist.
    const revealed = try Secret.decrypt(allocator);
    defer allocator.free(revealed);

    try std.testing.expectEqualSlices(u8, "ThisIsHidden", revealed);
}
