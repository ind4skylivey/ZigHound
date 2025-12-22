// Copyright (c) 2025 il1v3y. All Rights Reserved.
// Unauthorized copying or use of this file is strictly prohibited.
// Proprietary and confidential.

const std = @import("std");
const crypto = std.crypto;
const aead = crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const KeySize = aead.key_length;
pub const NonceSize = aead.nonce_length;
pub const TagSize = aead.tag_length;

/// Encrypts plaintext using XChaCha20-Poly1305.
/// Returns a newly allocated slice containing [nonce][ciphertext][tag].
pub fn encrypt(allocator: std.mem.Allocator, key: [KeySize]u8, plaintext: []const u8) ![]u8 {
    var nonce: [NonceSize]u8 = undefined;
    crypto.random.bytes(&nonce);

    const ciphertext_len = plaintext.len;
    const total_len = NonceSize + ciphertext_len + TagSize;
    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);

    // Copy nonce to the start
    @memcpy(out[0..NonceSize], &nonce);

    var tag: [TagSize]u8 = undefined;
    aead.encrypt(out[NonceSize .. NonceSize + ciphertext_len], &tag, plaintext, "", nonce, key);

    // Copy tag to the end
    @memcpy(out[NonceSize + ciphertext_len ..], &tag);

    return out;
}

/// Decrypts a buffer containing [nonce][ciphertext][tag].
/// Returns newly allocated plaintext.
pub fn decrypt(allocator: std.mem.Allocator, key: [KeySize]u8, input: []const u8) ![]u8 {
    if (input.len < NonceSize + TagSize) return error.InputTooShort;

    const nonce = input[0..NonceSize].*;
    const tag = input[input.len - TagSize ..][0..TagSize].*;
    const ciphertext = input[NonceSize .. input.len - TagSize];

    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);

    try aead.decrypt(plaintext, ciphertext, tag, "", nonce, key);

    return plaintext;
}

test "encryption/decryption roundtrip" {
    const allocator = std.testing.allocator;
    var key: [KeySize]u8 = undefined;
    crypto.random.bytes(&key);

    const original = "Hello ZigHound! Real C2 Protocol Test.";
    const encrypted = try encrypt(allocator, key, original);
    defer allocator.free(encrypted);

    const decrypted = try decrypt(allocator, key, encrypted);
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, original, decrypted);
}
