# ZigHound Quick Start Guide

## 1) Install Zig

```bash
zig version
```

If Zig is not installed, download it from ziglang.org or use your package manager.

## 2) Build

```bash
zig build
./zig-out/bin/zighound --help
```

## 3) Basic Scanning

```bash
./zig-out/bin/zighound scan --target 192.168.1.0/24
```

### Stealth scan with custom ports

```bash
./zig-out/bin/zighound scan \
  --target 10.0.0.1 \
  --ports 22,80,443,3389 \
  --stealth \
  --jitter 100
```

### Export results

```bash
./zig-out/bin/zighound scan \
  --target 192.168.1.0/24 \
  --output results.json

./zig-out/bin/zighound scan \
  --target 192.168.1.0/24 \
  --output results.csv \
  --format csv
```

## 4) C2 Simulator (Local Only)

```bash
# Create or update simulation state
./zig-out/bin/zighound c2 listen --port 443

# Register a simulated beacon
./zig-out/bin/zighound c2 beacon --listener 127.0.0.1:443 --jitter 5

# Queue a simulated command
./zig-out/bin/zighound c2 exec --beacon-id sim-1a2b3c --cmd "whoami"

# List beacons and queued commands
./zig-out/bin/zighound c2 list --commands
```

## 5) Evasion Simulation

```bash
./zig-out/bin/zighound evasion simulate
./zig-out/bin/zighound evasion simulate --seed 1337
```

## 6) File Structure

```
zighound/
├── src/
│   ├── main.zig
│   ├── scanner.zig
│   ├── c2.zig
│   └── evasion.zig
├── build.zig
├── README.md
└── QUICKSTART.md
```

## 7) Common Tasks

```bash
# Clean rebuild
rm -rf zig-cache zig-out
zig build

# Run tests
zig build test

# Format code
zig fmt src/*.zig
```

## Troubleshooting

### "zig: command not found"
- Add Zig to PATH or reinstall.

### "Permission denied" when running
```bash
chmod +x zig-out/bin/zighound
```

## Security Reminder

Only scan or test systems with explicit authorization.

---

For more details, see README.md.
