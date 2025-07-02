# vaulty
`vaulty` is a command-line password manager for UNIX-like systems (Linux, macOS), focused on security and simplicity. It encrypts credentials with AEAD using strong key derivation, ensures sensitive data remains in memory only as long as necessary, and guarantees plaintext never hits the disk during storage.

## Features
- **Memory protection** — passwords stored in memory protected from swapping and core dumps (via OpenSSL secure heap)
- **Strong encryption** — AEAD with per-record keys derived via PBKDF2 (HMAC-SHA512, 210k iterations, 64-byte salt)
- **Lightweight storage** — encrypted credentials persisted in a local SQLite database
- **Minimal dependencies** — OpenSSL, SQLite, spdlog, clip

## Usage
```bash
vaulty add --domain example.com      # Add credentials for example.com
vaulty get --domain example.com      # Retrieve credentials for example.com
vaulty list                          # List stored credentials
vaulty remove --domain example.com   # Remove stored credentials
vaulty --help                        # View additional features
```

## Installation
```bash
git clone https://github.com/mdvsec/vaulty.git
cd vaulty
mkdir build && cd build

# Default: Release build without debug logging
cmake ..
make

# Debug build with additional logging enabled
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

## Requirements
- Linux or macOS (UNIX-like systems)
- C++17 compatible compiler
- OpenSSL
- SQLite3
- [spdlog](https://github.com/gabime/spdlog) (for logging)
- [clip](https://github.com/dacap/clip) (for clipboard support)

## Potential improvements
- Implement password generator with customizable policies
- Add FIDO authentication support
