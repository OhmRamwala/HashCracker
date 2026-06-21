# HashCracker

`HashCracker` is a Linux-only, multi-threaded password hash cracking tool built in modern C++ with OpenSSL, Boost, and memory-mapped dictionary scanning.

It is designed primarily for Kali Linux and other modern Linux distributions, with a focus on:

- Fast dictionary attacks with `mmap`
- Deterministic brute-force partitioning across CPU threads
- Rule-based mutations
- Batch cracking in a single run with `--hash-file`
- Resumable brute-force and dictionary sessions with checkpoint files
- Clean terminal progress output with hash-type detection feedback

## Supported Hashes

- `md5`
- `sha1`
- `sha256`
- `sha512`
- `sha3-256`
- `sha3-512`

Auto-detection is available for unique digest lengths. For ambiguous lengths such as `sha256` vs `sha3-256`, use `--type`.

## Primary Platform

This project is optimized for Linux. The main target environment is:

- Kali Linux
- Ubuntu / Debian
- Arch Linux
- Fedora

The dictionary path uses POSIX `mmap`, `madvise`, and Linux-friendly atomic rename semantics for checkpoint files.

## Build

### Install dependencies

Kali, Debian, Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential cmake libssl-dev libboost-program-options-dev
```

Fedora:

```bash
sudo dnf install -y gcc-c++ make cmake openssl-devel boost-program-options
```

Arch:

```bash
sudo pacman -S --needed gcc make cmake openssl boost
```

If `cmake` says it cannot find `Ninja`, pull the latest changes from this repo first. The presets now use `Unix Makefiles`, so Ninja is no longer required.

### Quick install

```bash
./install.sh
```

This installs dependencies, builds the release binary, and symlinks it to `~/.local/bin/hashcracker`.

### Manual build

```bash
cmake --preset release
cmake --build build/release
```

### Run tests

```bash
cmake --preset debug
cmake --build build/debug
ctest --test-dir build/debug --output-on-failure
```

## Usage

### Dictionary attack

```bash
hashcracker \
  --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
  --wordlist wordlists/10k-most-common.txt
```

### Rule-based attack

```bash
hashcracker \
  --hash ed9d3d832af899035363a69fd53cd3be8f71501c \
  --wordlist wordlists/10k-most-common.txt \
  --rules
```

### Brute force

```bash
hashcracker \
  --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
  --bruteforce \
  --charset lower \
  --max-length 8
```

### SHA3 example

```bash
hashcracker \
  --hash c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484 \
  --type sha3-256 \
  --wordlist wordlists/10k-most-common.txt
```

### Batch cracking

```bash
hashcracker \
  --hash-file tests/data/batch_hashes_sha256.txt \
  --type sha256 \
  --wordlist tests/data/small_wordlist.txt
```

### Resumable brute force

Start a session with checkpointing:

```bash
hashcracker \
  --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
  --bruteforce \
  --charset lower,digits \
  --max-length 8 \
  --checkpoint-file .hashcracker.chk
```

Resume it later:

```bash
hashcracker \
  --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
  --bruteforce \
  --charset lower,digits \
  --max-length 8 \
  --checkpoint-file .hashcracker.chk \
  --resume
```

### Resumable dictionary attack

```bash
hashcracker \
  --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
  --wordlist wordlists/10k-most-common.txt \
  --checkpoint-file .hashcracker-dict.chk
```

Resume:

```bash
hashcracker \
  --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
  --wordlist wordlists/10k-most-common.txt \
  --checkpoint-file .hashcracker-dict.chk \
  --resume
```

## Checkpoint Notes

- Checkpointing is supported for brute-force and dictionary attacks
- Rule mode is intentionally not resumable yet
- Batch mode currently does not support `--resume`
- Checkpoints are written atomically via temp file + rename
- Completed runs remove their checkpoint file automatically

## Project Layout

```text
src/
  attack/      candidate generation strategies
  core/        engine and concepts
  display/     terminal progress UI
  hash/        OpenSSL EVP hashers and detection
  io/          mmap and checkpoint file helpers
  rules/       mutation rules
  threading/   thread pool and shared state

tests/         unit and integration tests
learn/         learning notes, architecture, and implementation docs
wordlists/     bundled sample wordlists
```

## GitHub Upload Checklist

Before pushing:

```bash
cmake --preset debug
cmake --build build/debug
ctest --test-dir build/debug --output-on-failure
git status
```

Recommended first push:

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```

## Learn

The `learn/` directory documents the theory and architecture behind the tool:

- `learn/00-OVERVIEW.md`
- `learn/01-CONCEPTS.md`
- `learn/02-ARCHITECTURE.md`
- `learn/03-IMPLEMENTATION.md`

## License

MIT

This tool is developed for authorized security testing, academic research, and CTF competitions. Unauthorized use against systems you do not own is illegal.
