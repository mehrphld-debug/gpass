# gpass

A lightweight, secure terminal password generator for macOS and Linux.

```bash
gpass -12 -134 -y -keyOne
```

That single command generates a 12-character password from lowercase letters,
digits, and special characters, prints it once, and appends it to your password
file under the name `keyOne`. Without `-y`, nothing is ever written to disk —
the password is shown once and forgotten.

## Why gpass was built

Existing options were either online generators (your secrets leave the
machine), heavyweight password managers (daemons, accounts, sync you didn't
ask for), or ad-hoc shell one-liners (`$RANDOM`, `openssl rand -base64`)
with biased sampling, no character-set control, and no safe place to keep
results. gpass is the middle ground: a tiny offline tool that does one job —
generate unique, custom passwords in the terminal — and exits, closing
everything it opened.

Design goals:

- **Offline by construction.** No network code exists in the project. There
  is nothing to leak to because the program cannot phone home.
- **Do the job and exit.** No daemon, no background service, no open handles.
  Every run generates, optionally stores, wipes secrets from memory, and
  terminates. File handles close via `Drop`; the password buffer is a
  `Zeroizing<String>` that is wiped on drop.
- **Install as an application, not a script.** A single compiled binary on
  your `PATH` — no interpreter version to babysit, no virtualenv, no
  half-remembered `python3 ~/scripts/gen.py` invocation.
- **Open to the future.** Storage, output, and generation are separated so
  new sinks (encrypted vault, OS keychain, JSON, QR) plug in without
  touching the CLI or the generator.

## Features

- Custom length (default 13) and combinable character sets:
  `1` = lowercase, `2` = UPPERCASE, `3` = digits, `4` = special.
- Guaranteed coverage: every selected set appears at least once
  (when the length allows it).
- Uniqueness: generated passwords are checked against your saved file and
  regenerated on collision.
- Append-only history file (`~/Documents/psess.txt`), created with mode
  `600`, never overwritten.
- Interactive name prompt when `-y` is given without a name.
- Unambiguous long flags (`--len`, `--charset`, `--save`, `--name`) for
  scripts, alongside the terse shorthand for daily use.

## Usage

```
gpass [-LENGTH] [-CHARSET] [-y] [-NAME]
gpass [--len N] [--charset CODE] [--save] [--name NAME]
```

| Switch | Meaning | Default |
| --- | --- | --- |
| `-12` | Password length. The **first** numeric switch. | `13` |
| `-134` | Character sets (digits combine: `1` lower, `2` upper, `3` digits, `4` special). The **second** numeric switch. | `1234` (all) |
| `-y` / `--save` | Append `name  =>  password` to `~/Documents/psess.txt`. | off — print once, save nothing |
| `-keyOne` / `--name` | Entry name for `-y`. You are prompted if omitted. | none |
| `-h` / `--help` | Show help and exit. | — |

Examples:

```bash
gpass                        # 13 chars, all sets, print once
gpass -16                    # 16 chars, all sets, print once
gpass -12 -134               # 12 chars, lower + digits + special, print once
gpass -12 -134 -y -keyOne    # same, and save it under "keyOne"
gpass -12 -134 -y            # same, but ask me for the name
gpass --len 20 --charset 12 --save --name github
```

Notes:

- Because `-12` (length) and `-134` (charset) look alike, they are
  positional: the first numeric switch is always the length, the second is
  always the charset. A single numeric switch (`gpass -16`) is the length.
  In scripts, prefer the explicit `--len` / `--charset` form.
- Names may not contain newlines, `:` or `=>` (the file separators) — this is
  enforced on every input path, including `--name` and the prompt.
- Length is capped at 512 characters; names at 128.
- The store is append-only history: saving the same name twice keeps both
  lines. Passwords, never names, are deduplicated.

## Installation

Prerequisites: a Rust toolchain (`rustc` + `cargo`).

### macOS (Apple Silicon / Intel, tested on macOS 27)

```bash
# 1. Install Rust (Homebrew)
brew install rust

# 2. Build
cd /path/to/gpass
cargo build --release

# 3. Install the binary on your PATH
cp target/release/gpass /opt/homebrew/bin/gpass   # Apple Silicon
# cp target/release/gpass /usr/local/bin/gpass    # Intel Macs

# 4. Verify
gpass --help
gpass -12 -134
```

Alternatively, if you use `rustup`:

```bash
cargo install --path .
# binary lands in ~/.cargo/bin/gpass — make sure it is on your PATH
```

### Arch Linux

```bash
# 1. Install Rust
sudo pacman -S rust

# 2. Build
cd /path/to/gpass
cargo build --release

# 3. Install the binary on your PATH
sudo cp target/release/gpass /usr/local/bin/gpass
# or, without sudo: mkdir -p ~/.local/bin && cp target/release/gpass ~/.local/bin/

# 4. Verify
gpass --help
gpass -12 -134
```

### Uninstall

macOS:

```bash
rm /opt/homebrew/bin/gpass   # Apple Silicon
# rm /usr/local/bin/gpass    # Intel Macs
```

Linux:

```bash
sudo rm /usr/local/bin/gpass
# rm ~/.local/bin/gpass      # if you installed without sudo
```

Your saved passwords in `~/Documents/psess.txt` are left untouched.

## Architecture

Three layers, one direction of dependency: **CLI → generator → sink**.

```
args / stdin ──▶ parse_args ──▶ Config { length, charset, save, name }
                                      │
                                      ▼
                          build_pool + generate_once (CSPRNG)
                          covers_all + collision check
                                      │
                     ┌────────────────┴────────────────┐
                     ▼                                 ▼
              stdout (print once)            OutputSink::store
                                             (v1: FileSink → psess.txt)
```

**CLI (`parse_args`).** A small hand-written parser, because the shorthand
grammar (`-12 -134 -y -keyOne`) is not POSIX-conventional and `clap`-style
parsers would fight it. Rules: `-y`/`--save` toggles saving; all-digit
switches fill length-then-charset positionally; anything else after `-` (or
a bare token) is the entry name. Long flags (`--len 12`, `--charset=134`,
`--name`, `--save`, `--help`) exist for scripts. All user input is
validated before use: length range, charset digits, name characters. There
are no `unwrap`/`expect` calls on any production path — bad input exits
with code 2 and a message, never a panic.

**Generator (`build_pool`, `generate_once`, `covers_all`).** The charset
code is deduplicated and expanded into a pool (26 + 26 + 10 + 32 special
characters for the full set). Indices are sampled uniformly with
`random_range` — no modulo bias. Candidates that miss a selected character
class are discarded, and (when saving) candidates already present in the
store are discarded, up to 1000 attempts.

**Storage (`OutputSink` trait, `FileSink`).** The extension point of the
whole program:

```rust
trait OutputSink {
    fn load_passwords(&self) -> io::Result<HashSet<String>>;
    fn store(&self, name: &str, password: &str) -> io::Result<PathBuf>;
}
```

v1 ships one implementation, `FileSink`, which reads the password column of
the store (tolerant of `k: v` and `{k: v}` shapes) and appends
`name  =>  password` lines with a single write plus `fsync`. Adding a keychain
or encrypted-vault sink means implementing these two methods — the CLI and
generator never change.

## Why Rust, and why it is fast

Python and Rust were compared before building, against the brief's own
criteria — better performance, plus safety and install easiness on macOS
and Arch. Rust won on all three:

- **Performance.** Measured ~1.5 ms per run (50 runs in 0.076 s) with a
  ~500 KB static binary. Python would pay ~40 ms of interpreter startup on
  every invocation plus GC — for a tool you fire dozens of times a day,
  that latency is the whole user experience.
- **Install safety.** One binary, no runtime. No interpreter version drift,
  no `pipx`/`venv` layer, identical artifact on macOS 27 (arm64) and Arch.
- **Security ergonomics.** No garbage collector means secrets can actually
  be wiped (`zeroize`); the type system and the absence of `unwrap` on
  input paths mean malformed arguments are errors, not crashes or
  undefined behavior.

Dependencies are exactly two focused crates: `rand` (RNG) and `zeroize`
(memory wiping). No CLI framework, no async runtime, no serialization
library — nothing that doesn't serve the single job.

## Why you can trust it

Threat model, stated plainly:

- **What it protects against:** weak/biased passwords, accidental
  overwrites of your history, other users on the same machine reading your
  file (mode `600`, tightened on every save), malformed names corrupting
  the log format (rejected on all input paths, regression-tested).
- **What it does not do:** it never touches the network (no such code
  exists — verify with a glance at `Cargo.toml`), never executes shell
  commands, never deserializes anything, never reads anything except its
  own store file. The password itself is never passed as an argument, so
  it never appears in `ps` output.
- **Memory:** the password lives in a `Zeroizing<String>` and is wiped on
  drop; file handles close deterministically.
- **Randomness:** OS-seeded CSPRNG (`rand`'s thread RNG, seeded and
  reseeded from OS entropy via `getrandom`), uniform sampling, class
  coverage, collision retry against the store.
- **Verifiable:** the whole program is one ~500-line file with unit tests
  (`cargo test`), including a regression test for the store-format
  injection guard. There is no obfuscation possible at this size — read it
  in ten minutes.

Known limitation, by decision: **v1 stores passwords in plaintext.**
Permissions (`600`) keep other users out, but not disk theft, backups, or
malware running as you. This was a conscious staging choice — ship the
generator and the safe file handling first, add encryption next (see
roadmap). If that tradeoff is wrong for you, use stdout-only mode until
the encrypted sink lands.

## Roadmap

- **Encrypted sink** (highest priority): age- or keychain-backed
  `OutputSink` so the store is ciphertext at rest. The trait boundary is
  already in place; the CLI won't change.
- **OS keychain integration** (macOS Keychain / Linux Secret Service) as
  an alternative sink.
- **Duplicate-name policy**: currently history is append-only; options are
  warn-on-reuse or explicit `--force`.
- **Output formats**: JSON lines for scripting, QR rendering for phone
  transfer.
- **Shell completions** for zsh/fish/bash.

## For developers

```bash
cargo test                 # run the unit tests
cargo build                # debug build
cargo build --release      # optimized binary at target/release/gpass
```

Project layout:

```
gpass/
├── Cargo.toml                  # package "gpass", deps: rand, zeroize
├── Cargo.lock
├── README.md
├── password-generator-prompt.md  # original brief (historical)
└── src/
    └── main.rs                 # CLI + generator + FileSink + tests
```

Conventions: keep `main.rs` readable as a single file until a second sink
forces a split; no new dependencies without a paragraph of justification;
every new input path gets validation plus a test; production code stays
`unwrap`-free.

## The password file

`~/Documents/psess.txt`, one entry per line:

```
keyOne  =>  hqa?ekc;/>60
github  =>  Z{d0xtQMZ}^{]
```

Old `key: value` lines from earlier versions keep working — they are still
recognized when checking for duplicates.

Back it up like anything precious — and look forward to the day it holds
ciphertext instead.
