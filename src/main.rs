//! gpass — lightweight, secure terminal password generator.
//!
//! Spec (v1):
//!   gpass -12 -134 -y -keyOne
//!   - first numeric switch  = length  (default 13), e.g. `-12` = 12 chars
//!   - second numeric switch = charset (default 1234), digits combine:
//!       1 = lowercase, 2 = UPPERCASE, 3 = digits, 4 = special
//!     e.g. `-134` = lower + digits + special
//!   - `-y` / `--save`     = append `{name: password}` to ~/Documents/psess.txt
//!   - `-keyOne` / `--name`= entry name; prompted interactively if `-y` without a name
//!   - no `-y`             = print once to stdout, save nothing
//!
//! Extension point: implement the [`OutputSink`] trait to add new outputs
//! (keychain, vault, JSON, QR, ...) without touching generator/CLI code.

use rand::Rng;
use std::collections::HashSet;
use std::env;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Charset pools
// ---------------------------------------------------------------------------

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
// Printable ASCII specials except space (32 chars). Excludes nothing that
// breaks the `name: password` line format except newline itself.
const SPECIAL: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

const DEFAULT_LEN: usize = 13;
const DEFAULT_CHARSET: &str = "1234";
const MAX_LEN: usize = 512;
const MAX_ATTEMPTS: u32 = 1000;

/// Build the character pool for a charset code like "134".
/// Returns (pool, required_classes) where required_classes is one entry
/// per selected digit so we can guarantee coverage.
fn build_pool(code: &str) -> Result<(Vec<char>, Vec<&'static str>), String> {
    if code.is_empty() {
        return Err("charset code is empty".to_string());
    }
    let mut seen = HashSet::new();
    let mut pool: Vec<char> = Vec::new();
    let mut classes: Vec<&'static str> = Vec::new();
    for ch in code.chars() {
        if !matches!(ch, '1' | '2' | '3' | '4') {
            return Err(format!(
                "invalid charset digit '{ch}' in \"{code}\" — use only 1,2,3,4 (1=lower 2=upper 3=digits 4=special)"
            ));
        }
        if !seen.insert(ch) {
            continue; // dedup: "113" == "13"
        }
        let (set, label): (&str, &'static str) = match ch {
            '1' => (LOWER, "lowercase"),
            '2' => (UPPER, "UPPERCASE"),
            '3' => (DIGITS, "digits"),
            _ => (SPECIAL, "special"),
        };
        pool.extend(set.chars());
        classes.push(label);
    }
    if pool.is_empty() {
        return Err("charset pool is empty".to_string());
    }
    Ok((pool, classes))
}

/// Generate one candidate password with the OS-seeded CSPRNG
/// (`rand::rng()` — ThreadRng seeded from OS entropy via getrandom).
/// Uniform index sampling via `random_range` — no modulo bias.
fn generate_once(pool: &[char], len: usize) -> Zeroizing<String> {
    let mut rng = rand::rng();
    let mut pw = Zeroizing::new(String::with_capacity(len));
    for _ in 0..len {
        let idx = rng.random_range(0..pool.len());
        pw.push(pool[idx]);
    }
    pw
}

/// Check every selected class appears at least once (only meaningful
/// when len >= number of classes; otherwise best-effort skip).
fn covers_all(pw: &str, code: &str) -> bool {
    if pw.len() < code.len() {
        return true; // can't cover 4 classes in 2 chars — accept entropy
    }
    for d in code.chars() {
        let set = match d {
            '1' => LOWER,
            '2' => UPPER,
            '3' => DIGITS,
            _ => SPECIAL,
        };
        if !pw.chars().any(|c| set.contains(c)) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

struct Config {
    length: usize,
    charset_code: String,
    save: bool,
    name: Option<String>,
}

fn print_help() {
    println!(
        "\
gpass — secure terminal password generator

USAGE:
  gpass [-LENGTH] [-CHARSET] [-y] [-NAME]
  gpass [--len N] [--charset CODE] [--save] [--name NAME]

SWITCHES (shorthand):
  -12       length of password (default {DEFAULT_LEN}). First numeric switch.
  -134      charset code (default {DEFAULT_CHARSET}). Second numeric switch.
            digits combine: 1=lowercase 2=UPPERCASE 3=digits 4=special
            e.g. -13 = lower+digits, -1234 = all
  -y        save: append \"name: password\" to ~/Documents/psess.txt (mode 600).
            Without -y the password is printed once and saved nowhere.
  -keyOne   entry name for -y. If -y is given without a name you are prompted.

EXPLICIT FLAGS (unambiguous, recommended in scripts):
  --len 12 --charset 134 --save --name keyOne

EXAMPLES:
  gpass                        # 13 chars, all sets, print once
  gpass -16                    # 16 chars, all sets, print once
  gpass -12 -134               # 12 chars, lower+digits+special, print once
  gpass -12 -134 -y -keyOne    # same + append as keyOne
  gpass -12 -134 -y            # same, but prompt for the name

SECURITY (v1):
  CSPRNG via OS (OsRng/getrandom). File created with mode 600.
  Passwords checked against saved file, regenerated on collision.
  v1 stores plaintext — encryption / keychain is the planned next sink.
  See OutputSink trait in source to add new outputs."
    );
}

fn parse_args(raw: &[String]) -> Result<Config, String> {
    let mut length_opt: Option<usize> = None;
    let mut charset_opt: Option<String> = None;
    let mut save = false;
    let mut name_opt: Option<String> = None;
    let mut i = 0;
    while i < raw.len() {
        let a = raw[i].as_str();
        if a == "-y" || a == "--save" {
            save = true;
        } else if a == "-h" || a == "--help" || a == "help" {
            print_help();
            std::process::exit(0);
        } else if a == "--len" {
            i += 1;
            let v = raw.get(i).ok_or("--len needs a value")?;
            length_opt = Some(parse_len(v)?);
        } else if let Some(v) = a.strip_prefix("--len=") {
            length_opt = Some(parse_len(v)?);
        } else if a == "--charset" {
            i += 1;
            let v = raw.get(i).ok_or("--charset needs a value")?;
            validate_charset(v)?;
            charset_opt = Some(canonical_charset(v));
        } else if let Some(v) = a.strip_prefix("--charset=") {
            validate_charset(v)?;
            charset_opt = Some(canonical_charset(v));
        } else if a == "--name" {
            i += 1;
            let v = raw.get(i).ok_or("--name needs a value")?;
            ensure_name_free(&name_opt)?;
            validate_name(v)?;
            name_opt = Some(v.clone());
        } else if let Some(v) = a.strip_prefix("--name=") {
            ensure_name_free(&name_opt)?;
            validate_name(v)?;
            name_opt = Some(v.to_string());
        } else if let Some(rest) = a.strip_prefix('-') {
            if rest.is_empty() {
                return Err("lone '-' is not valid. See --help".to_string());
            }
            if rest.chars().all(|c| c.is_ascii_digit()) {
                // Positional rule: first numeric = length, second = charset.
                if length_opt.is_none() {
                    length_opt = Some(parse_len(rest)?);
                } else if charset_opt.is_none() {
                    validate_charset(rest)?;
                    charset_opt = Some(canonical_charset(rest));
                } else {
                    return Err(format!(
                        "too many numeric switches (\"-{rest}\"): expected at most -LENGTH -CHARSET"
                    ));
                }
            } else {
                // Name switch: -keyOne
                ensure_name_free(&name_opt)?;
                let nm = rest.to_string();
                validate_name(&nm)?;
                name_opt = Some(nm);
            }
        } else {
            // Bare token (no dash): accept as name for easiness.
            ensure_name_free(&name_opt)?;
            validate_name(a)?;
            name_opt = Some(a.to_string());
        }
        i += 1;
    }
    Ok(Config {
        length: length_opt.unwrap_or(DEFAULT_LEN),
        charset_code: charset_opt.unwrap_or_else(|| DEFAULT_CHARSET.to_string()),
        save,
        name: name_opt,
    })
}

fn parse_len(s: &str) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("invalid length \"{s}\" — expected a number like -12"))?;
    if n == 0 || n > MAX_LEN {
        return Err(format!("length must be 1..={MAX_LEN}, got {n}"));
    }
    Ok(n)
}

fn validate_charset(code: &str) -> Result<(), String> {
    build_pool(code).map(|_| ())
}

fn canonical_charset(code: &str) -> String {
    // dedup preserving first-seen order
    let mut seen = HashSet::new();
    code.chars().filter(|c| seen.insert(*c)).collect()
}

fn ensure_name_free(existing: &Option<String>) -> Result<(), String> {
    if existing.is_some() {
        return Err("duplicate name switch — provide one -NAME only".to_string());
    }
    Ok(())
}

fn validate_name(nm: &str) -> Result<(), String> {
    if nm.is_empty() {
        return Err("name must not be empty".to_string());
    }
    if nm.len() > 128 {
        return Err("name too long (max 128 chars)".to_string());
    }
    if nm.contains(['\n', '\r', ':']) {
        // ':' is our file separator — forbid to keep parsing unambiguous.
        return Err("name must not contain newline or ':'".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Storage (v1 file sink) + OutputSink extension point
// ---------------------------------------------------------------------------

/// Extension point for future outputs (keychain, vault, JSON, ...).
/// v1 ships [`FileSink`]; add new sinks without touching generator/CLI.
trait OutputSink {
    fn load_passwords(&self) -> io::Result<HashSet<String>>;
    fn store(&self, name: &str, password: &str) -> io::Result<PathBuf>;
}

struct FileSink {
    path: PathBuf,
}

impl FileSink {
    fn default_path() -> Result<PathBuf, String> {
        let home = env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
        Ok(PathBuf::from(home).join("Documents").join("psess.txt"))
    }
}

impl OutputSink for FileSink {
    /// Read all previously stored passwords (password column only) so the
    /// generator can retry on collision. Tolerant of `{k: v}` / `k: v` /
    /// JSON-line shapes.
    fn load_passwords(&self) -> io::Result<HashSet<String>> {
        let mut set = HashSet::new();
        let Ok(file) = std::fs::File::open(&self.path) else {
            return Ok(set); // no file yet — nothing to collide with
        };
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            // password = text after first ':'; strip braces/quotes/spaces
            let pw = match t.find(':') {
                Some(idx) => &t[idx + 1..],
                None => continue,
            };
            let pw = pw
                .trim()
                .trim_start_matches('{')
                .trim()
                .trim_matches(['"', '\''])
                .trim_end_matches('}')
                .trim()
                .trim_matches(['"', '\''])
                .trim();
            // trailing '}' or ',' from `{k: v}` / JSON lines
            let pw = pw.trim_end_matches([',', '}']).trim();
            if !pw.is_empty() {
                set.insert(pw.to_string());
            }
        }
        Ok(set)
    }

    /// Append `name: password` atomically-ish (single write + fsync),
    /// tighten permissions to 600. Resources close via Drop.
    fn store(&self, name: &str, password: &str) -> io::Result<PathBuf> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&self.path)?;
            writeln!(f, "{name}: {password}")?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            writeln!(f, "{name}: {password}")?;
            f.sync_all()?;
        }
        // Tighten pre-existing files that may have loose perms.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&self.path, perm);
        }
        Ok(self.path.clone())
    }
}

fn prompt_name() -> Result<String, String> {
    eprint!("Name for password: ");
    io::stderr()
        .flush()
        .map_err(|e| format!("prompt failed: {e}"))?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("read failed: {e}"))?;
    let nm = line.trim().to_string();
    if nm.is_empty() {
        return Err("no name given — aborting save".to_string());
    }
    validate_name(&nm)?;
    Ok(nm)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn run() -> Result<(), String> {
    let raw: Vec<String> = env::args().skip(1).collect();
    let cfg = parse_args(&raw)?;
    let (pool, _classes) = build_pool(&cfg.charset_code)?;

    // Uniqueness oracle = saved file (only when saving; stdout-only mode
    // is stateless by design and relies on CSPRNG entropy).
    let sink = FileSink {
        path: FileSink::default_path()?,
    };
    let existing: HashSet<String> = if cfg.save {
        sink
            .load_passwords()
            .map_err(|e| format!("cannot read store: {e}"))?
    } else {
        HashSet::new()
    };

    let mut password: Zeroizing<String> = Zeroizing::new(String::new());
    let mut collided = 0;
    for _ in 0..MAX_ATTEMPTS {
        let cand = generate_once(&pool, cfg.length);
        if !covers_all(&cand as &str, &cfg.charset_code) {
            continue;
        }
        if cfg.save && existing.contains(&cand as &str) {
            collided += 1;
            continue;
        }
        password = cand;
        break;
    }
    if password.is_empty() {
        return Err(format!(
            "could not generate a unique password after {MAX_ATTEMPTS} attempts ({collided} collisions)"
        ));
    }

    if cfg.save {
        let name = match cfg.name {
            Some(n) => n,
            None => prompt_name()?,
        };
        // Re-check name uniqueness? Spec v1: names may repeat (history),
        // passwords must not. Keep append-only per spec.
        let path = sink
            .store(&name, &password as &str)
            .map_err(|e| format!("cannot write store: {e}"))?;
        // Password on stdout (pipeable), status on stderr.
        println!("{}", &password as &str);
        let _ = io::stdout().flush();
        eprintln!("saved as \"{name}\" → {}", path.display());
    } else {
        println!("{}", &password as &str);
    }
    // `password` (Zeroizing) + file handles drop here — explicit cleanup.
    drop(password);
    Ok(())
}

fn main() {
    if let Err(msg) = run() {
        eprintln!("gpass: {msg}");
        eprintln!("Try: gpass --help");
        std::process::exit(2);
    }
}

// Read any leftover stdin? No — deliberate: never consume stdin except for
// the -y name prompt, so piped usage stays predictable.

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn positional_length_then_charset() {
        let c = parse_args(&args(&["-12", "-134"])).unwrap();
        assert_eq!(c.length, 12);
        assert_eq!(c.charset_code, "134");
        assert!(!c.save);
    }

    #[test]
    fn defaults() {
        let c = parse_args(&args(&[])).unwrap();
        assert_eq!(c.length, 13);
        assert_eq!(c.charset_code, "1234");
    }

    #[test]
    fn save_with_name() {
        let c = parse_args(&args(&["-12", "-134", "-y", "-keyOne"])).unwrap();
        assert!(c.save);
        assert_eq!(c.name.as_deref(), Some("keyOne"));
    }

    #[test]
    fn pool_covers() {
        let (pool, _) = build_pool("1234").unwrap();
        assert!(pool.len() > 90);
        let pw = generate_once(&pool, 16);
        assert_eq!(pw.len(), 16);
    }

    #[test]
    fn rejects_bad_charset() {
        assert!(build_pool("5").is_err());
        assert!(build_pool("").is_err());
    }

    #[test]
    fn name_with_newline_or_colon_rejected_everywhere() {
        assert!(parse_args(&args(&["--name", "a:b"])).is_err());
        assert!(parse_args(&args(&["--name=a:b"])).is_err());
        assert!(parse_args(&args(&["--name", "a\nb"])).is_err());
        assert!(parse_args(&args(&["--name=a\nb"])).is_err());
        assert!(parse_args(&args(&["-a:b"])).is_err());
        assert!(parse_args(&args(&["-y", "--name", "ok"])).is_ok());
    }
}
