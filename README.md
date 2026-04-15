# safe-extract

Security-focused archive extraction with policy enforcement. Prevents Zip Slip, archive bombs, symlink abuse, and malicious file types — before writing anything to disk.

```
$ safe-extract malware_sample.zip --out ./analysis
Extracting malware_sample.zip → ./analysis

  Decision   File                    Reason
 ──────────────────────────────────────────────────────────────
  BLOCKED    ../../evil.exe          Path traversal detected
  RENAMED    dropper.ps1             renamed to dropper.ps1.blocked
  BLOCKED    payload.pdf.exe         Double extension spoofing detected

  1 allowed  1 renamed  2 blocked
```

## Why

Standard archive tools trust the archive. `safe-extract` doesn't.

| Attack | 7-Zip / WinRAR | safe-extract |
|--------|---------------|--------------|
| Zip Slip (`../../evil.exe`) | Extracts to parent dir | Blocked |
| Absolute path (`/etc/passwd`) | Extracts to root | Blocked |
| Archive bomb (42.zip) | Fills disk | Aborted |
| Symlink pointing outside dir | Follows link | Blocked |
| `document.pdf.exe` | Extracts as-is | Blocked |
| RTLO filename spoofing | Extracts as-is | Blocked |
| Forged size metadata | Trusts metadata | Counts real bytes |
| Duplicate entry names | Unpredictable | Aborted |

## Install

```bash
pip install safe-extract
```

## Usage

### Basic extraction

```bash
safe-extract archive.zip
safe-extract archive.zip --out ./output_dir
```

### Dry run — analyze without extracting

```bash
safe-extract archive.zip --dry-run --verbose
```

### JSON output — for automation and CI/CD

```bash
safe-extract archive.zip --format json
safe-extract archive.zip --format json --log audit.json
```

### Custom limits

```bash
safe-extract archive.zip --max-size 50MB
safe-extract archive.zip --block-ext .exe,.ps1,.lnk
```

### Policy config file

```bash
safe-extract archive.zip --config policy.json
```

### All options

```
safe-extract <archive> [options]

  --out, -o PATH        Output directory (default: ./extracted)
  --dry-run             Analyze without extracting
  --config, -c FILE     Policy config file (JSON)
  --verbose, -v         Show all entries including allowed ones
  --format [table|json] Output format (default: table)
  --log FILE            Save JSON audit log to file
  --max-size SIZE       Max file size, e.g. 100MB, 500KB, 1GB
  --block-ext EXTS      Comma-separated extensions to block
  --version             Show version
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All entries allowed |
| `1` | One or more entries blocked or renamed |
| `2` | Extraction aborted (archive bomb, malformed archive) |

Use exit codes in CI/CD pipelines to fail builds on suspicious archives.

## Policy config

Create a `policy.json` to enforce consistent rules across your team or pipeline:

```json
{
  "max_file_size": 104857600,
  "max_total_size": 524288000,
  "max_files": 1000,
  "max_compression_ratio": 100,
  "block_extensions": [".exe", ".dll", ".ps1", ".js", ".lnk", ".vbs", ".bat", ".cmd"],
  "rename_blocked": true,
  "allow_symlinks": false,
  "allow_overwrite": false,
  "scan_hashes": true,
  "block_rtlo": true,
  "block_double_extension": true,
  "block_ambiguous_archives": true
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `max_file_size` | 100 MB | Max uncompressed size per file |
| `max_total_size` | 500 MB | Max total extracted size |
| `max_files` | 1000 | Max number of files |
| `max_compression_ratio` | 100× | Abort if compression ratio exceeds this |
| `block_extensions` | See below | File extensions to block |
| `rename_blocked` | `true` | Rename blocked files (`.exe` → `.exe.blocked`) instead of hard-blocking |
| `allow_symlinks` | `false` | Allow symlinks and hardlinks |
| `allow_overwrite` | `false` | Allow overwriting existing files |
| `scan_hashes` | `true` | Compute SHA-256 for each extracted file |
| `block_rtlo` | `true` | Block Unicode Right-to-Left Override filename tricks |
| `block_double_extension` | `true` | Block `document.pdf.exe` style spoofing |
| `block_ambiguous_archives` | `true` | Abort if archive has duplicate entry names |

**Default blocked extensions:**
`.exe .dll .sys .drv .ps1 .psm1 .psd1 .bat .cmd .com .vbs .vbe .js .jse .wsf .wsh .lnk .pif .scr .msi .msp .msc .hta .cpl`

## Use as a library

```python
from pathlib import Path
from safe_extract import SafeExtractor, ExtractionPolicy

policy = ExtractionPolicy(
    max_file_size=50 * 1024 * 1024,  # 50 MB
    block_extensions=[".exe", ".ps1"],
    rename_blocked=True,
)

extractor = SafeExtractor(policy)
report = extractor.extract(Path("archive.zip"), Path("./output"))

print(f"Allowed: {report.allowed_count}")
print(f"Blocked: {report.blocked_count}")
print(report.to_json())
```

### Integration with gate

`safe-extract` is designed to work alongside [gate](https://github.com/Mhacker1020/gate), a supply chain security scanner. Use `gate` to validate packages from registries, and `safe-extract` to safely unpack archive files before inspection:

```python
from safe_extract import SafeExtractor, ExtractionPolicy

# Safely unpack a downloaded .whl or .tar.gz before analyzing contents
policy = ExtractionPolicy(rename_blocked=False)  # hard block in CI
report = SafeExtractor(policy).extract(wheel_path, staging_dir)

if report.aborted or report.blocked_count > 0:
    raise SecurityError(f"Unsafe archive: {report.abort_reason or 'blocked entries'}")
```

## CI/CD example

```yaml
# GitHub Actions
- name: Extract and validate artifact
  run: |
    pip install safe-extract
    safe-extract artifact.zip --out ./artifact --format json --log audit.json
    # Exits with code 1 if any entries were blocked
```

## What it does NOT do

- Replace antivirus or EDR
- Prevent execution of extracted files
- Scan file contents for malware (use alongside ClamAV or YARA for that)

## Threat model

Detailed threat model, architecture, and security design decisions are documented in [SECURITY.md](SECURITY.md).

## License

MIT
