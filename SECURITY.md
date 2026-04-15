# Security Design

## Threat model

`safe-extract` defends against malicious archives used as an attack vector. It is designed for environments where archive files come from untrusted sources: user uploads, CI/CD artifact downloads, malware triage, or third-party integrations.

### Attacks mitigated

**Path traversal (Zip Slip)**
Archive entries can contain paths like `../../etc/passwd` or `C:\Windows\evil.exe`. Standard extractors resolve these relative to the working directory, allowing files to be written outside the intended output folder. `safe-extract` resolves every destination path and rejects any entry that escapes the target directory.

**Symlink and hardlink abuse**
An archive can contain a symlink pointing to a directory outside the extraction target. A subsequent entry extracted into that "directory" lands outside the sandbox. Symlinks are blocked by default.

**Archive bombs**
Highly compressed archives (the classic example is `42.zip`: ~42 KB compressed, ~4.5 PB uncompressed) can exhaust disk space. `safe-extract` enforces limits on per-file size, total extracted size, and compression ratio — checked against actual bytes written, not metadata (which can be forged).

**Forged ZIP metadata**
The ZIP central directory records uncompressed file sizes. An attacker can set `file_size = 0` to bypass pre-flight size checks. `safe-extract` counts bytes during streaming via an `on_chunk` callback and aborts mid-write if limits are exceeded.

**Parsing differentials**
The ZIP format allows duplicate entry names. Different tools resolve the ambiguity differently — one extractor may write file A while another writes file B for the same name. Archives with duplicate entries are rejected before extraction begins.

**Malicious file types**
Executable files embedded in archives are a common delivery mechanism. `safe-extract` enforces an extension block list. Blocked files are either renamed (`.exe` → `.exe.blocked`) or hard-blocked depending on policy.

**Filename spoofing**
- *Double extension*: `document.pdf.exe` looks like a PDF to casual inspection. Detected and blocked.
- *RTLO (Right-to-Left Override)*: Unicode bidirectional control characters can make `evil.exe` display as `exe.live` on screen. Detected and blocked.

### Attacks NOT mitigated

- **Content-based malware**: `safe-extract` does not scan file contents. Use ClamAV, YARA, or similar tools alongside it.
- **Post-extraction execution**: once files are on disk, `safe-extract` has no control over what runs them.
- **TOCTOU between validation and write**: Python does not expose `O_NOFOLLOW`-style syscalls portably. A process replacing the target directory with a symlink between validation and write is a known limitation. Mitigate by using a dedicated, isolated output directory.
- **Password-protected archives**: encrypted entries are blocked with a clear error message.

## Architecture

Extraction happens in three phases:

1. **Structural validation** — the archive is opened once and inspected for anomalies (duplicate names, malformed headers) before any entry is touched.
2. **Per-entry validation** — each entry is validated against policy (path, symlinks, filename, extension) before extraction begins.
3. **Streaming extraction** — files are written in 64 KB chunks with resource limits enforced incrementally. If a limit is hit mid-write, the partial file is deleted.

The archive is opened exactly once per extraction job and kept open for the full session, eliminating redundant I/O and reducing the TOCTOU window.

## Reporting vulnerabilities

Open an issue at https://github.com/Mhacker1020/safe-extract/issues or contact via [hivesecurity.gitlab.io](https://hivesecurity.gitlab.io).
