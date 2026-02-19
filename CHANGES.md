# Changelog

All notable changes to **Lenoos Net Audit** (`lenoos-net-audit.sh`) are documented here.

This project follows [Semantic Versioning](https://semver.org/) (SemVer):
- **MAJOR** — incompatible API / CLI changes
- **MINOR** — new features, backward-compatible
- **PATCH** — bug fixes, backward-compatible

---

## [1.0.2] — 2025-06-24

### Added
- **Rebranded to Lenoos Net Audit** — app renamed from "net-audit" / "Ultimate OSI Forensic & Performance Suite" to **Lenoos Net Audit** (`lenoos-net-audit.sh`). All headers, banners, PDF reports, Prometheus metrics, export filenames, stream output, and Dockerfile updated.
- **`pdf.conf` branding support** — optional configuration file for PDF report customization. Supports: `PDF_LOGO` (PNG/SVG), `PDF_BRAND`, `PDF_AUTHOR`, `PDF_FILENAME`, `PDF_WEBSITE`, `PDF_EMAIL`, `PDF_PHONE`, `PDF_CONTACT_PERSON`, `PDF_TEST_ENV`, `PDF_LAB_DETAILS`, `PDF_REF_BASE_URL`. Searched in `./pdf.conf`, `<script_dir>/pdf.conf`, `~/.config/lenoos/pdf.conf`.
- **QR code on PDF cover page** — generates SVG QR code from `PDF_REF_BASE_URL` + filename using local `qrencode` or api.qrserver.com fallback.
- **Default `exports/` directory** — all export/stream output files now default to an `exports/` subdirectory (auto-created). Custom paths via `-n` still override.
- **Sample `pdf.conf`** — documented config template included in the repository.

### Changed
- **Prometheus metric prefix** — renamed from `osi_*` to `lenoos_*` (e.g., `lenoos_audit_info`, `lenoos_dns_ok`). Update your Grafana dashboards accordingly.
- **Export filenames** — default prefix changed from `osi-audit-` to `lenoos-audit-`, stream files from `osi-stream-` to `lenoos-stream-`.
- **Temp file prefixes** — changed from `osi-` to `lenoos-` for all temp files.
- **Dockerfile** — updated paths to `/opt/lenoos-net-audit/`, copies `pdf.conf`, creates `exports/` directory.
- **Renamed `VersionHistory.md`** → `CHANGES.md`.

---

## [1.0.1] — 2025-02-19

### Added
- **Custom export path (`-n <path>`)** — specify a custom file path and name for export output (use with `-e`). Auto-appends format extension if missing; creates parent directories automatically.
- **Semantic versioning** — migrated from internal build number (v128) to SemVer (v1.0.1).
- **CHANGES.md** — added this changelog following SemVer conventions.

### Fixed
- **PDF subshell bug** — `_pdf_cap()` used a pipe (`| tee`) which ran modules in a subshell, losing all `RES_*` values. Fixed by switching to process substitution (`> >(tee file) 2>&1`).
- **MTR pipeline subshell** — `run_mtr_audit()` used `mtr | while` which lost `RES_MTR_LOSS` in a subshell. Fixed with `while ... done < <(mtr ...)`.
- **Stream capture pipeline** — `stream_capture()` used `"$@" | tee` which lost variables. Fixed with process substitution.
- **Parallel mode RES_* loss** — background `&` subshells discarded all `RES_*` arrays. Fixed with serialization to temp files and reload after `wait`. PDF mode now forces sequential execution.
- **PDF table CSS** — Chrome headless squished 12-column tables. Fixed with `white-space: nowrap`, 8pt font, `max-width`/`overflow` rules.

### Changed
- **Conclusion matrix** — rewritten from fixed 6 columns to fully dynamic; only shows columns for enabled modules using a `_cols` array with `HEADER:width:flag` format.
- **PDF export** — expanded to capture full console output per section (ANSI-to-HTML converter, per-target sections, updated TOC, dark terminal CSS theme).
- **README.md** — fully synchronized with source code; documents all 28 flags, correct line count, PDF multi-backend support, and all examples.

---

## [1.0.0] — 2026-02-18

> Initial public release under semantic versioning. Corresponds to internal build v128.

### Features
- **20+ specialized modules** covering all 7 OSI layers in a single Bash script.
- **Identity & Setup**
  - `-i` — Public IP discovery (IPv4 & IPv6)
  - `-j` — Auto-install dependencies (apt / apk)
  - `-4` / `-6` — Force IPv4-only or IPv6-only mode
  - `-u` — Enable UDP protocol for applicable tests
- **DNS Module**
  - `-d` — A/AAAA records, hijack detection, resolver analysis
  - `-D` — DoH (DNS-over-HTTPS) and DoT (DNS-over-TLS) connectivity and latency
- **Routing & Geo**
  - `-r` — MTR hop-by-hop route trace with loss/latency stats and bar graphs
  - `-g` — IP geolocation and ASN lookup
- **TLS / SSL**
  - `-c` — Full certificate chain validation, expiry, OCSP, CT logs
  - `-s` — SNI probing, ALPN negotiation, cipher suite, TLS version details
- **Censorship Detection**
  - `-t` — Deep Packet Inspection fingerprinting (TCP RST, HTTP injection, fragmentation)
  - `-b` — Censorship bypass technique detection
- **Port Scanning**
  - `-p <ports>` — Targeted TCP/UDP port scan with service names
  - `-P` — Full 65535 TCP SYN + UDP + OS/service detection
- **Security & Pentesting**
  - `-O` — OWASP-style penetration test (17 categories)
  - `-V` — Vulnerability check (nmap NSE + online CVE lookup)
  - `-B` — Data breach and leak detection (5-phase analysis)
  - `-S` — Sensitive data deep scan (JWT, XSS, CSRF, PII, localStorage)
  - `-M <model[:url[:path]]>` — AI pentest via Ollama LLM (CPU-only, local or remote)
- **Performance & Simulation**
  - `-T <N[:L[:M]]>` — Stress / load test with percentile analysis and grading
  - `-F <A[:D[:W]]>` — Brute force simulation (credential spray, lockout, CAPTCHA, WAF)
  - `-X <W[:C[:S]]>` — DDoS resilience simulation (multi-vector waves, recovery test)
  - `-W <cores>` — Parallel worker dispatch for multi-target audits
- **Reporting**
  - `-a` — Risk advisory with conclusion matrix
  - `-A` — Prioritised remediation action plan
  - `-e <fmt>` — Export to JSON, CSV, HTML, XML, YAML, or PDF
  - `-o <fmt>` — Real-time structured streaming (JSON, YAML, HTML, XML, text)
  - `-E <port>` — Prometheus metrics exporter (`/metrics` endpoint)
  - `-w <sec>` — Watch mode (continuous re-audit with live metric updates)
- **PDF Report** — rich report with cover page, table of contents, page numbers, system info, per-target sections with captured console output. Supports wkhtmltopdf, Chrome/Chromium headless, and weasyprint backends.
- **Prometheus Integration** — 30+ gauge/counter/histogram metrics for Grafana dashboards.
- **Docker Support** — Dockerfile with all dependencies, Ollama, and Chromium pre-installed.
