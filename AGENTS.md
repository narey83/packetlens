# AGENTS.md

Guidance for AI agents and contributors working in this repo. Keep this file in
sync when you change the architecture.

## What this is

**Packetlens** is a **defensive** DDoS forensics tool. It reads packet captures and flags attack
indicators. It never generates attack traffic and is not an inline mitigator.
Keep all work within that defensive scope.

## Layout

- `ddos_analyzer.py` — the detection engine **and** the CLI. Importable API:
  `Analyzer`, `Thresholds`, `Finding`, `analyze_file()`, `REFLECTORS`,
  `BASE_SEVERITY`, `SEVERITY_RANK`.
- `webapp.py` — Flask web UI. It **imports** the engine; it must not
  re‑implement detection. The front‑end is one self‑contained HTML string
  (`PAGE`) with no external assets (CSP‑free, works offline).
  - The responsive workspace includes severity filtering and a client-side
    JSON export of the current report. Preserve file-selection keyboard access,
    mobile layouts, and safe text rendering when changing the UI.
  - `build_report` keeps legacy `top_*` arrays and also returns complete
    `sources`, `destinations`, `protocols`, and `udp_ports` inventories. The UI
    renders these with searchable, sortable, paginated local data grids; do not
    silently truncate the complete arrays.
  - `POST /api/analyze` returns plain JSON, **or** streams NDJSON progress lines
    (`{"type":"progress"|"result"|"error", …}`) when the form has `stream=1`
    (the UI uses this for the live progress bar; `_analyze_stream` estimates
    percent from `reader.f.tell()/filesize`). `POST /api/demo` is JSON only.
    Keep the non‑stream JSON path working — curl/automation depend on it.
  - `POST /api/report.pdf` accepts a `build_report` JSON object and returns a
    locally rendered PDF. The UI uses it for the PDF report download.
- `pdf_report.py` — ReportLab PDF renderer. It includes the capture summary,
  findings, mitigation playbooks, every vendor's configuration, inline
  verification and rollback, plus the leading 20 inventory values. Keep the
  full inventories in the dashboard and JSON rather than producing unbounded
  PDFs.
- `requirements.txt` — `scapy`, `flask`, `reportlab`.

There is no git repo, no test suite, and no build step. Validate by running.

## Environment

- Python 3.14 in `.venv` (created without pip; pip was bootstrapped via
  `ensurepip`). Always invoke as `.venv/bin/python`.
- `scapy` and `flask` are installed in the venv. `playwright` (+ Chromium) is
  installed both in the venv and user‑globally for screenshots.

## How detection works

One **streaming pass** (`Analyzer.ingest` per packet, via `PcapReader` — never
`rdpcap`, to keep memory bounded). Per packet it updates:

- global counters (protocols, dst/src packets, udp ports),
- per‑window buckets for peak‑rate charting (`global_buckets`, `proto_buckets`),
- one `CategoryTracker` per attack category (`syn`, `synack`, `ack`, `rst`,
  `fin`, `udp`, `icmp`, `frag`, `dns_query`, `samesport`, `udp_port0`,
  `weird_proto`) and one per reflector service (`reflectors[name]`).

A `CategoryTracker` holds, keyed by victim: packet count, byte count, per‑window
buckets (for `peak()`), and a **bounded** set of sources (`SOURCE_TRACK_CAP`).

`Analyzer.findings()` runs two gates per category (`_gate`):

1. **rate** — `peak() >= threshold`.
2. **signature** — victim is the dominant target (`dst_share >= target_share`)
   and the category is a meaningful share of that victim's inbound
   (`vic_share >= sig_victim_share`), with `count >= min_sig_packets`.

Severity = `_escalate(BASE_SEVERITY[attack], peak_pps, threshold)` — the higher of
the signature base and the rate‑derived severity. `method` records which gate(s)
fired. Findings are de‑duplicated by `(attack, victim, reflector service)`
keeping the highest severity, then sorted severity‑desc. Reflection retains one
finding per abused service so each source port gets a distinct FlowSpec rule.

**Distribution gating (false‑positive control).** Generic volumetric floods pass
`require_distributed=True` to `_gate`, so their *signature* path needs many
distinct sources — this is what stops heavy one‑directional benign traffic (a
download/stream from one host) from being flagged. Inherently‑malicious
signatures (reflection, SYN‑ACK reflection, `sport==dport`, UDP port 0,
non‑standard proto) don't require distribution; reflection instead requires
`min_reflectors` distinct sources. Each finding carries a `confidence`
(`high`/`medium`): distributed → high; single/few‑source (even at high rate) →
medium; inherently‑malicious → high. `source_spread()` (distinct /16‑or‑/32
networks, derived from the stored source set) feeds the high/medium decision.

**FlowSpec output.** `flowspec_for_finding()` turns supported findings into a
structured match plus ExaBGP and portable/Junos-style renderings. Keep rules
victim-scoped and narrow them using observed ports where possible. Return a
note-only `supported=False` result when FlowSpec cannot express the detector
safely; in particular, never emit a stateless ACK discard rule. Reflection
route names include the service because one victim may have multiple reflector
findings. UDP port 0 uses FlowSpec's `port` component so either source or
destination port 0 is matched.

`flowspec.vendors` adds ExaBGP, Junos IPv4 set syntax, and IOS XR IPv4
class-map/PBR definitions, with per-format support status, notes, references
and verification commands. The CLI selects text dialect via
`--flowspec-format`; the UI selects and copies the active dialect. Preserve the
legacy `exabgp`/`portable` fields. Vendor IPv6 templates are unsupported; IOS XR
multi-flag AND matches are unsupported rather than broadened to ANY. IOS XR
either-port matching uses two classes, preserving destination/protocol in each.
Do not attach one policy per finding over an existing aggregate policy.
Verification is inline with each selected vendor in the UI and CLI; never
append a global Cisco block to other vendors' output. The top-level JSON
`flowspec_verify` field remains for legacy API compatibility only.
Each supported rule also carries `risk`, `monitoring`, `response_checklist`,
and vendor-specific `withdraw` fields. The PDF incident-report export is
server-rendered locally and includes every vendor format. Keep packet-size, ICMP-type,
protocol-number and dominant-port matches evidence-derived; never invent a
narrowing field that was not observed in the capture.

### Key invariants / gotchas

- **Out‑of‑order timestamps**: buckets are anchored to the *first packet seen*,
  but duration and offsets use the true `min_time`/`max_time`. Use
  `abs_offset(idx)` (clamped ≥ 0) for any reported offset. Do not reintroduce
  first‑packet‑as‑start assumptions.
- **One‑way captures**: real sample captures are anonymized to a single victim
  (e.g. `10.10.10.10`) and are ~100% incoming. `target_share` defaults high
  (0.8) so benign two‑way traffic (~50/50) doesn't trip signatures.
- **Mutually exclusive UDP classification** in `ingest`: a UDP packet goes to
  exactly one of `udp_port0` / reflector / `dns_query` / generic `udp`, so one
  vector isn't reported twice. Preserve this when editing the UDP branch.
- **PSH‑ACK is data**, excluded from the ACK‑flood tracker — don't count it.
- **Fragment continuations** (IPv4 proto 6/17/1 or an IPv6 Fragment extension
  header with no L4 header) must not be flagged as "Non‑standard IP Protocol";
  they belong to the fragmentation detector.
- **Sparse timelines**: never materialize every empty bucket before
  downsampling. Capture timestamps can be extremely far apart, so downsample
  from the occupied bucket indices to keep report memory bounded.

## Adding a new detector

1. Add a `CategoryTracker` in `Analyzer.__init__` and populate it in `ingest`.
2. Add the attack name to `BASE_SEVERITY` and `MITIGATIONS`.
3. Emit findings with `self._mk(...)` from a `_detect_*` method and call it in
   `findings()`. Use `_gate(..., require_vic_share=False)` for signatures that are
   inherently malicious regardless of proportion (reflection, crafted, port 0).
4. If the finding needs new UI/JSON fields, add them to `Finding`, to
   `webapp.build_report`, and render them in `PAGE`'s `renderFindings`.

Every attack in `BASE_SEVERITY` must also have both a concise `MITIGATIONS`
entry and an ordered `MITIGATION_TECHNIQUES` playbook. Keep techniques
defensive, vendor-neutral, scoped to the finding, and explicit about controls
that could cause collateral damage.

## Validate your changes

```bash
.venv/bin/python -m py_compile ddos_analyzer.py webapp.py pdf_report.py

# Real corpus (if present): every capture should produce a finding
for f in ~/Downloads/captures/*.pcap*; do
  echo "### $(basename "$f")"
  .venv/bin/python ddos_analyzer.py "$f" --no-color --max-packets 40000 2>/dev/null \
    | grep -E '^\[' | sed 's/  Victim.*//'
done

# Regression: benign two-way traffic must yield NO findings.
# JS syntax check for the web UI (extract <script> and run):
node --check <(python3 -c "import re;print(re.search(r'<script>(.*?)</script>',open('webapp.py').read(),re.S).group(1))")
```

Screenshot the dashboard with Playwright against a running `webapp.py`
(`p.chromium.launch(headless=True, args=["--no-sandbox","--disable-dev-shm-usage"])`),
`set_input_files("#file", path)`, click `#analyzeBtn`, wait for `.finding`.

## Conventions

- Match existing style: dataclasses, small pure helpers, generous comments on
  *why*. No new third‑party deps without a strong reason.
- Never send capture data off‑machine. The web UI stays dependency‑free and
  localhost‑bound by default.
- When you change detection behavior, update `README.md` (detection table /
  limitations) and this file.
