#!/usr/bin/env python3

"""
Web UI for Packetlens.

A small, self-contained Flask app that wraps ddos_analyzer.Analyzer. Upload a
capture in the browser and get a dashboard: severity verdict, capture stats, a
protocol-split traffic-over-time chart, ranked findings with mitigations, and
top-talker tables. All analysis runs locally (scapy parses the PCAP server
side); nothing is sent anywhere. The page has no external dependencies, so it
works fully offline / air-gapped.

Requires:
    pip install scapy flask

Usage:
    python3 webapp.py                 # http://127.0.0.1:8000
    python3 webapp.py --port 5000
    python3 webapp.py --host 0.0.0.0  # exposes to the network (warns)
"""

import argparse
from io import BytesIO
import json
import os
import tempfile
import time

from flask import Flask, Response, jsonify, request, send_file, stream_with_context
from scapy.utils import PcapReader

from ddos_analyzer import (
    Analyzer,
    Thresholds,
    REFLECTORS,
    SEVERITY_RANK,
    FLOWSPEC_VERIFY_CMDS,
    analyze_file,
    flowspec_for_finding,
    rate,
    percentage,
)
from pdf_report import build_pdf_report

app = Flask(__name__)

# Reject uploads larger than this (bytes). Override with DDOS_MAX_UPLOAD_MB.
MAX_UPLOAD_MB = int(os.environ.get("DDOS_MAX_UPLOAD_MB", "1024"))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

# Threshold form fields the UI may send, mapped to Thresholds attributes.
THRESHOLD_FIELDS = (
    "window", "syn_pps", "udp_pps", "icmp_pps", "reflect_pps",
    "dns_query_pps", "distributed_sources",
)


# ---------------------------------------------------------------------------
# Report building (JSON consumed by the front-end)
# ---------------------------------------------------------------------------

def build_report(analyzer: Analyzer, filename: str, filesize: int) -> dict:
    findings = analyzer.findings()
    duration = analyzer.duration

    worst = None
    if findings:
        worst = max(findings, key=lambda f: SEVERITY_RANK[f.severity]).severity

    dst_total = sum(analyzer.dst_packets.values())

    destinations = [
        {"ip": ip, "packets": c,
         "pps": round(rate(c, duration), 1),
         "share": round(percentage(c, dst_total), 2)}
        for ip, c in analyzer.dst_packets.most_common()
    ]
    sources = [
        {"ip": ip, "packets": c, "pps": round(rate(c, duration), 1),
         "share": round(percentage(c, analyzer.total_packets), 2)}
        for ip, c in analyzer.src_packets.most_common()
    ]
    udp_ports = [
        {"port": port, "packets": c,
         "share": round(percentage(c, sum(analyzer.udp_ports.values())), 2),
         "reflector": REFLECTORS[port][0] if port in REFLECTORS else None}
        for port, c in analyzer.udp_ports.most_common()
    ]
    protocols = [
        {"protocol": protocol, "packets": count,
         "pps": round(rate(count, duration), 1),
         "share": round(percentage(count, analyzer.total_packets), 2)}
        for protocol, count in analyzer.protocol_counts.most_common()
    ]

    return {
        "file": {"name": filename, "size_bytes": filesize},
        "verdict": {"severity": worst, "count": len(findings)},
        "summary": {
            "packets": analyzer.total_packets,
            "bytes": analyzer.total_bytes,
            "duration_s": round(duration, 3),
            "avg_pps": round(rate(analyzer.total_packets, duration), 1),
            "peak_pps": round(analyzer.peak_overall_pps(), 1),
            "avg_mbps": round(
                (analyzer.total_bytes * 8) / duration / 1_000_000, 3),
            "window_s": analyzer.window,
            "timeline_bucket_s": analyzer.timeline_bucket_s,
            "protocol_counts": dict(analyzer.protocol_counts),
        },
        "findings": [
            {
                "attack": f.attack,
                "severity": f.severity,
                "victim": f.victim,
                "peak_pps": f.peak_pps,
                "avg_pps": f.avg_pps,
                "total_packets": f.total_packets,
                "unique_sources": f.unique_sources,
                "distributed": f.distributed,
                "method": f.method,
                "confidence": f.confidence,
                "evidence": f.evidence,
                "mitigation": f.mitigation,
                "mitigation_techniques": f.mitigation_techniques,
                "peak_offset_s": f.peak_offset_s,
                "mbps": f.mbps,
                "extra": f.extra,
                "flowspec": flowspec_for_finding(f, analyzer),
            }
            for f in findings
        ],
        "flowspec_verify": FLOWSPEC_VERIFY_CMDS,
        "timeline": analyzer.timeline(),
        # Keep the top-N fields for API clients written before full inventory
        # views were added; the dashboard consumes the complete arrays.
        "top_destinations": destinations[:10],
        "top_sources": sources[:10],
        "top_udp_ports": udp_ports[:10],
        "destinations": destinations,
        "sources": sources,
        "udp_ports": udp_ports,
        "protocols": protocols,
        "inventory_complete": True,
    }


def thresholds_from_form(form) -> Thresholds:
    t = Thresholds()
    for field in THRESHOLD_FIELDS:
        raw = form.get(field)
        if raw in (None, ""):
            continue
        try:
            value = float(raw)
        except ValueError:
            continue
        if field == "distributed_sources":
            if not value.is_integer():
                raise ValueError("distributed_sources must be a whole number")
            setattr(t, field, int(value))
        else:
            setattr(t, field, value)
    return t.validate()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    upload = request.files.get("pcap")
    if upload is None or upload.filename == "":
        return jsonify({"error": "No capture file was uploaded."}), 400

    try:
        thresholds = thresholds_from_form(request.form)
    except ValueError as exc:
        return jsonify({"error": f"Invalid threshold: {exc}"}), 400
    fname = upload.filename

    suffix = os.path.splitext(fname)[1] or ".pcap"
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    upload.save(tmp.name)
    tmp.close()
    size = os.path.getsize(tmp.name)

    # Streaming mode (used by the web UI): emit NDJSON progress lines while the
    # capture is parsed, then a final result line. Plain JSON otherwise, so the
    # API and curl stay backward compatible.
    if request.form.get("stream"):
        return Response(
            stream_with_context(
                _analyze_stream(tmp.name, thresholds, fname, size)),
            mimetype="application/x-ndjson")

    try:
        analyzer = analyze_file(tmp.name, thresholds)
        if analyzer.total_packets == 0:
            return jsonify({"error": "Capture contains no packets."}), 400
        return jsonify(build_report(analyzer, fname, size))
    except Exception as exc:  # noqa: BLE001 - surface parse errors to the UI
        return jsonify({"error": f"Failed to analyze capture: {exc}"}), 400
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def _analyze_stream(path, thresholds, fname, size):
    """Generator yielding NDJSON progress lines then a final result/error line.

    Progress percent is estimated from how far through the file scapy has read
    (bytes), so it works without knowing the packet count in advance.
    """
    def line(obj):
        return json.dumps(obj) + "\n"

    try:
        analyzer = Analyzer(thresholds)
        yield line({"type": "progress", "pct": 0, "packets": 0})
        last = time.time()
        with PcapReader(path) as reader:
            fh = getattr(reader, "f", None)
            for packet in reader:
                analyzer.ingest(packet)
                now = time.time()
                if now - last >= 0.15:
                    last = now
                    pct = None
                    try:
                        pos = fh.tell() if fh is not None else None
                        if pos is not None and size:
                            pct = min(99, int(pos / size * 100))
                    except (OSError, ValueError):
                        pct = None
                    yield line({"type": "progress", "pct": pct,
                                "packets": analyzer.total_packets})
        if analyzer.total_packets == 0:
            yield line({"type": "error",
                        "error": "Capture contains no packets."})
            return
        yield line({"type": "progress", "pct": 100,
                    "packets": analyzer.total_packets})
        report = build_report(analyzer, fname, size)
        yield line({"type": "result", "report": report})
    except Exception as exc:  # noqa: BLE001
        yield line({"type": "error", "error": f"Failed to analyze capture: {exc}"})
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


@app.route("/api/demo", methods=["POST"])
def api_demo():
    """Generate a synthetic multi-vector capture and analyze it, so the UI is
    explorable without a real PCAP on hand."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    try:
        tmp.close()
        _write_demo_capture(tmp.name)
        size = os.path.getsize(tmp.name)
        analyzer = analyze_file(tmp.name, Thresholds())
        report = build_report(analyzer, "demo_attack.pcap", size)
        report["file"]["demo"] = True
        return jsonify(report)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Failed to build demo: {exc}"}), 400
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


@app.route("/api/report.pdf", methods=["POST"])
def api_pdf_report():
    """Render the current local analysis JSON as a downloadable PDF."""
    report = request.get_json(silent=True)
    try:
        pdf = build_pdf_report(report)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001 - report errors are actionable in UI
        return jsonify({"error": f"Failed to build PDF report: {exc}"}), 500
    return send_file(
        BytesIO(pdf), mimetype="application/pdf", as_attachment=True,
        download_name="packetlens-incident-report.pdf",
    )


def _write_demo_capture(path: str) -> None:
    import random
    from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap

    pkts = []
    t = 1000.0

    def add(pkt, ts):
        pkt.time = ts
        pkts.append(pkt)

    for i in range(200):  # benign background
        add(IP(src=f"203.0.113.{i % 50}", dst="198.51.100.10")
            / TCP(sport=40000 + i, dport=443, flags="PA"), t + i * 0.01)
    for i in range(8000):  # spoofed SYN flood
        src = f"{random.randint(1,223)}.{random.randint(0,255)}." \
              f"{random.randint(0,255)}.{random.randint(1,254)}"
        add(IP(src=src, dst="198.51.100.20")
            / TCP(sport=random.randint(1024, 65535), dport=80, flags="S"),
            t + 5 + i * 0.0005)
    for i in range(6000):  # UDP flood
        add(IP(src=f"192.0.2.{i % 254 + 1}", dst="198.51.100.30")
            / UDP(sport=random.randint(1024, 65535), dport=53413) / (b"X" * 64),
            t + 12 + i * 0.0004)
    for i in range(4000):  # NTP reflection
        refl = f"45.{random.randint(0,255)}.{random.randint(0,255)}.{i % 254 + 1}"
        add(IP(src=refl, dst="198.51.100.40")
            / UDP(sport=123, dport=random.randint(1024, 65535)) / (b"N" * 468),
            t + 18 + i * 0.0006)
    for i in range(3000):  # ICMP flood
        add(IP(src=f"10.0.{i % 255}.{i % 254 + 1}", dst="198.51.100.50")
            / ICMP() / (b"P" * 56), t + 22 + i * 0.0007)
    for i in range(3000):  # DNS query flood
        add(IP(src=f"172.16.{i % 255}.{i % 254 + 1}", dst="198.51.100.60")
            / UDP(sport=random.randint(1024, 65535), dport=53)
            / DNS(rd=1, qd=DNSQR(qname="victim.example.")), t + 26 + i * 0.0005)

    random.shuffle(pkts)
    wrpcap(path, pkts)


# ---------------------------------------------------------------------------
# Front-end (single self-contained page, no external assets)
# ---------------------------------------------------------------------------

PAGE = r"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Packetlens | Defensive DDoS Forensics</title>
<style>
  :root{
    --bg:#0b0e14; --panel:#141922; --panel2:#1b212d; --line:#26303f;
    --text:#e6e9ef; --muted:#8b95a7; --accent:#5b8def;
    --tcp:#5b8def; --udp:#22c1a4; --icmp:#f2b134; --other:#8a8f98;
    --crit:#ff3b6b; --high:#ff7a45; --med:#ffb020; --low:#4aa3ff; --ok:#22c55e;
    --radius:14px;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
  a{color:var(--accent)}
  .wrap{max-width:1180px;margin:0 auto;padding:28px 20px 64px}
  header.top{display:flex;align-items:center;gap:14px;margin-bottom:6px}
  .logo{width:40px;height:40px;border-radius:11px;flex:0 0 auto;
    background:linear-gradient(135deg,#5b8def,#22c1a4);display:grid;place-items:center;
    font-size:20px;box-shadow:0 6px 18px rgba(35,110,230,.35)}
  h1{font-size:20px;margin:0;letter-spacing:.2px}
  .sub{color:var(--muted);font-size:13px;margin:2px 0 0}

  .card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius)}
  .pad{padding:20px}

  /* Upload panel */
  #upload{margin-top:22px}
  .drop{border:2px dashed var(--line);border-radius:var(--radius);padding:40px 20px;
    text-align:center;transition:.15s;cursor:pointer;background:var(--panel2)}
  .drop.drag{border-color:var(--accent);background:#18202c}
  .drop .big{font-size:16px;font-weight:600}
  .drop .hint{color:var(--muted);margin-top:6px}
  .chosen{margin-top:14px;color:var(--muted);font-size:13px}
  .chosen b{color:var(--text)}
  .row{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-top:18px}
  button{font:inherit;font-weight:600;border:0;border-radius:10px;padding:11px 18px;
    cursor:pointer;color:#fff;background:var(--accent);transition:.15s}
  button:hover{filter:brightness(1.08)}
  button:disabled{opacity:.55;cursor:default}
  button.ghost{background:transparent;border:1px solid var(--line);color:var(--text)}
  details.adv{margin-top:16px;border-top:1px solid var(--line);padding-top:14px}
  details.adv summary{cursor:pointer;color:var(--muted);font-weight:600;user-select:none}
  .grid-opts{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
    gap:12px;margin-top:14px}
  .grid-opts label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--muted)}
  .grid-opts input{background:var(--bg);border:1px solid var(--line);color:var(--text);
    border-radius:8px;padding:8px 10px;font:inherit}
  .err{margin-top:14px;color:#ffb4c2;background:#3a1420;border:1px solid #5a1f30;
    padding:10px 14px;border-radius:10px;display:none}

  /* Results */
  #results{display:none;margin-top:22px}
  .verdict{display:flex;align-items:center;gap:16px;padding:18px 20px;border-radius:var(--radius);
    border:1px solid var(--line);margin-bottom:18px}
  .verdict .dot{width:14px;height:14px;border-radius:50%}
  .verdict .vtext{font-size:17px;font-weight:700}
  .verdict .vsub{color:var(--muted);font-size:13px}
  .verdict .filemeta{margin-left:auto;color:var(--muted);font-size:12px;text-align:right}

  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:18px}
  .stat{padding:16px 18px}
  .stat .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.6px}
  .stat .v{font-size:24px;font-weight:700;margin-top:6px}
  .stat .u{color:var(--muted);font-size:12px;font-weight:500;margin-left:4px}

  .section-title{font-size:13px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);
    margin:26px 0 12px}
  .chartwrap{position:relative}
  canvas{width:100%;height:260px;display:block}
  .legend{display:flex;gap:16px;flex-wrap:wrap;margin-top:10px;font-size:12px;color:var(--muted)}
  .legend span{display:inline-flex;align-items:center;gap:6px}
  .legend i{width:11px;height:11px;border-radius:3px;display:inline-block}
  .tooltip{position:absolute;pointer-events:none;background:#0a0d13;border:1px solid var(--line);
    border-radius:8px;padding:8px 10px;font-size:12px;display:none;transform:translate(-50%,-108%);
    white-space:nowrap;box-shadow:0 8px 20px rgba(0,0,0,.4);z-index:5}

  .findings{display:flex;flex-direction:column;gap:12px}
  .finding{border-left:4px solid var(--line);padding:14px 16px}
  .finding .fhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .pill{font-size:11px;font-weight:700;letter-spacing:.5px;padding:3px 9px;border-radius:20px;color:#0b0e14}
  .fattack{font-weight:700;font-size:15px}
  .fsvc{font-size:12px;font-weight:700;letter-spacing:.2px;padding:3px 10px;border-radius:20px;
    background:#20304d;border:1px solid #35507f;color:#dbe7ff}
  .fsvc code{background:transparent;color:#8fb6ff;font-weight:700}
  .ftag{font-size:11px;color:var(--muted);border:1px solid var(--line);padding:2px 8px;border-radius:20px}
  .fvictim{margin:8px 0 4px;font-size:13px}
  .fvictim code{background:var(--panel2);padding:2px 7px;border-radius:6px}
  .fevidence{color:var(--muted);font-size:13px}
  .fmit{margin-top:8px;font-size:12.5px;color:#bcd0ff;background:#111a2b;border:1px solid #1d2b47;
    padding:8px 10px;border-radius:8px}
  details.mitsteps{margin-top:9px;background:#101923;border:1px solid #203247;
    border-radius:8px;padding:8px 10px}
  details.mitsteps summary{cursor:pointer;color:#bcd0ff;font-size:12.5px;font-weight:600}
  details.mitsteps ol{margin:8px 0 2px;padding-left:22px;color:var(--muted);font-size:12.5px}
  details.mitsteps li{margin:5px 0;padding-left:3px}
  .clean{padding:26px;text-align:center;color:var(--ok);font-weight:600}
  details.fs{margin-top:10px}
  details.fs summary{cursor:pointer;font-size:12px;color:var(--accent);font-weight:600;user-select:none}
  .fscode{position:relative;margin-top:8px}
  .fscode pre{margin:0;background:#0a0d13;border:1px solid var(--line);border-radius:8px;
    padding:12px 12px;overflow-x:auto;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    color:#cfe3ff}
  .fscode .copy{position:absolute;top:8px;right:8px;font-size:11px;padding:4px 9px;border-radius:6px;
    background:var(--panel2);color:var(--text);border:1px solid var(--line);cursor:pointer}
  .fscode .copy:hover{filter:brightness(1.15)}
  .fsformat{display:flex;align-items:center;gap:10px;margin-top:12px;flex-wrap:wrap;font-size:12px}
  .fsformat select{max-width:100%}
  .risk{display:inline-flex;margin-top:10px;padding:4px 8px;border-radius:20px;
    font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
  .risk-low{background:#183d34;color:#8ce9ce}.risk-medium{background:#493716;color:#ffd27a}
  .risk-high{background:#51242b;color:#ffadb9}
  .fsheading{margin-top:14px;color:var(--text);font-size:12px;font-weight:700}
  .fscheck{margin:7px 0 0;padding-left:22px;color:var(--muted);font-size:12px}
  .fscheck li{margin:6px 0;line-height:1.6}
  .fsnote{margin-top:8px;font-size:12px;color:var(--muted)}
  .fsunsupported{margin-top:10px;font-size:12.5px;color:#ffd9a6;background:#241a0e;
    border:1px solid #4a380f;padding:8px 10px;border-radius:8px}
  .verifybox pre{margin:0;background:#0a0d13;border:1px solid var(--line);border-radius:8px;
    padding:12px;overflow-x:auto;font:12px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#cfe3ff}

  .cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  @media(max-width:760px){.cols{grid-template-columns:1fr}}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
  th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
  td.num{text-align:right;font-variant-numeric:tabular-nums}
  .bar{height:9px;border-radius:5px;background:var(--panel2);overflow:hidden}
  .bar>i{display:block;height:100%}
  .refltag{font-size:10px;color:#0b0e14;background:var(--med);padding:1px 6px;border-radius:10px;font-weight:700}
  .gridtools{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:4px 0 12px}
  .gridtools input{min-width:150px;flex:1;background:var(--bg);border:1px solid var(--line);
    color:var(--text);border-radius:7px;padding:8px 10px;font:inherit}
  .gridtools select{padding:7px}.gridstatus{color:var(--muted);font-size:11px;white-space:nowrap}
  .tablewrap{overflow:auto;max-height:430px;border:1px solid var(--line);border-radius:8px}
  .tablewrap table{min-width:440px}.tablewrap th{position:sticky;top:0;background:var(--panel);z-index:1}
  .sortbtn{all:unset;cursor:pointer;color:inherit;font:inherit;display:flex;gap:6px;align-items:center}
  .sortbtn:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
  .sortmark{color:var(--accent);min-width:8px}.pager{display:flex;gap:8px;align-items:center;margin-top:10px}
  .pager button{padding:6px 10px;font-size:11px}.pager .gridstatus{margin-right:auto}

  .overlay{position:fixed;inset:0;background:rgba(6,9,14,.78);display:none;place-items:center;z-index:20}
  .overlay.show{display:grid}
  .progbox{width:min(420px,86vw);background:var(--panel);border:1px solid var(--line);
    border-radius:var(--radius);padding:26px 26px 22px;text-align:center}
  .spinner{width:40px;height:40px;border:4px solid var(--line);border-top-color:var(--accent);
    border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 14px}
  @keyframes spin{to{transform:rotate(360deg)}}
  .progtrack{margin-top:16px;height:10px;border-radius:6px;background:var(--panel2);
    overflow:hidden;position:relative}
  .progtrack>i{display:block;height:100%;width:0;border-radius:6px;
    background:linear-gradient(90deg,#5b8def,#22c1a4);transition:width .2s ease}
  .progtrack.indet>i{width:35%!important;position:absolute;
    animation:indet 1.1s ease-in-out infinite}
  @keyframes indet{0%{left:-40%}100%{left:105%}}
  .progmeta{margin-top:10px;color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums}
  .foot{color:var(--muted);font-size:12px;margin-top:30px;text-align:center}
  /* Investigation workspace: persistent navigation and a quieter data canvas. */
  :root{--bg:#101419;--panel:#181e25;--panel2:#202832;--line:#303b47;
    --text:#ecf1f5;--muted:#a0adbc;--accent:#73dcc0;--radius:12px}
  body{font-size:14px;background:var(--bg)}
  .sidebar{position:fixed;inset:0 auto 0 0;width:220px;background:#141a20;
    border-right:1px solid var(--line);padding:30px 22px;display:flex;flex-direction:column;gap:32px}
  .brand{font-size:22px;letter-spacing:-1px;font-weight:800;display:flex;align-items:center;gap:10px}
  .brandmark{color:var(--accent);font-size:28px}
  .brand small{display:block;font-size:10px;letter-spacing:2px;color:var(--muted);font-weight:500}
  .navlabel,.eyebrow{color:var(--muted);font-size:10px;letter-spacing:1.8px;text-transform:uppercase;font-weight:700}
  .sidebar nav{display:grid;gap:8px;margin-top:14px}
  .sidebar nav a{color:var(--muted);text-decoration:none;padding:11px 12px;border-radius:7px}
  .sidebar nav a:hover{color:var(--text);background:var(--panel2)}
  .sidebar nav a[aria-disabled="true"]{opacity:.45;pointer-events:none}
  .sidebar nav a:first-child{background:#233c36;color:#8ce9ce}
  .local-note{margin-top:auto;font-size:12px;color:var(--muted);line-height:1.8}
  .local-note strong{display:block;color:var(--accent);font-weight:500}
  .wrap{max-width:1500px;margin-left:220px;padding:28px 40px 48px}
  header.top{justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:22px;margin-bottom:32px}
  h1{font-size:14px;font-weight:600;letter-spacing:0}
  .status{font-size:11px;color:var(--accent);border:1px solid #355247;border-radius:30px;padding:5px 10px;white-space:nowrap}
  .pageintro{margin-bottom:26px}
  .pageintro h2{font-size:34px;letter-spacing:-1.2px;line-height:1.2;margin:10px 0 12px;font-weight:650}
  .pageintro p{color:var(--muted);max-width:620px;margin:0;line-height:1.7}
  #upload{margin-top:0;padding:26px;max-width:1000px}
  .drop{padding:44px 20px;background:#151f24;border:1px dashed #48675e;border-radius:9px}
  .drop:hover,.drop.drag{background:#1c302b;border-color:var(--accent)}
  .upload-icon{display:block;font-size:30px;color:var(--accent);margin-bottom:14px}
  .drop .big{font-size:19px;letter-spacing:-.4px}
  .drop .hint{font-size:12px}
  .chosen{overflow-wrap:anywhere}
  button{color:#0c201a;background:var(--accent);font-size:13px;padding:11px 16px}
  button.ghost{color:var(--text);background:var(--panel2)}
  :focus-visible{outline:2px solid var(--accent);outline-offset:4px}
  .workflow{display:grid;grid-template-columns:repeat(3,1fr);gap:24px;margin:28px 0 0;padding-top:24px;border-top:1px solid var(--line)}
  .workflow span{color:var(--accent);font-size:11px;font-family:monospace}
  .workflow strong{display:block;font-size:13px;margin:6px 0}
  .workflow p{color:var(--muted);font-size:12px;margin:0;line-height:1.6}
  #results{margin-top:0}
  .result-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:20px}
  .result-actions .eyebrow{margin-right:auto}
  .verdict{background:linear-gradient(100deg,#242b32,var(--panel));align-items:flex-start}
  .verdict .dot{margin-top:5px;flex-shrink:0}
  .verdict .filemeta{max-width:35%;overflow-wrap:anywhere}
  .stats{grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;border:1px solid var(--line);border-radius:12px;overflow:hidden}
  .stat{border:0;border-radius:0;padding:19px 22px}
  .stat .v{font-size:27px;letter-spacing:-.7px;font-variant-numeric:tabular-nums}
  .section-title{font-size:12px;letter-spacing:.3px;text-transform:none;font-weight:600;color:var(--text);margin-top:28px}
  .finding{padding:22px;border-left-width:3px}
  .finding .fhead{gap:8px}.fattack{font-size:16px}.fvictim{margin:14px 0 8px}
  .fevidence{line-height:1.8}.fmit{margin-top:15px;background:#1b2c2b;border-color:#304b45;color:#b8e1d6;line-height:1.7}
  details.mitsteps{background:transparent;border-color:var(--line);padding:12px}
  details.mitsteps summary{color:var(--text)}
  details.mitsteps li{line-height:1.7;margin:8px 0}
  details.fs summary{color:var(--accent);overflow-wrap:anywhere;line-height:1.8}
  .fscode pre{padding-top:42px}
  .cols>div{min-width:0}.cols .card{overflow-x:auto}
  .filterbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:26px 0 12px}
  .filterbar .section-title{margin:0 auto 0 0}
  .filterbar label{color:var(--muted);font-size:12px}
  select{background:var(--panel2);color:var(--text);border:1px solid var(--line);padding:8px;border-radius:7px;font:inherit}
  .finding[hidden]{display:none}
  .foot{text-align:left;border-top:1px solid var(--line);padding-top:20px}
  @media(min-width:1500px){.stats{grid-template-columns:repeat(6,minmax(0,1fr))}}
  @media(max-width:1000px){.sidebar{width:175px;padding:26px 16px}.wrap{margin-left:175px;padding:24px}.cols{grid-template-columns:1fr}}
  @media(max-width:650px){.sidebar{position:static;width:auto;padding:16px 20px;border-right:0;border-bottom:1px solid var(--line)}
    .sidebar nav,.sidebar .navlabel,.local-note{display:none}.brand{font-size:19px}.brand small{display:none}
    .wrap{margin:0;padding:20px 16px}.pageintro h2{font-size:27px}header.top{margin-bottom:24px}
    .stats{grid-template-columns:repeat(2,minmax(0,1fr))}.stat{padding:15px}.stat .v{font-size:23px}
    #upload{padding:18px}.workflow{grid-template-columns:1fr;gap:16px}.drop{padding:32px 12px}
    .verdict{flex-wrap:wrap}.verdict .filemeta{max-width:100%;margin-left:30px;text-align:left}
    .finding{padding:16px}.fattack{font-size:14px}.fvictim{overflow-wrap:anywhere}
    .pad{padding:16px}.result-actions button{flex:1}.grid-opts{grid-template-columns:repeat(2,minmax(0,1fr))}
    .grid-opts input{min-width:0;width:100%}}
  @media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
</style>
</head>
<body>
<aside class="sidebar" aria-label="Workspace navigation">
  <div class="brand"><span class="brandmark" aria-hidden="true">◈</span><div>Packetlens<small>DDOS FORENSICS</small></div></div>
  <div><div class="navlabel">Workspace</div><nav>
    <a href="#workspace">Capture analysis</a><a href="#findings" class="report-link" aria-disabled="true" tabindex="-1">Findings &amp; response</a>
    <a href="#topsrc" class="report-link" aria-disabled="true" tabindex="-1">Traffic sources</a>
  </nav></div>
  <div class="local-note"><strong>● Local analysis</strong>Your captures stay on this machine.<br>No external services required.</div>
</aside>
<div class="wrap">
  <header class="top" id="workspace">
    <h1>Security workspace / Capture analysis</h1><span class="status">● Offline ready</span>
  </header>
  <div class="pageintro"><div class="eyebrow">PACKET CAPTURE INTELLIGENCE</div>
    <h2 id="pageTitle">Understand the traffic.<br>Plan your response.</h2>
    <p id="pageDescription">Turn a packet capture into a clear view of attack indicators, affected hosts, and practical mitigation steps.</p>
  </div>

  <!-- UPLOAD -->
  <section id="upload" class="card pad">
    <form id="form">
      <div class="drop" id="drop" role="button" tabindex="0" aria-label="Choose a packet capture">
        <span class="upload-icon" aria-hidden="true">↥</span>
        <div class="big">Drop your capture here</div>
        <div class="hint">or click to browse &nbsp; · &nbsp; PCAP, PCAPNG, CAP</div>
        <input type="file" id="file" name="pcap" accept=".pcap,.pcapng,.cap" hidden>
      </div>
      <div class="chosen" id="chosen">No file selected.</div>

      <details class="adv">
        <summary>Advanced thresholds</summary>
        <div class="grid-opts">
          <label>Window (s)<input type="number" step="0.1" min="0.1" name="window" placeholder="1.0"></label>
          <label>SYN pps<input type="number" name="syn_pps" placeholder="500"></label>
          <label>UDP pps<input type="number" name="udp_pps" placeholder="1000"></label>
          <label>ICMP pps<input type="number" name="icmp_pps" placeholder="500"></label>
          <label>Reflection pps<input type="number" name="reflect_pps" placeholder="200"></label>
          <label>DNS query pps<input type="number" name="dns_query_pps" placeholder="500"></label>
          <label>Distributed sources<input type="number" name="distributed_sources" placeholder="25"></label>
        </div>
      </details>

      <div class="row">
        <button type="submit" id="analyzeBtn" disabled>Analyze capture</button>
        <button type="button" class="ghost" id="demoBtn">Try a demo capture</button>
      </div>
      <div class="err" id="err" role="alert"></div>
    </form>
    <div class="workflow"><div><span>01 / INGEST</span><strong>Bring the evidence</strong><p>Upload a capture or explore a sample with the demo.</p></div>
      <div><span>02 / INVESTIGATE</span><strong>Find the signal</strong><p>Inspect traffic peaks, targets, and detection confidence.</p></div>
      <div><span>03 / RESPOND</span><strong>Choose your next step</strong><p>Review mitigation playbooks and scoped FlowSpec rules.</p></div></div>
  </section>

  <!-- RESULTS -->
  <section id="results">
    <div class="result-actions"><span class="eyebrow">ANALYSIS REPORT</span><button type="button" class="ghost" id="newBtn">New capture</button><button type="button" class="ghost" id="reportBtn">PDF report ↓</button><button type="button" id="exportBtn">Export JSON ↓</button></div>
    <div class="verdict card" id="verdict"></div>
    <div class="stats" id="stats"></div>

    <div class="section-title" id="tlTitle">Traffic over time (packets/sec)</div>
    <div class="card pad chartwrap">
      <canvas id="chart"></canvas>
      <div class="tooltip" id="tt"></div>
      <div class="legend">
        <span><i style="background:var(--tcp)"></i>TCP</span>
        <span><i style="background:var(--udp)"></i>UDP</span>
        <span><i style="background:var(--icmp)"></i>ICMP</span>
        <span><i style="background:var(--other)"></i>Other</span>
      </div>
    </div>

    <div class="filterbar"><div class="section-title">Findings &amp; response <span id="findingCount"></span></div>
      <label for="severityFilter">Severity</label><select id="severityFilter"><option value="all">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></div>
    <div id="filterEmpty" class="clean card" hidden>No findings match this severity.</div>
    <div class="findings" id="findings"></div>

    <div class="cols">
      <div>
        <div class="section-title">Protocols — complete inventory</div>
        <div class="card pad" id="protomix"></div>
      </div>
      <div>
        <div class="section-title">UDP destination ports — complete inventory</div>
        <div class="card pad" id="udpports"></div>
      </div>
    </div>

    <div class="cols">
      <div>
        <div class="section-title">Destinations — complete inventory</div>
        <div class="card pad" id="topdst"></div>
      </div>
      <div>
        <div class="section-title">Sources — complete inventory</div>
        <div class="card pad" id="topsrc"></div>
      </div>
    </div>

    <div class="row"><button class="ghost" id="againBtn">Analyze another capture</button></div>
  </section>

  <p class="foot">Heuristic forensic tool &middot; runs locally with scapy &middot; not an inline mitigation device.</p>
</div>

<div class="overlay" id="overlay">
  <div class="progbox">
    <div class="spinner"></div>
    <div id="overlayText">Analyzing capture&hellip;</div>
    <div class="progtrack" id="progtrack"><i id="progfill"></i></div>
    <div class="progmeta" id="progmeta" role="status" aria-live="polite"></div>
  </div>
</div>

<script>
const SEV = {
  CRITICAL:{c:'var(--crit)',label:'Critical'},
  HIGH:{c:'var(--high)',label:'High'},
  MEDIUM:{c:'var(--med)',label:'Medium'},
  LOW:{c:'var(--low)',label:'Low'},
};
const PROTO = [['TCP','var(--tcp)'],['UDP','var(--udp)'],['ICMP','var(--icmp)'],['other','var(--other)']];

const $ = s => document.querySelector(s);
const el = (t,c,txt)=>{const e=document.createElement(t);if(c)e.className=c;if(txt!=null)e.textContent=txt;return e;};

function fmt(n){
  if(n>=1e6) return (n/1e6).toFixed(2)+'M';
  if(n>=1e3) return Math.round(n).toLocaleString();
  return (Math.round(n*10)/10).toLocaleString();
}
function fmtInt(n){return Math.round(n).toLocaleString();}
function fmtBytes(n){
  const u=['B','KB','MB','GB','TB'];let i=0;
  while(n>=1024&&i<u.length-1){n/=1024;i++;}
  return (Math.round(n*10)/10).toLocaleString()+' '+u[i];
}

// ---- file selection ----
const fileInput=$('#file'), drop=$('#drop'), chosen=$('#chosen'), analyzeBtn=$('#analyzeBtn');
drop.addEventListener('click',()=>fileInput.click());
drop.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();fileInput.click();}});
['dragover','dragenter'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('drag');}));
['dragleave','drop'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('drag');}));
drop.addEventListener('drop',e=>{if(e.dataTransfer.files.length){fileInput.files=e.dataTransfer.files;onFile();}});
fileInput.addEventListener('change',onFile);
function onFile(){
  const f=fileInput.files[0];
  if(f){
    chosen.textContent='Selected: ';
    const name=el('b',null,f.name);
    chosen.append(name,document.createTextNode(' ('+fmtBytes(f.size)+')'));
    analyzeBtn.disabled=false;
  }
  else{chosen.textContent='No file selected.';analyzeBtn.disabled=true;}
}

// ---- submit ----
function showErr(m){const e=$('#err');e.textContent=m;e.style.display='block';}
function hideErr(){$('#err').style.display='none';}
function overlay(on,text){$('#overlayText').textContent=text||'Analyzing capture…';$('#overlay').classList.toggle('show',on);}
function setProgress(pct,packets,label){
  const fill=$('#progfill'),track=$('#progtrack'),meta=$('#progmeta');
  if(label) $('#overlayText').textContent=label;
  const parts=[];
  if(pct==null){track.classList.add('indet');}
  else{track.classList.remove('indet');fill.style.width=Math.max(2,pct)+'%';parts.push(pct+'%');}
  if(packets!=null&&packets>0) parts.push(fmtInt(packets)+' packets');
  meta.textContent=parts.join('  ·  ');
}

$('#form').addEventListener('submit',async e=>{
  e.preventDefault();hideErr();
  if(!fileInput.files.length){showErr('Choose a capture file first.');return;}
  const fd=new FormData($('#form'));
  fd.append('stream','1');
  await runStream(fd);
});
$('#demoBtn').addEventListener('click',async()=>{hideErr();await runJson('/api/demo',new FormData(),'Building demo capture…');});
let currentReport=null;
function newCapture(){
  document.querySelectorAll('.report-link').forEach(a=>{a.setAttribute('aria-disabled','true');a.tabIndex=-1;});
  $('#results').style.display='none';$('#upload').style.display='block';window.scrollTo({top:0,behavior:'smooth'});
  $('#pageTitle').textContent='Understand the traffic. Plan your response.';
  $('#pageDescription').textContent='Turn a packet capture into a clear view of attack indicators, affected hosts, and practical mitigation steps.';
  drop.focus();
}
$('#againBtn').addEventListener('click',newCapture);
$('#newBtn').addEventListener('click',newCapture);
function downloadText(name,text,type){
  const url=URL.createObjectURL(new Blob([text],{type:type}));
  const link=el('a');link.href=url;link.download=name;link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
$('#exportBtn').addEventListener('click',()=>{
  if(!currentReport)return;
  downloadText('capture-analysis.json',JSON.stringify(currentReport,null,2),'application/json');
});
$('#reportBtn').addEventListener('click',async()=>{
  if(!currentReport)return;
  const button=$('#reportBtn'),label=button.textContent;
  button.disabled=true;button.textContent='Building PDF…';hideErr();
  try{
    const response=await fetch('/api/report.pdf',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(currentReport)
    });
    if(!response.ok){
      let message='PDF report failed ('+response.status+')';
      try{const data=await response.json();message=data.error||message;}catch(_){}
      throw new Error(message);
    }
    const url=URL.createObjectURL(await response.blob());
    const link=el('a');link.href=url;link.download='packetlens-incident-report.pdf';link.click();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  }catch(err){showErr(err.message);}
  finally{button.disabled=false;button.textContent=label;}
});
function filterFindings(){
  const value=$('#severityFilter').value;
  let visible=0;
  document.querySelectorAll('.finding').forEach(card=>{
    card.hidden=value!=='all'&&card.dataset.severity!==value;
    if(!card.hidden)visible++;
  });
  $('#filterEmpty').hidden=!currentReport||!currentReport.findings.length||visible>0;
}
$('#severityFilter').addEventListener('change',filterFindings);

// Non-streaming (demo): show an indeterminate bar until the JSON arrives.
async function runJson(url,fd,text){
  overlay(true,text);setProgress(null,null);
  try{
    const r=await fetch(url,{method:'POST',body:fd});
    const data=await r.json();
    if(!r.ok){showErr(data.error||('Request failed ('+r.status+')'));return;}
    render(data);
  }catch(err){showErr('Network error: '+err.message);}
  finally{overlay(false);}
}

// Streaming upload+analysis: read NDJSON progress lines, update the bar live.
async function runStream(fd){
  overlay(true,'Analyzing capture…');setProgress(0,0);
  try{
    const r=await fetch('/api/analyze',{method:'POST',body:fd});
    if(!r.ok){
      let msg='Request failed ('+r.status+')';
      try{const d=await r.json();msg=d.error||msg;}catch(_){}
      showErr(msg);return;
    }
    const reader=r.body.getReader(),dec=new TextDecoder();
    let buf='',result=null,err=null;
    for(;;){
      const {done,value}=await reader.read();
      if(done) break;
      buf+=dec.decode(value,{stream:true});
      let nl;
      while((nl=buf.indexOf('\n'))>=0){
        const ln=buf.slice(0,nl).trim();buf=buf.slice(nl+1);
        if(!ln) continue;
        let msg;try{msg=JSON.parse(ln);}catch(_){continue;}
        if(msg.type==='progress') setProgress(msg.pct,msg.packets);
        else if(msg.type==='result') result=msg.report;
        else if(msg.type==='error') err=msg.error;
      }
    }
    if(err){showErr(err);return;}
    if(result){setProgress(100,result.summary.packets,'Done');render(result);}
    else showErr('No result received from server.');
  }catch(err){showErr('Network error: '+err.message);}
  finally{overlay(false);}
}

// ---- render ----
function render(d){
  document.querySelectorAll('.report-link').forEach(a=>{a.removeAttribute('aria-disabled');a.tabIndex=0;});
  currentReport=d;
  $('#pageTitle').textContent='Your capture, decoded.';
  $('#pageDescription').textContent='Review the evidence, prioritize findings, and choose the right mitigation for each affected host.';
  $('#severityFilter').value='all';
  $('#findingCount').textContent='('+d.findings.length+')';
  $('#upload').style.display='none';
  $('#results').style.display='block';

  // verdict
  const v=$('#verdict');v.innerHTML='';
  const sev=d.verdict.severity;
  const color=sev?SEV[sev].c:'var(--ok)';
  v.style.borderColor=color;
  const dot=el('div','dot');dot.style.background=color;
  const txt=el('div');
  const line=el('div','vtext');
  line.textContent=sev
    ? SEV[sev].label.toUpperCase()+' — '+d.verdict.count+' finding'+(d.verdict.count>1?'s':'')+' detected'
    : 'No attack indicators above thresholds';
  line.style.color=color;
  const sline=el('div','vsub',sev?'Highest-severity vector shown first below.':'Traffic looks clean for the configured thresholds.');
  txt.append(line,sline);
  const meta=el('div','filemeta');
  if(d.file.demo){meta.append(el('b',null,'demo capture'),el('br'));}
  meta.append(document.createTextNode(d.file.name),el('br'),
    document.createTextNode(fmtBytes(d.file.size_bytes)));
  v.append(dot,txt,meta);

  // stats
  const s=d.summary;
  const cards=[
    ['Packets',fmtInt(s.packets),''],
    ['Duration',fmt(s.duration_s),'s'],
    ['Avg rate',fmt(s.avg_pps),'pps'],
    ['Peak rate',fmt(s.peak_pps),'pps'],
    ['Avg bandwidth',fmt(s.avg_mbps),'Mbps'],
    ['Total bytes',fmtBytes(s.bytes),''],
  ];
  const st=$('#stats');st.innerHTML='';
  cards.forEach(([k,val,u])=>{
    const c=el('div','stat card');
    c.append(el('div','k',k));
    const vv=el('div','v');vv.textContent=val;if(u){const us=el('span','u',u);vv.append(us);}
    c.append(vv);st.append(c);
  });

  const res=s.timeline_bucket_s;
  if(res){const rt=res<1?Math.round(res*1000)+' ms':(+res.toFixed(2))+' s';
    $('#tlTitle').textContent='Traffic over time (packets/sec · '+rt+' buckets)';}
  drawChart(d.timeline,s.window_s);
  renderFindings(d.findings);
  filterFindings();
  const protocols=d.protocols||Object.entries(s.protocol_counts).map(([protocol,packets])=>
    ({protocol,packets,pps:packets/s.duration_s,share:packets/s.packets*100}));
  renderProtoMix(s.protocol_counts,s.packets,protocols);
  renderDataGrid('#udpports',[
    {key:'port',label:'Port',numeric:true,format:v=>'UDP/'+v},
    {key:'packets',label:'Packets',numeric:true,format:fmtInt},
    {key:'share',label:'Share',numeric:true,format:v=>v+'%'},
    {key:'reflector',label:'Service',format:v=>v||'—'}],d.udp_ports||d.top_udp_ports,'Search ports or services');
  renderDataGrid('#topdst',[
    {key:'ip',label:'Destination'},
    {key:'packets',label:'Packets',numeric:true,format:fmtInt},
    {key:'pps',label:'pps',numeric:true,format:fmt},
    {key:'share',label:'Share',numeric:true,format:v=>v+'%'}],d.destinations||d.top_destinations,'Search destinations');
  renderDataGrid('#topsrc',[
    {key:'ip',label:'Source'},
    {key:'packets',label:'Packets',numeric:true,format:fmtInt},
    {key:'pps',label:'pps',numeric:true,format:fmt},
    {key:'share',label:'Share',numeric:true,format:v=>v+'%'}],d.sources||d.top_sources,'Search sources');

  window.scrollTo({top:0,behavior:'smooth'});
}

function renderFindings(list){
  const box=$('#findings');box.innerHTML='';
  if(!list.length){
    const c=el('div','card clean','✓ No traffic crossed the configured heuristic thresholds.');
    box.append(c);return;
  }
  list.forEach(f=>{
    const sev=SEV[f.severity];
    const card=el('div','finding card');card.style.borderLeftColor=sev.c;
    card.dataset.severity=f.severity;
    const head=el('div','fhead');
    const pill=el('span','pill',sev.label.toUpperCase());pill.style.background=sev.c;
    head.append(pill,el('span','fattack',f.attack));
    // Distinguish otherwise-identical alerts (e.g. reflection per service) by
    // surfacing the unique service + source port in the header.
    if(f.extra && f.extra.service){
      const svc=el('span','fsvc');svc.textContent=f.extra.service;
      if(f.extra.source_port!=null){svc.append(document.createTextNode(' '));
        svc.append(el('code',null,'UDP/'+f.extra.source_port));}
      head.append(svc);
    }
    head.append(el('span','ftag',f.distributed?'distributed':'single/few-source'));
    if(f.method) head.append(el('span','ftag','via '+f.method));
    if(f.confidence && f.confidence!=='high') head.append(el('span','ftag',f.confidence+' confidence'));
    if(f.mbps!=null) head.append(el('span','ftag',fmt(f.mbps)+' Mbps'));
    card.append(head);
    const vic=el('div','fvictim');vic.innerHTML='Victim: <code>'+f.victim+'</code> · peak <b>'+fmt(f.peak_pps)+' pps</b> @ +'+f.peak_offset_s+'s · '+fmtInt(f.unique_sources)+' unique sources';
    card.append(vic);
    card.append(el('div','fevidence',f.evidence));
    if(f.mitigation) card.append(el('div','fmit','Mitigation: '+f.mitigation));
    if(f.mitigation_techniques && f.mitigation_techniques.length){
      const playbook=el('details','mitsteps');
      playbook.append(el('summary',null,'Mitigation playbook — '+f.mitigation_techniques.length+' actions'));
      const actions=el('ol');
      f.mitigation_techniques.forEach(step=>actions.append(el('li',null,step)));
      playbook.append(actions);card.append(playbook);
    }
    if(f.flowspec) card.append(flowspecBlock(f.flowspec));
    box.append(card);
  });
}

function flowspecBlock(fs){
  if(!fs.supported){
    const d=el('div','fsunsupported');
    d.textContent='FlowSpec: not expressible ('+fs.summary+'). '+fs.note;
    return d;
  }
  const det=el('details','fs');
  det.append(el('summary',null,'FlowSpec rule — '+fs.summary));
  if(fs.note) det.append(el('div','fsnote',fs.note));
  if(fs.risk){
    const risk=el('span','risk risk-'+fs.risk.level,fs.risk.level+' collateral risk');
    risk.title=fs.risk.reason;det.append(risk,el('div','fsnote',fs.risk.reason));
  }
  if(fs.monitoring){
    det.append(el('div','fsnote','Suggested expiry: '+fs.monitoring.suggested_expiry_minutes+
      ' minutes · verify counters every '+fs.monitoring.check_every_seconds+' seconds'));
  }
  if(fs.response_checklist){
    const checklist=el('details','mitsteps');checklist.append(el('summary',null,'Response checklist'));
    const steps=el('ol','fscheck');fs.response_checklist.forEach(step=>steps.append(el('li',null,step)));
    checklist.append(steps);det.append(checklist);
  }
  const formats=fs.vendors||{exabgp:{label:'ExaBGP',supported:true,config:fs.exabgp,note:'',verify:[]}};
  const controls=el('label','fsformat','Syntax for '), selector=el('select');
  Object.entries(formats).forEach(([key,value])=>{const option=el('option',null,value.label);option.value=key;selector.append(option);});
  controls.append(selector);det.append(controls);
  const vendorNote=el('div','fsnote');det.append(vendorNote);
  const wrap=el('div','fscode');
  const pre=el('pre');
  const btn=el('button','copy','Copy');
  btn.type='button';
  btn.addEventListener('click',async()=>{
    try{
      await navigator.clipboard.writeText(formats[selector.value].config);
      btn.textContent='Copied';setTimeout(()=>btn.textContent='Copy',1200);
    }catch(_){btn.textContent='Copy failed';}
  });
  wrap.append(pre,btn);det.append(wrap);
  const verifyTitle=el('div','fsheading'),verify=el('pre','fsnote');
  const withdrawTitle=el('div','fsheading'),withdrawNote=el('div','fsnote'),withdraw=el('pre','fsnote');
  const reference=el('a','fsnote','Vendor documentation ↗');
  reference.target='_blank';reference.rel='noopener noreferrer';
  det.append(verifyTitle,verify,withdrawTitle,withdrawNote,withdraw,reference);
  function selectFormat(){
    const selected=formats[selector.value];
    vendorNote.textContent=selected.note;
    wrap.hidden=!selected.supported;
    pre.textContent=selected.config||'';btn.textContent='Copy';
    verify.textContent=(selected.verify||[]).join('\n');
    verify.style.whiteSpace='pre-wrap';verify.hidden=!verify.textContent;
    verifyTitle.textContent=verify.textContent
      ? 'Verification — '+selected.label
      : selected.supported ? 'Verify installation and packet counters on the receiving router using its vendor-specific commands.' : '';
    verifyTitle.hidden=!verifyTitle.textContent;
    withdrawTitle.textContent=selected.withdraw?'Withdrawal / rollback — '+selected.label:'';
    withdrawTitle.hidden=!withdrawTitle.textContent;
    withdrawNote.textContent=selected.withdraw_note||'';withdrawNote.hidden=!withdrawNote.textContent;
    withdraw.textContent=selected.withdraw||'';withdraw.style.whiteSpace='pre-wrap';
    withdraw.hidden=!withdraw.textContent;
    reference.hidden=!selected.reference;
    if(selected.reference)reference.href=selected.reference;
  }
  selector.addEventListener('change',selectFormat);selectFormat();
  return det;
}

function renderProtoMix(counts,total,rows){
  const box=$('#protomix');box.innerHTML='';
  const mix=el('div');box.append(mix);
  const entries=Object.entries(counts).sort((a,b)=>b[1]-a[1]);
  const colorFor=k=>({TCP:'var(--tcp)',UDP:'var(--udp)',ICMP:'var(--icmp)'})[k]||'var(--other)';
  entries.forEach(([k,c])=>{
    const pct=total?(c/total*100):0;
    const rowEl=el('div');rowEl.style.margin='10px 0';
    const lbl=el('div');lbl.style.cssText='display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px';
    lbl.append(el('span',null,k),el('span','',fmtInt(c)+'  ('+pct.toFixed(1)+'%)'));
    const bar=el('div','bar');const fill=el('i');fill.style.width=pct+'%';fill.style.background=colorFor(k);
    bar.append(fill);rowEl.append(lbl,bar);mix.append(rowEl);
  });
  const grid=el('div');box.append(grid);
  renderDataGrid(grid,[
    {key:'protocol',label:'Protocol'},
    {key:'packets',label:'Packets',numeric:true,format:fmtInt},
    {key:'pps',label:'pps',numeric:true,format:fmt},
    {key:'share',label:'Share',numeric:true,format:v=>v.toFixed(2)+'%'}],rows,'Search protocols');
}

const GRID_COLLATOR=new Intl.Collator(undefined,{numeric:true,sensitivity:'base'});
function renderDataGrid(target,columns,sourceRows,placeholder){
  const box=typeof target==='string'?$(target):target;box.innerHTML='';box.style.color='';
  const rows=sourceRows||[], state={sort:columns.find(c=>c.numeric)?.key||columns[0].key,dir:-1,page:0,size:25,query:''};
  const tools=el('div','gridtools'),search=el('input'),size=el('select'),status=el('span','gridstatus');
  search.type='search';search.placeholder=placeholder;search.setAttribute('aria-label',placeholder);
  [['25','25 rows'],['100','100 rows'],['all','All rows']].forEach(([v,t])=>{const o=el('option',null,t);o.value=v;size.append(o);});
  tools.append(search,size,status);box.append(tools);
  const wrap=el('div','tablewrap'),table=el('table'),head=el('tr');table.append(head);wrap.append(table);box.append(wrap);
  const pager=el('div','pager'),pageStatus=el('span','gridstatus'),prev=el('button','ghost','Previous'),next=el('button','ghost','Next');
  prev.type=next.type='button';pager.append(pageStatus,prev,next);box.append(pager);
  columns.forEach(col=>{
    const th=el('th',col.numeric?'num':null),button=el('button','sortbtn'),mark=el('span','sortmark');
    button.append(document.createTextNode(col.label),mark);button.addEventListener('click',()=>{
      if(state.sort===col.key)state.dir*=-1;else{state.sort=col.key;state.dir=col.numeric?-1:1;}state.page=0;draw();
    });th.append(button);head.append(th);col._th=th;col._mark=mark;
  });
  function draw(){
    table.querySelectorAll('tr:not(:first-child)').forEach(r=>r.remove());
    const query=state.query.toLocaleLowerCase();
    const filtered=rows.filter(row=>!query||columns.some(col=>String(row[col.key]??'').toLocaleLowerCase().includes(query)));
    filtered.sort((a,b)=>{
      const av=a[state.sort],bv=b[state.sort];
      const cmp=typeof av==='number'&&typeof bv==='number'?av-bv:GRID_COLLATOR.compare(String(av??''),String(bv??''));
      return cmp*state.dir;
    });
    const pageSize=state.size==='all'?Math.max(filtered.length,1):state.size;
    const pages=Math.max(1,Math.ceil(filtered.length/pageSize));state.page=Math.min(state.page,pages-1);
    const start=state.page*pageSize,end=Math.min(start+pageSize,filtered.length);
    filtered.slice(start,end).forEach(row=>{
      const tr=el('tr');columns.forEach(col=>{
        const value=col.format?col.format(row[col.key]):row[col.key];
        const td=el('td',col.numeric?'num':null,value==null?'—':String(value));tr.append(td);
      });table.append(tr);
    });
    if(!filtered.length){const tr=el('tr'),td=el('td',null,'No matching rows.');td.colSpan=columns.length;tr.append(td);table.append(tr);}
    status.textContent=fmtInt(filtered.length)+' of '+fmtInt(rows.length)+' rows';
    pageStatus.textContent=filtered.length?(fmtInt(start+1)+'–'+fmtInt(end)+' of '+fmtInt(filtered.length)):'0 rows';
    prev.disabled=state.page===0;next.disabled=state.page>=pages-1;pager.hidden=state.size==='all';
    columns.forEach(col=>{const active=state.sort===col.key;col._mark.textContent=active?(state.dir===1?'↑':'↓'):'';col._th.setAttribute('aria-sort',active?(state.dir===1?'ascending':'descending'):'none');});
  }
  search.addEventListener('input',()=>{state.query=search.value;state.page=0;draw();});
  size.addEventListener('change',()=>{state.size=size.value==='all'?'all':Number(size.value);state.page=0;draw();});
  prev.addEventListener('click',()=>{state.page--;draw();});next.addEventListener('click',()=>{state.page++;draw();});draw();
}

// ---- stacked-area chart on canvas ----
let chartState=null;
function drawChart(timeline,windowS){
  const canvas=$('#chart');
  const dpr=window.devicePixelRatio||1;
  const cssW=canvas.clientWidth, cssH=260;
  canvas.width=cssW*dpr; canvas.height=cssH*dpr;
  const ctx=canvas.getContext('2d');ctx.setTransform(dpr,0,0,dpr,0,0);
  ctx.clearRect(0,0,cssW,cssH);

  const padL=54,padR=14,padT=14,padB=26;
  const W=cssW-padL-padR, H=cssH-padT-padB;

  if(!timeline.length){ctx.fillStyle='#8b95a7';ctx.fillText('No data',padL,padT+20);return;}

  let maxY=0;
  timeline.forEach(r=>{maxY=Math.max(maxY,r.total);});
  maxY=maxY||1; maxY*=1.08;

  const n=timeline.length;
  const x=i=>padL+(n===1?W/2:(i/(n-1))*W);
  const y=val=>padT+H-(val/maxY)*H;

  // gridlines + y labels
  ctx.strokeStyle='rgba(255,255,255,.06)';ctx.fillStyle='#8b95a7';
  ctx.font='11px system-ui';ctx.textBaseline='middle';
  const ticks=4;
  for(let g=0;g<=ticks;g++){
    const val=maxY*g/ticks, yy=y(val);
    ctx.beginPath();ctx.moveTo(padL,yy);ctx.lineTo(padL+W,yy);ctx.stroke();
    ctx.textAlign='right';ctx.fillText(fmt(val),padL-8,yy);
  }
  // x labels (start / mid / end seconds)
  ctx.textAlign='center';ctx.textBaseline='top';
  [0,Math.floor(n/2),n-1].forEach(i=>{ctx.fillText('+'+timeline[i].t+'s',x(i),padT+H+7);});

  // stacked areas (bottom to top): other, ICMP, UDP, TCP
  const order=[['other','#8a8f98'],['ICMP','#f2b134'],['UDP','#22c1a4'],['TCP','#5b8def']];
  const base=new Array(n).fill(0);
  order.forEach(([key,col])=>{
    ctx.beginPath();
    for(let i=0;i<n;i++){const yv=y(base[i]+timeline[i][key]);i?ctx.lineTo(x(i),yv):ctx.moveTo(x(i),yv);}
    for(let i=n-1;i>=0;i--){ctx.lineTo(x(i),y(base[i]));}
    ctx.closePath();
    ctx.fillStyle=hexA(col,.75);ctx.fill();
    ctx.strokeStyle=col;ctx.lineWidth=1;ctx.stroke();
    for(let i=0;i<n;i++) base[i]+=timeline[i][key];
  });

  chartState={timeline,x,y,padL,padT,W,H,n,maxY,cssH};
  attachHover(canvas);
}
function hexA(varColor,a){
  // varColor here is a literal hex; map to rgba
  const m=varColor.replace('#','');
  const r=parseInt(m.substring(0,2),16),g=parseInt(m.substring(2,4),16),b=parseInt(m.substring(4,6),16);
  return 'rgba('+r+','+g+','+b+','+a+')';
}
function attachHover(canvas){
  const tt=$('#tt');
  canvas.onmousemove=e=>{
    if(!chartState)return;
    const rect=canvas.getBoundingClientRect();
    const mx=e.clientX-rect.left;
    const {timeline,padL,W,n}=chartState;
    let i=Math.round(((mx-padL)/W)*(n-1));
    i=Math.max(0,Math.min(n-1,i));
    const r=timeline[i];
    tt.style.display='block';
    tt.style.left=chartState.x(i)+'px';
    tt.style.top=chartState.y(r.total)+'px';
    tt.innerHTML='<b>+'+r.t+'s</b><br>'+
      'TCP '+fmt(r.TCP)+' · UDP '+fmt(r.UDP)+'<br>'+
      'ICMP '+fmt(r.ICMP)+' · Other '+fmt(r.other)+'<br>'+
      '<b>Total '+fmt(r.total)+' pps</b>';
  };
  canvas.onmouseleave=()=>{$('#tt').style.display='none';};
}
window.addEventListener('resize',()=>{if(chartState&&$('#results').style.display!=='none'){/* redraw on resize */
  const tl=chartState.timeline;drawChart(tl);}});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Packetlens local web dashboard.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000,
                        help="port (default 8000)")
    parser.add_argument("--debug", action="store_true", help="Flask debug mode")
    args = parser.parse_args()

    if args.host not in ("127.0.0.1", "localhost"):
        print("!! WARNING: binding to", args.host,
              "exposes the analyzer (and uploaded captures) to the network.")

    print(f"[+] Packetlens on http://{args.host}:{args.port}  "
          f"(max upload {MAX_UPLOAD_MB} MB)")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
