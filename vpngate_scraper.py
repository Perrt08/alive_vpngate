import base64
import csv
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from typing import List, Dict, Optional, Tuple


CSV_URL = "https://www.vpngate.net/api/iphone/"


def fetch_csv_text(url: str = CSV_URL) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="replace")


def iter_server_rows(csv_text: str) -> List[Dict[str, str]]:
    lines = csv_text.splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        if line.startswith("#HostName,IP,Score,"):
            header_idx = i
            break
    if header_idx is None:
        return []
    csv_block = "\n".join(lines[header_idx:])
    reader = csv.reader(io.StringIO(csv_block))
    rows = list(reader)
    if not rows:
        return []
    header = rows[0]
    records = []
    for row in rows[1:]:
        if not row or row[0].startswith("*") or row[0].startswith("#"):
            continue
        if len(row) < len(header):
            # Some rows may be truncated; skip them
            continue
        record = {header[i]: row[i] for i in range(len(header))}
        records.append(record)
    return records


def extract_tcp_ports_from_ovpn_b64(b64_config: str) -> Tuple[Optional[str], List[int]]:
    if not b64_config:
        return None, []
    try:
        config = base64.b64decode(b64_config).decode("utf-8", errors="replace")
    except Exception:
        return None, []
    proto = None
    ports: List[int] = []
    for line in config.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("proto "):
            val = line.split(" ", 1)[1].strip().lower()
            if val in ("tcp", "udp"):
                proto = val
        elif line.startswith("remote "):
            parts = line.split()
            if len(parts) >= 3:
                port_s = parts[2]
                if port_s.isdigit():
                    try:
                        ports.append(int(port_s))
                    except ValueError:
                        pass
    ports = sorted(set(ports))
    if proto != "tcp":
        return proto, []
    return proto, ports


def find_tcping_executable() -> Optional[str]:
    local_path = os.path.join(os.getcwd(), "tcping")
    if os.path.isfile(local_path):
        return local_path
    for dir_ in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(dir_, "tcping")
        if os.path.isfile(candidate):
            return candidate
    return None


def run_tcping(tcping_exe: str, ip: str, port: int, attempts: int = 3) -> Tuple[List[float], Optional[float]]:
    cmd = [tcping_exe, "-c", str(attempts), ip, str(port)]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=attempts * 10,
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        return []
    out = proc.stdout or ""
    times_ms: List[float] = []
    for line in out.splitlines():
        m = re.search(r"time=([0-9]+(?:\.[0-9]+)?)\s*ms", line)
        if m:
            try:
                times_ms.append(float(m.group(1)))
            except ValueError:
                pass
    avg_summary: Optional[float] = None
    m2 = re.search(r"rtt\s+min/avg/max:\s*([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms", out)
    if m2:
        try:
            avg_summary = float(m2.group(2))
        except ValueError:
            avg_summary = None
    return times_ms, avg_summary


def select_entries(records: List[Dict[str, str]], limit: int) -> List[Dict[str, str]]:
    # Sort by Score descending (string numeric)
    def score(rec: Dict[str, str]) -> int:
        try:
            return int(rec.get("Score", "0"))
        except Exception:
            return 0

    # Prefer records with OpenVPN TCP ports available
    with_ports = []
    without_ports = []
    for rec in records:
        _, ports = extract_tcp_ports_from_ovpn_b64(rec.get("OpenVPN_ConfigData_Base64", ""))
        if ports:
            rec["_OpenVPN_TCP_Ports"] = ports
            with_ports.append(rec)
        else:
            without_ports.append(rec)
    with_ports.sort(key=score, reverse=True)
    without_ports.sort(key=score, reverse=True)
    combined = with_ports + without_ports
    return combined[:limit]


def main():
    import argparse

    parser = argparse.ArgumentParser(description="抓取 VPNGate 存活主机并进行 tcping 测试")
    parser.add_argument("--limit", type=int, default=20, help="测试的服务器数量上限")
    parser.add_argument("--attempts", type=int, default=3, help="tcping 测试次数")
    parser.add_argument("--out", type=str, default="vpngate_alive.csv", help="输出 CSV 路径")
    args = parser.parse_args()

    tcping_exe = find_tcping_executable()
    if not tcping_exe:
        print("未找到 tcping，请将其放在当前目录或加入 PATH")
        sys.exit(1)

    print("正在获取服务器列表...")
    csv_text = fetch_csv_text()
    records = iter_server_rows(csv_text)
    if not records:
        print("未能解析服务器列表")
        sys.exit(1)

    entries = select_entries(records, args.limit)

    results_rows = []
    print(f"共选择 {len(entries)} 个服务器进行测试")

    for i, rec in enumerate(entries, 1):
        country = rec.get("CountryLong", "")
        ip = rec.get("IP", "")
        ports: List[int] = rec.get("_OpenVPN_TCP_Ports", []) or []

        # 如果无法从 OpenVPN 配置提取 TCP 端口，尽量猜测常见端口 443
        if not ports:
            ports = [443]

        for port in ports:
            print(f"[{i}] {country} {ip}:{port} 正在 tcping 测试 ({args.attempts} 次)...")
            times_ms, avg_sum = run_tcping(tcping_exe, ip, port, attempts=args.attempts)
            avg = avg_sum if avg_sum is not None else (sum(times_ms) / len(times_ms) if times_ms else None)
            status = "alive" if avg is not None else "dead"
            results_rows.append(
                {
                    "country": country,
                    "ip": ip,
                    "port": port,
                    "attempts": args.attempts,
                    "times_ms": json.dumps(times_ms, ensure_ascii=False),
                    "avg_ms": f"{avg:.3f}" if avg is not None else "",
                    "status": status,
                }
            )
            print(
                f"结果: status={status} times={times_ms} "
                + (f"avg={avg:.3f} ms" if avg is not None else "")
            )
            # 小睡避免对服务器过于频繁请求
            time.sleep(0.2)

    # 输出 CSV
    out_path = os.path.abspath(args.out)
    print(f"写入结果到 {out_path}")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["country", "ip", "port", "attempts", "times_ms", "avg_ms", "status"],
        )
        writer.writeheader()
        for row in results_rows:
            writer.writerow(row)

    # 控制台展示前若干条
    for row in results_rows[:10]:
        print(f"{row['country']} {row['ip']}:{row['port']} status={row['status']} avg={row['avg_ms']} ms")


if __name__ == "__main__":
    main()

