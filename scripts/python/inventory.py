#!/usr/bin/env python3
import argparse, json, socket, psutil, os
from datetime import datetime

def snapshot():
    procs = []
    for p in psutil.process_iter(attrs=["pid","name","username","cmdline","create_time"]):
        procs.append(p.info)
    conns = []
    for c in psutil.net_connections(kind="inet"):
        if c.laddr:
            conns.append({
                "laddr": f"{c.laddr.ip}:{c.laddr.port}",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                "status": c.status,
                "pid": c.pid
            })
    return {"processes": procs, "connections": conns}

def main():
    parser = argparse.ArgumentParser(description="Asset/process/network snapshot")
    parser.add_argument("--out", default="results/reports/inventory.json")
    args = parser.parse_args()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    data = {
        "host": socket.gethostname(),
        "generated_at": datetime.utcnow().isoformat()+"Z",
        "snapshot": snapshot()
    }
    with open(args.out, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[*] Wrote {args.out}")

if __name__ == "__main__":
    main()
