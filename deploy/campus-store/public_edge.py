#!/usr/bin/env python3
"""Supervise the demo HTTPS tunnel and atomically publish its exact origin.

No KMS access, no credentials, no Kubernetes API. Portal reads the origin file
on each request so an automatically restarted temporary tunnel can change URL.
"""
import os
from pathlib import Path
import re
import signal
import subprocess

ORIGIN = Path('/var/lib/campus-store-edge/public/origin')
BINARY = '/usr/local/libexec/campus-store-edge/cloudflared'


def main():
    os.umask(0o027)
    ORIGIN.parent.mkdir(parents=True, exist_ok=True)
    ORIGIN.unlink(missing_ok=True)
    process = subprocess.Popen([BINARY, 'tunnel', '--no-autoupdate', '--protocol', 'http2',
                                '--url', 'http://127.0.0.1:8300', '--metrics', '127.0.0.1:18301'],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    signal.signal(signal.SIGTERM, lambda *_: process.terminate())
    signal.signal(signal.SIGINT, lambda *_: process.terminate())
    published = False
    try:
        for line in process.stdout:
            match = re.search(r'https://[a-z0-9-]+\.trycloudflare\.com\b', line)
            if match and not published:
                temp = ORIGIN.with_suffix('.tmp')
                temp.write_text(match.group(0)+'\n')
                os.chmod(temp, 0o640)
                temp.replace(ORIGIN)
                print('Public HTTPS origin ready; path /store/.', flush=True)
                published = True
            elif 'Registered tunnel connection' in line:
                print('Public HTTPS tunnel connected.', flush=True)
        raise SystemExit(process.wait() or 1)
    finally:
        ORIGIN.unlink(missing_ok=True)
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=10)


if __name__ == '__main__':
    main()
