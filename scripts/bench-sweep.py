#!/usr/bin/env python3
"""Concurrency/payload sweep over the fixed benchmark Jobs.

Reuses HostAdmin/execute from scripts/benchmark-release.py (same trusted host-loopback
boundary, same result-binding checks). Each (mode, concurrency, payload, repeat) is one
Job; failures are kept, never dropped. Prints a summary table and writes summary.csv.
"""
import argparse
import csv
import datetime
import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('benchrel', HERE / 'benchmark-release.py')
benchrel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchrel)


def ints(s):
    return [int(x) for x in s.split(',') if x]


def seconds(r):
    t = lambda v: datetime.datetime.fromisoformat(v.replace('Z', '+00:00'))
    return (t(r['ended_at']) - t(r['started_at'])).total_seconds()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True, help='new directory for per-run JSON and summary.csv')
    p.add_argument('--modes', default='transit,plugin,e2e')
    p.add_argument('--concurrency', default='1,4,16,32', help='comma list, each 1..32')
    p.add_argument('--payload', default='1024', help='comma list of bytes, each 1..1048576')
    p.add_argument('--count', type=int, default=2000, help='roundtrips per Job (transit/plugin)')
    p.add_argument('--e2e-count', type=int, default=500, help='roundtrips per Job for e2e (Secret create+get+delete)')
    p.add_argument('--repeats', type=int, default=1)
    a = p.parse_args()

    out = pathlib.Path(a.output)
    out.mkdir(parents=True, mode=0o755)  # fails if it exists: never overwrite earlier evidence
    client = benchrel.HostAdmin()
    rows, failed = [], False
    for rep in range(1, a.repeats + 1):
        for mode in a.modes.split(','):
            for conc in ints(a.concurrency):
                for size in ints(a.payload):
                    count = a.e2e_count if mode == 'e2e' else a.count
                    s = {'scenario': 'basic', 'op': 'roundtrip', 'count': count, 'concurrency': conc,
                         'payload_bytes': size, 'duration_seconds': 0}
                    row = benchrel.execute(client, mode, s)
                    name = f'{mode}-c{conc}-p{size}-r{rep}'
                    (out / (name + '.json')).write_text(json.dumps(row, indent=2))
                    r = row.get('result')
                    if row['state'] == 'succeeded' and r:
                        sec = seconds(r)
                        rps = r['success'] / sec if sec > 0 else 0
                        line = dict(mode=mode, concurrency=conc, payload=size, repeat=rep, state='ok',
                                    requests=r['requests'], errors=r['errors'], rps=round(rps, 1),
                                    p50_ms=round(r['p50_seconds'] * 1000, 3), p95_ms=round(r['p95_seconds'] * 1000, 3),
                                    p99_ms=round(r['p99_seconds'] * 1000, 3))
                        failed |= r['errors'] > 0
                    else:
                        line = dict(mode=mode, concurrency=conc, payload=size, repeat=rep, state=row['state'],
                                    requests='', errors='', rps='', p50_ms='', p95_ms='', p99_ms='')
                        failed = True
                    rows.append(line)
                    print(f"{name:28s} {line['state']:8s} rps={line['rps']} p50={line['p50_ms']}ms p99={line['p99_ms']}ms err={line['errors']}", flush=True)
    with open(out / 'summary.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f'\nsummary: {out / "summary.csv"}')
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('Sweep stopped: ' + str(e), file=sys.stderr)
        sys.exit(1)
