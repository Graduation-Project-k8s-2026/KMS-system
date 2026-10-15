#!/usr/bin/env python3
"""Summarize distinct benchmark modes without dropping failed trials; optionally plot with matplotlib."""
import argparse
import datetime
import json
import pathlib
import statistics

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--directory',default='docs/release/benchmark');p.add_argument('--plot',action='store_true');a=p.parse_args();root=pathlib.Path(a.directory)
    rows=[]
    for provider,folder in [('identity','identity-baseline'),('kms-v2','kms-v2')]:
        for mode in ['transit','plugin','e2e']:
            trials=[json.loads(f.read_text()) for f in sorted((root/folder).glob('*-'+mode+'.json'))]
            if not trials:continue
            good=[t['result'] for t in trials if t['result'] is not None]
            digests={r['image_digest'] for r in good}
            specs={json.dumps(t['spec'],sort_keys=True) for t in trials}
            if len(digests)!=1 or len(specs)!=1:raise ValueError('mixed benchmark conditions')
            rates=[]
            for r in good:
                seconds=(datetime.datetime.fromisoformat(r['ended_at'])-datetime.datetime.fromisoformat(r['started_at'])).total_seconds()
                rates.append(r['success']/seconds)
            row={'provider':provider,'mode':mode,'trials':len(trials),'failed_trials':sum(t['state']!='succeeded' for t in trials),'errors':sum(r['errors'] for r in good),'requests':sum(r['requests'] for r in good),'mean_roundtrips_per_second':statistics.mean(rates),'stdev_roundtrips_per_second':statistics.stdev(rates) if len(rates)>1 else None,'mean_trial_p95_ms':statistics.mean(r['p95_seconds']*1000 for r in good),'mean_trial_p99_ms':statistics.mean(r['p99_seconds']*1000 for r in good),'image_digest':next(iter(digests)),'spec':trials[0]['spec']}
            rows.append(row)
    (root/'summary.json').write_text(json.dumps(rows,indent=2)+'\n')
    lines=['# 반복 성능 시험','', '같은 ARM64 단일 노드, 같은 bench image digest, 모드별 100회 왕복·동시성 1·1024 bytes·3회 반복. `identity`는 apiserver KMS 연결 전, `kms-v2`는 연결·identity 제거·KEK 회전 후다. Transit/Plugin은 두 조건 모두 KMS 서비스를 사용한다.','', '| apiserver 저장 | 모드 | 반복 | 요청/오류 | 평균 왕복/s ± 표본 SD | 반복별 p95 평균(ms) |', '|---|---|---:|---:|---:|---:|']
    for r in rows:lines.append(f"| {r['provider']} | {r['mode']} | {r['trials']} | {r['requests']}/{r['errors']} | {r['mean_roundtrips_per_second']:.2f} ± {r['stdev_roundtrips_per_second']:.2f} | {r['mean_trial_p95_ms']:.3f} |")
    lines += ['', '## 해석 범위', '', '- `requests`는 왕복 수다. Transit/Plugin은 encrypt+decrypt, E2E는 Secret create+get+delete이며 서로 다른 경로다.', '- 평균 p95는 각 trial p95의 평균이며, 원시 표본을 합친 pooled p95가 아니다. 3회 반복만으로 모집단 신뢰구간·일반 성능 우열을 주장하지 않는다.', '- 신뢰된 호스트 관리자 loopback으로 Job을 생성했다. 실제 Job·projected token·TLS ingest는 사용했지만 Tailscale 사람 로그인 시연은 이 시험에 포함되지 않는다.', '- 같은 노드의 apiserver·etcd·Prometheus·KMS가 자원을 공유한다. 운영 검증 조회/재쓰기와 일부 시간대가 겹치므로 정밀한 독립 환경 실험이 아니다.', '- 오류와 실패한 trial도 JSON/통계에 보존한다. 이번 18개 trial의 상세 JSON은 두 하위 디렉터리에 있다.', '', '## Seal 실험', '', '`seal-lab.jsonl`은 `CGO_ENABLED=1 go run -tags=tpm_lab ./cmd/seal-lab --repeats 5`의 실제 출력이다. Shamir는 3-of-5 조각이 이미 준비된 처리 시간만 측정한다. Dev는 개발 baseline, TPM은 소프트웨어 simulator, K8sSeal은 fake client이며 실물 TPM·별도 실제 클러스터의 성능으로 해석하지 않는다. 운영 k8s-secrets 저장소는 사용하지 않았다.']
    (root/'README.md').write_text('\n'.join(lines)+'\n')
    if a.plot:
        import matplotlib;matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        fig,axes=plt.subplots(1,3,figsize=(10,3.4))
        for ax,mode in zip(axes,['transit','plugin','e2e']):
            rr=[r for r in rows if r['mode']==mode]
            ax.bar([r['provider'] for r in rr],[r['mean_roundtrips_per_second'] for r in rr],yerr=[r['stdev_roundtrips_per_second'] or 0 for r in rr],capsize=5,color=['#718096','#2563eb'])
            ax.set_title(mode);ax.set_ylabel('successful roundtrips / second');ax.set_ylim(bottom=0)
        fig.suptitle('3 trials × 100 roundtrips, 1 worker, 1024 bytes; error bars = sample SD')
        fig.tight_layout();fig.savefig(root/'throughput.png',dpi=180);fig.savefig(root/'throughput.svg');plt.close(fig)
    print('Summaries written; raw trial records retained.')
if __name__=='__main__':main()
