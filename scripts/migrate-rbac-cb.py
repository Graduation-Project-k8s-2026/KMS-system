#!/usr/bin/env python3
"""C+B 키 소유 모델 이전 도구 (ADR-009). 서버에서 사람이 실행한다. 클러스터를 수정하지 않는다.

배경: 이전(모델 A)에는 SAR 네임스페이스가 "요청한 SA의 네임스페이스"였다. 새 규칙(C+B)에서는
  - 점이 없는 키(전역 키)는 SAR을 namespace 없이 보내므로 ClusterRole/ClusterRoleBinding만 효력이 있고,
  - <ns>.<name> 키는 <ns> 소유이며 그 네임스페이스의 Role/RoleBinding만 효력이 있다.
그래서 "점 없는 키에 대한 네임스페이스 Role/RoleBinding"은 새 서버에서 효력이 사라진다.

  check     효력이 사라지는 권한을 표로 출력한다 (resourceNames가 없는 Role은 경고).
  generate  같은 권한(키·verb·주체 그대로)을 주는 ClusterRole + ClusterRoleBinding 매니페스트를 파일로 만든다.
            적용(kubectl apply)은 하지 않는다. 기존 Role/RoleBinding은 지우지 않는다(되돌리기 대비).

입력: --input <파일>  (kubectl get roles,rolebindings,clusterroles,clusterrolebindings -A -o json 결과; 여러 번 가능)
      --input 이 없으면 kubectl 로 직접 읽는다 (읽기 전용 get 만 실행).
"""
import argparse, hashlib, json, pathlib, re, subprocess, sys

GROUP, RESOURCE = 'kms.local', 'keys'
VERBS = ('encrypt', 'decrypt', 'rewrap')
NAME_RE = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')


def load_items(paths, kubeconfig=None):
    items = []
    if paths:
        for p in paths:
            doc = json.loads(pathlib.Path(p).read_text())
            items += doc['items'] if doc.get('kind', '').endswith('List') else [doc]
    else:
        cmd = ['kubectl'] + (['--kubeconfig=' + kubeconfig] if kubeconfig else []) + [
            'get', 'roles,rolebindings,clusterroles,clusterrolebindings', '-A', '-o', 'json']
        items = json.loads(subprocess.run(cmd, check=True, capture_output=True).stdout)['items']
    return items


def kms_rules(rules):
    """kms.local/keys 규칙만 골라 (resourceNames, verbs)로 돌려준다. 와일드카드 여부도 함께."""
    out = []
    for r in rules or []:
        groups, res = r.get('apiGroups') or [], r.get('resources') or []
        if not (GROUP in groups or '*' in groups):
            continue
        if not (RESOURCE in res or '*' in res):
            continue
        verbs = r.get('verbs') or []
        wildcard_verbs = '*' in verbs
        out.append({'names': list(r.get('resourceNames') or []),
                    'verbs': sorted(VERBS if wildcard_verbs else [v for v in verbs if v in VERBS]),
                    'wild_group_or_resource': '*' in groups or '*' in res,
                    'wild_verbs': wildcard_verbs})
    return out


def subject_str(s, default_ns):
    if s.get('kind') == 'ServiceAccount':
        return 'ServiceAccount:%s/%s' % (s.get('namespace') or default_ns, s['name'])
    return '%s:%s' % (s.get('kind'), s['name'])


def analyze(items):
    """returns (grants, warnings, cluster_grants)
    grants: 네임스페이스 바인딩이 주는 권한 [{'ns','binding','key','verbs','subjects':[(kind,name,ns)]}]
    cluster_grants: ClusterRoleBinding이 이미 주는 권한 (이미 이전된 것 판별용)
    """
    roles, croles = {}, {}
    for it in items:
        k, md = it.get('kind'), it.get('metadata', {})
        if k == 'Role':
            roles[(md['namespace'], md['name'])] = it
        elif k == 'ClusterRole':
            croles[md['name']] = it
    grants, cgrants, warnings = [], [], []
    for it in items:
        k, md = it.get('kind'), it.get('metadata', {})
        if k not in ('RoleBinding', 'ClusterRoleBinding'):
            continue
        ref = it.get('roleRef', {})
        if ref.get('kind') == 'Role':
            role = roles.get((md.get('namespace'), ref['name']))
        else:
            role = croles.get(ref.get('name'))
        if not role:
            continue
        rules = kms_rules(role.get('rules'))
        if not rules:
            continue
        ns = md.get('namespace', '')
        subjects = [(s.get('kind'), s['name'], s.get('namespace') or ns) for s in it.get('subjects') or []]
        where = '%s/%s' % (ns, md['name']) if ns else md['name']
        for r in rules:
            if r['wild_group_or_resource'] or r['wild_verbs']:
                warnings.append('%s %s: 와일드카드(*) 규칙 — 자동 분석 대상 아님, 사람이 확인하세요' % (k, where))
            if not r['names']:
                if k == 'RoleBinding':
                    warnings.append('RoleBinding %s: resourceNames 없음(모든 키 허용 규칙). 새 규칙에서는 이 네임스페이스 소유 키(<ns>.*)에만 효력이 '
                                    '남고 전역 키 권한은 사라집니다. 필요한 키 이름을 확인해 명시하세요 (자동 생성 제외)' % where)
                else:
                    cgrants.append({'key': None, 'verbs': r['verbs'], 'subjects': subjects})
                continue
            for key in r['names']:
                g = {'ns': ns, 'binding': where, 'key': key, 'verbs': r['verbs'], 'subjects': subjects}
                (grants if k == 'RoleBinding' else cgrants).append(g)
    return grants, warnings, cgrants


def classify(g):
    """새 규칙에서의 효력: kept / lost / ignored"""
    key, ns = g['key'], g['ns']
    if '.' in key:
        owner = key.split('.', 1)[0]
        return ('kept', '소유 네임스페이스 바인딩') if owner == ns else ('ignored', '점 있는 키는 이전 모델에 존재할 수 없음(소유 ns 불일치)')
    if not NAME_RE.match(key):
        return 'ignored', '유효하지 않은 키 이름'
    return 'lost', '전역 키: 네임스페이스 바인딩은 효력 없음'


def covered(g, cgrants):
    """이미 ClusterRoleBinding이 같은 권한을 주고 있는가 (모든 subject, 모든 verb 기준)."""
    for s in g['subjects']:
        have = set()
        for c in cgrants:
            if (c['key'] in (None, g['key'])) and s in c['subjects']:
                have |= set(c['verbs'])
        if not set(g['verbs']) <= have:
            return False
    return True


def safe_name(key, verbs):
    base = 'kms-cb-%s-%s' % (key.lower().replace('_', '-'), '-'.join(verbs))
    if base != 'kms-cb-%s-%s' % (key, '-'.join(verbs)) or len(base) > 200:
        h = hashlib.sha256(('%s|%s' % (key, ','.join(verbs))).encode()).hexdigest()[:8]
        base = base[:180].rstrip('-') + '-' + h
    return base


def build_manifests(grants, cgrants):
    """lost 권한을 (키, verbs) 단위로 묶어 ClusterRole + ClusterRoleBinding 으로 만든다."""
    groups = {}
    skipped = []
    for g in grants:
        if classify(g)[0] != 'lost':
            continue
        if covered(g, cgrants):
            skipped.append(g)
            continue
        verbs = tuple(sorted(g['verbs']))
        if not verbs:
            continue
        groups.setdefault((g['key'], verbs), [])
        for s in g['subjects']:
            if s not in groups[(g['key'], verbs)]:
                groups[(g['key'], verbs)].append(s)
    docs = []
    for (key, verbs), subjects in sorted(groups.items()):
        name = safe_name(key, verbs)
        docs.append({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRole', 'metadata': {'name': name},
                     'rules': [{'apiGroups': [GROUP], 'resources': [RESOURCE], 'resourceNames': [key], 'verbs': list(verbs)}]})
        subs = []
        for kind, sname, ns in subjects:
            s = {'kind': kind, 'name': sname}
            if kind == 'ServiceAccount':
                s['namespace'] = ns
            else:
                s['apiGroup'] = 'rbac.authorization.k8s.io'
            subs.append(s)
        docs.append({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'ClusterRoleBinding', 'metadata': {'name': name},
                     'subjects': subs, 'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': name}})
    return docs, skipped


def render_table(grants, warnings, cgrants):
    lines = ['%-8s %-14s %-24s %-26s %s' % ('효력', '네임스페이스', '키', 'verbs', '주체 (바인딩)')]
    lost = 0
    for g in grants:
        status, why = classify(g)
        if status == 'lost' and covered(g, cgrants):
            status, why = 'covered', '이미 ClusterRoleBinding으로 같은 권한이 있음'
        lost += status == 'lost'
        lines.append('%-8s %-14s %-24s %-26s %s (%s) — %s' % (
            {'kept': '유지', 'lost': '사라짐', 'ignored': '무시', 'covered': '이전됨'}[status], g['ns'], g['key'], ','.join(g['verbs']),
            ', '.join(subject_str({'kind': k, 'name': n, 'namespace': ns}, g['ns']) for k, n, ns in g['subjects']), g['binding'], why))
    lines.append('')
    for w in warnings:
        lines.append('경고: ' + w)
    lines.append('요약: 효력이 사라지는 권한 %d건, 경고 %d건. 이전하려면 generate 로 ClusterRole/ClusterRoleBinding 을 만든 뒤 검토·적용하세요.' % (lost, len(warnings)))
    return '\n'.join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('mode', choices=['check', 'generate'])
    p.add_argument('--input', action='append', help='kubectl get ... -o json 결과 파일 (없으면 kubectl 로 읽음)')
    p.add_argument('--kubeconfig', help='kubectl 로 직접 읽을 때 사용할 kubeconfig 경로')
    p.add_argument('--output', help='generate: 매니페스트를 쓸 새 파일 경로 (기존 파일 덮어쓰기 거부)')
    a = p.parse_args(argv)
    grants, warnings, cgrants = analyze(load_items(a.input, a.kubeconfig))
    if a.mode == 'check':
        print(render_table(grants, warnings, cgrants))
        return 0
    if not a.output:
        print('generate 는 --output 이 필요합니다', file=sys.stderr)
        return 2
    out = pathlib.Path(a.output)
    if out.exists():
        print('출력 파일이 이미 있습니다 (덮어쓰지 않음): ' + a.output, file=sys.stderr)
        return 2
    import yaml
    docs, skipped = build_manifests(grants, cgrants)
    out.write_text('# 생성됨(scripts/migrate-rbac-cb.py). 적용 전에 사람이 검토하세요. 기존 Role/RoleBinding 은 지우지 않습니다.\n'
                   + yaml.safe_dump_all(docs, sort_keys=False, allow_unicode=True))
    for w in warnings:
        print('경고: ' + w, file=sys.stderr)
    print('ClusterRole/ClusterRoleBinding %d쌍 생성 -> %s (이미 이전된 %d건 제외). 적용은 하지 않았습니다.' % (len(docs) // 2, a.output, len(skipped)))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as e:
        print('오류: %s' % e, file=sys.stderr)
        sys.exit(2)
