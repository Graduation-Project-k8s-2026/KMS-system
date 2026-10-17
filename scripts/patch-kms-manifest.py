#!/usr/bin/env python3
"""운영 KMS static pod 매니페스트를 '렌더하지 않고' 현재 파일에서 필요한 항목만 부분 수정한다.

운영 파일에는 템플릿에 없는 tmp emptyDir, resources가 있고 YAML이 flow 스타일(`- {name: X, value: Y}`)이라 다시 렌더하면
차이가 커진다. 이 도구는 텍스트에서 필요한 줄만 바꾸거나 더하고(원래 서식 유지), 결과를 YAML로 다시 읽어 의도한 항목이 모두
있는지 검증한 뒤에만 출력 파일을 쓴다. 입력 파일은 절대 수정하지 않는다. 바뀐 줄만 diff로 표준 출력에 보여 준다.

바꾸는 항목:
  1. 이미지 (--image 를 줬을 때)
  2. KMS_SEAL_TYPE → KMS_SEAL_ALLOWED=shamir
  3. KMS_TRANSIT_AUDIT_DIR env + transit-audit 마운트·볼륨 (호스트 디렉터리는 미리 만들어 둘 것)
  4. 외부 리스너 env (KMS_EXTERNAL_*; --no-external 이면 건너뜀)
이미 적용된 항목은 건너뛴다 (두 번 실행해도 같은 결과). 값이 다르게 이미 있으면 그대로 두고 경고만 한다.

사용: patch-kms-manifest.py --input /etc/kubernetes/manifests/kms-static-pod.yaml --output ./kms-static-pod.new.yaml [--image 이름@sha256:...]
"""
import argparse, difflib, os, pathlib, re, shutil, sys
import yaml

ENVS_CORE = [("KMS_SEAL_ALLOWED", "shamir"), ("KMS_TRANSIT_AUDIT_DIR", "/transit-audit")]
ENVS_EXTERNAL = [("KMS_EXTERNAL_ADDR", "0.0.0.0:9443"), ("KMS_EXTERNAL_SUBJECT_NAMESPACES", "kms-external"),
                 ("KMS_EXTERNAL_KEY_NAMESPACES", "kms-external"), ("KMS_EXTERNAL_RPS", "20"),
                 ("KMS_EXTERNAL_BURST", "40"), ("KMS_EXTERNAL_AUTHFAIL_MAX", "10")]
MOUNT = {"name": "transit-audit", "mountPath": "/transit-audit"}
VOLUME = {"name": "transit-audit", "hostPath": {"path": "/var/lib/custom-kms/transit-audit", "type": "Directory"}}
IMAGE_RE = re.compile(r"^[\w./:-]+@sha256:[a-f0-9]{64}$")


class PatchError(Exception):
    pass


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def find_key(lines, key, start=0):
    """`<key>:` 만 있는 줄 (리스트 시작)의 인덱스. 없으면 -1."""
    pat = re.compile(r"^\s*" + re.escape(key) + r":\s*(#.*)?$")
    for i in range(start, len(lines)):
        if pat.match(lines[i]):
            return i
    return -1


def list_span(lines, key_idx):
    """key 줄 다음에 오는 리스트 항목 전체의 (첫 줄, 마지막 줄+1). 빈 줄·주석은 끝에서 제외."""
    key_indent = indent_of(lines[key_idx])
    first = key_idx + 1
    # 리스트 항목의 들여쓰기 (key와 같거나 더 깊을 수 있다)
    j = first
    while j < len(lines) and (not lines[j].strip() or lines[j].lstrip().startswith("#")):
        j += 1
    if j >= len(lines) or not lines[j].lstrip().startswith("- "):
        raise PatchError("리스트 항목을 찾지 못했어요: " + lines[key_idx].strip())
    item_indent = indent_of(lines[j])
    end = j
    k = j
    while k < len(lines):
        ln = lines[k]
        if not ln.strip() or ln.lstrip().startswith("#"):
            k += 1
            continue
        ind = indent_of(ln)
        if ind > item_indent or (ind == item_indent and ln.lstrip().startswith("- ")):
            end = k + 1
            k += 1
            continue
        if ind == item_indent and key_indent == item_indent:
            break  # key와 항목이 같은 들여쓰기이고 '- '로 시작하지 않으면 다음 키
        break
    return j, end, item_indent


def needs_quote(v):
    """YAML에서 일반 문자열로 읽히지 않을 값(숫자처럼 보이는 값, ':'나 '#'가 든 값)만 따옴표로 감싼다."""
    return isinstance(v, str) and (re.fullmatch(r"[0-9][0-9._eE+-]*", v) is not None or ":" in v or " #" in v or v == "" or v.lower() in ("true", "false", "null", "yes", "no", "on", "off"))


def q(v):
    return "'" + str(v).replace("'", "''") + "'"


def render_item(style, indent, item):
    pad = " " * indent
    if style == "flow":
        def fl(v):
            if isinstance(v, dict):
                return "{" + ", ".join("%s: %s" % (k, fl(x)) for k, x in v.items()) + "}"
            return q(v) if needs_quote(v) else str(v)
        return [pad + "- " + fl(item)]
    out = []
    def blk(d, ind, first):
        for n, (k, v) in enumerate(d.items()):
            lead = (pad + "- ") if (first and n == 0) else " " * ind
            if isinstance(v, dict):
                out.append("%s%s:" % (lead, k)); blk(v, ind + 2, False)
            else:
                out.append("%s%s: %s" % (lead, k, q(v) if needs_quote(v) else v))
    blk(item, indent + 2, True)
    return out


def item_style(lines, first_idx):
    return "flow" if re.match(r"^\s*- \{", lines[first_idx]) else "block"


def append_item(lines, key, item, scope_start=0):
    ki = find_key(lines, key, scope_start)
    if ki < 0:
        raise PatchError("%s: 목록을 찾지 못했어요" % key)
    first, end, ind = list_span(lines, ki)
    new = render_item(item_style(lines, first), ind, item)
    lines[end:end] = new
    return new


def doc_of(lines):
    return yaml.safe_load("\n".join(lines) + "\n")


def patch(text, image=None, external=True):
    lines = text.rstrip("\n").split("\n")
    doc = doc_of(lines)
    try:
        container = doc["spec"]["containers"][0]
    except (KeyError, IndexError, TypeError):
        raise PatchError("static pod 형식이 아니에요 (spec.containers[0] 없음)")
    notes = []
    env = {e["name"]: e.get("value") for e in container.get("env", [])}

    # 1. 이미지
    if image:
        if not IMAGE_RE.match(image):
            raise PatchError("이미지는 이름@sha256:<64 hex> 형식이어야 해요")
        if container.get("image") == image:
            notes.append("이미지: 이미 같은 값 — 건너뜀")
        else:
            idx = [i for i, l in enumerate(lines) if re.match(r"^\s*image:\s", l)]
            if not idx:
                raise PatchError("image 줄을 찾지 못했어요")
            lines[idx[0]] = re.sub(r"(image:\s*).*$", lambda m: m.group(1) + image, lines[idx[0]])

    # 2. KMS_SEAL_TYPE → KMS_SEAL_ALLOWED
    if "KMS_SEAL_TYPE" in env:
        flow = [i for i, l in enumerate(lines) if re.search(r"name:\s*KMS_SEAL_TYPE\b", l) and "{" in l]
        blk = [i for i, l in enumerate(lines) if re.match(r"^\s*- name:\s*KMS_SEAL_TYPE\s*$", l)]
        have_allowed = "KMS_SEAL_ALLOWED" in env
        if flow:
            i = flow[0]
            if have_allowed:
                del lines[i]
            else:
                lines[i] = re.sub(r"\{.*\}", "{name: KMS_SEAL_ALLOWED, value: shamir}", lines[i])
        elif blk:
            i = blk[0]
            ind = indent_of(lines[i])
            if i + 1 >= len(lines) or not re.match(r"^\s*value:", lines[i + 1]):
                raise PatchError("KMS_SEAL_TYPE 항목의 value 줄을 찾지 못했어요")
            if have_allowed:
                del lines[i:i + 2]
            else:
                lines[i] = " " * ind + "- name: KMS_SEAL_ALLOWED"
                lines[i + 1] = re.sub(r"value:.*$", "value: shamir", lines[i + 1])
        else:
            raise PatchError("KMS_SEAL_TYPE 줄 형식을 알아보지 못했어요")
        doc = doc_of(lines); container = doc["spec"]["containers"][0]
        env = {e["name"]: e.get("value") for e in container.get("env", [])}

    # 3·4. env 추가
    wanted = ENVS_CORE + (ENVS_EXTERNAL if external else [])
    env_key_idx = find_key(lines, "env")
    for name, value in wanted:
        if name in env:
            if str(env[name]) != value:
                notes.append("%s: 이미 %r 로 설정돼 있어 그대로 둠 (권장값 %r)" % (name, env[name], value))
            continue
        append_item(lines, "env", {"name": name, "value": value}, env_key_idx)
        env[name] = value

    # 마운트·볼륨
    mounts = [m.get("name") for m in container.get("volumeMounts", [])]
    if "transit-audit" not in mounts:
        append_item(lines, "volumeMounts", MOUNT)
    vols = [v.get("name") for v in doc["spec"].get("volumes", [])]
    if "transit-audit" not in vols:
        append_item(lines, "volumes", VOLUME)

    # 검증: 다시 읽어서 의도한 항목이 모두 있고 원래 항목이 사라지지 않았는지 확인
    new_doc = doc_of(lines)
    nc = new_doc["spec"]["containers"][0]
    nenv = {e["name"]: e.get("value") for e in nc.get("env", [])}
    for name, value in wanted:
        if name not in nenv:
            raise PatchError("검증 실패: env %s 가 결과에 없어요 (출력하지 않음)" % name)
    if "KMS_SEAL_TYPE" in nenv:
        raise PatchError("검증 실패: KMS_SEAL_TYPE 가 남아 있어요")
    if "transit-audit" not in [m["name"] for m in nc.get("volumeMounts", [])] or \
       "transit-audit" not in [v["name"] for v in new_doc["spec"].get("volumes", [])]:
        raise PatchError("검증 실패: transit-audit 마운트/볼륨이 결과에 없어요")
    old_names = {e["name"] for e in container.get("env", [])} - {"KMS_SEAL_TYPE"}
    if not old_names <= set(nenv):
        raise PatchError("검증 실패: 기존 env가 사라졌어요")
    for key in ("volumeMounts",):
        if not {m["name"] for m in container.get(key, [])} <= {m["name"] for m in nc.get(key, [])}:
            raise PatchError("검증 실패: 기존 마운트가 사라졌어요")
    if not {v["name"] for v in doc["spec"].get("volumes", [])} <= {v["name"] for v in new_doc["spec"].get("volumes", [])}:
        raise PatchError("검증 실패: 기존 볼륨이 사라졌어요")
    if doc["spec"]["containers"][0].get("resources") != nc.get("resources"):
        raise PatchError("검증 실패: resources 가 바뀌었어요")
    return "\n".join(lines) + "\n", notes


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--image")
    p.add_argument("--no-external", action="store_true", help="외부 리스너 env를 추가하지 않는다")
    a = p.parse_args(argv)
    src, dst = pathlib.Path(a.input), pathlib.Path(a.output)
    if src.resolve() == dst.resolve():
        raise PatchError("입력과 출력이 같은 파일이에요 (원본은 수정하지 않아요)")
    old = src.read_text()
    new, notes = patch(old, a.image, not a.no_external)
    diff = list(difflib.unified_diff(old.splitlines(), new.splitlines(), "원본", "수정본", lineterm="", n=0))
    tmp = dst.with_name("." + dst.name + ".tmp")
    tmp.write_text(new)
    shutil.copymode(src, tmp)
    os.replace(tmp, dst)
    print("\n".join(diff) if diff else "변경 없음 (이미 모두 적용됨)")
    for n in notes:
        print("참고: " + n, file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (PatchError, OSError, yaml.YAMLError) as e:
        print("오류: %s" % e, file=sys.stderr)
        sys.exit(2)
