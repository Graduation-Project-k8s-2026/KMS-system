"""Shared host operations: strict YAML, durable writes and output-redacted commands."""
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import time
import yaml

class UniqueLoader(yaml.SafeLoader):
    pass

def mapping(loader, node, deep=False):
    result = {}
    for key, value in node.value:
        k = loader.construct_object(key, deep=deep)
        if k in result:
            raise ValueError('duplicate YAML key')
        result[k] = loader.construct_object(value, deep=deep)
    return result
UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)

def load(raw):
    return yaml.load(raw, Loader=UniqueLoader)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def atomic(path, data, mode=0o600, owner=None):
    path = pathlib.Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), mode)
            if owner is not None: os.fchown(f.fileno(), *owner)
            f.write(data if isinstance(data, bytes) else data.encode())
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

def run(args, body=None, timeout=60):
    result = subprocess.run([str(x) for x in args], input=body, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(pathlib.Path(args[0]).name+' failed (output withheld)')
    return result.stdout

def kube(*args):
    return json.loads(run(['kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--request-timeout=15s', *args]))

def containers(name):
    items = json.loads(run(['crictl', '--runtime-endpoint=unix:///run/containerd/containerd.sock', 'ps', '-o', 'json']))['containers']
    return [x for x in items if x['metadata']['name'] == name]

def wait_stopped(names, timeout=150):
    end = time.monotonic()+timeout
    while any(containers(n) for n in names):
        if time.monotonic() >= end: raise RuntimeError('container termination timed out')
        time.sleep(2)

def flags(container):
    args = container.get('command', [])+container.get('args', [])
    result = {}
    for arg in args:
        if arg.startswith('--'):
            if '=' not in arg: raise ValueError('split-form flags require manual review')
            k, v = arg.split('=', 1)
            if k in result: raise ValueError('duplicate command flag')
            result[k] = v
    return result
