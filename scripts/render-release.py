#!/usr/bin/env python3
"""Render reviewable YAML only; never applies it. Exit 2 on invalid contract input."""
import argparse, json, pathlib, re, sys
import yaml
class UniqueLoader(yaml.SafeLoader): pass
def mapping(loader,node,deep=False):
 result={}
 for key,value in node.value:
  k=loader.construct_object(key,deep=deep)
  if k in result: raise ValueError('duplicate YAML key')
  result[k]=loader.construct_object(value,deep=deep)
 return result
UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,mapping)
REQUIRED={'NODE_NAME','NODE_IP','GUI_FQDN','DEMO_FQDN','SA_ISSUER','SERVER_IMAGE','ADMIN_IMAGE','BENCH_IMAGE','DEMO_IMAGE','PROMETHEUS_IMAGE','SOURCE_SHA','SERVER_VERSION'}
def render(template,values):
 def replace(m):
  k=m.group(1)
  if k not in REQUIRED or k not in values: raise ValueError('unknown or missing input: '+k)
  return values[k]
 raw=re.sub(r'\$\{([A-Z_]+)\}',replace,template)
 if '${' in raw or re.search(r'\b(?:IMAGE_TAG|RUN_ID|NODE_NAME|NODE_IP|GUI_FQDN|SA_ISSUER)\b',raw):raise ValueError('unresolved placeholder')
 docs=list(yaml.load_all(raw,Loader=UniqueLoader))
 def check(v):
  if isinstance(v,dict):
   for field in ('containers','initContainers','ephemeralContainers'):
    if field in v:
     if not isinstance(v[field],list) or not v[field]:raise ValueError('container list required')
     for container in v[field]:
      if not isinstance(container,dict) or not container.get('image'):raise ValueError('container image missing')
   for k,x in v.items():
    if k=='image' and (not isinstance(x,str) or not re.fullmatch(r'[\w./:-]+@sha256:[a-f0-9]{64}',x)):raise ValueError('image must have digest')
    check(x)
  elif isinstance(v,list):
   for x in v:check(x)
 for doc in docs:
  if isinstance(doc,dict):
   paths={'Pod':('spec',),'Deployment':('spec','template','spec'),'StatefulSet':('spec','template','spec'),'DaemonSet':('spec','template','spec'),'Job':('spec','template','spec'),'CronJob':('spec','jobTemplate','spec','template','spec')}
   if doc.get('kind') in paths:
    spec=doc
    for key in paths[doc['kind']]:
     if not isinstance(spec,dict):raise ValueError('workload spec missing')
     spec=spec.get(key)
    if not isinstance(spec,dict) or not spec.get('containers'):raise ValueError('workload containers missing')
  check(doc)
 return raw
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--values',required=True);p.add_argument('--templates',default='deploy/oci-single-node/templates');p.add_argument('--output',required=True);a=p.parse_args()
 values=json.loads(pathlib.Path(a.values).read_text())
 if set(values)!=REQUIRED:raise ValueError('input keys must exactly match contract')
 for k,v in values.items():
  if not isinstance(v,str) or not v or any(c in v for c in '\n\r\'"{}[]#'):raise ValueError('unsafe input '+k)
 for k in REQUIRED:
  if k.endswith('_IMAGE') and not re.fullmatch(r'[\w./:-]+@sha256:[a-f0-9]{64}',values[k]):raise ValueError('digest required: '+k)
 if not re.fullmatch('[a-f0-9]{40}',values['SOURCE_SHA']):raise ValueError('source SHA required')
 rendered={f.name:render(f.read_text(),values) for f in pathlib.Path(a.templates).glob('*.yaml')}
 if not rendered:raise ValueError('templates absent')
 out=pathlib.Path(a.output)
 if out.exists() and any(out.iterdir()):raise ValueError('output must be new/empty; existing release preserved')
 out.mkdir(parents=True,exist_ok=True)
 for name,raw in rendered.items():(out/name).write_text(raw)
 print('rendered',len(rendered),'files; no deployment performed')
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,yaml.YAMLError) as e:print(str(e),file=sys.stderr);sys.exit(2)
