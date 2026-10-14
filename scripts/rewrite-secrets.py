#!/usr/bin/env python3
"""Later deployment stage only. Paginated Secret rewrites; dry-run unless --execute.
Requires a confirmed backup ID and KMS provider already connected. No Secret data is logged.
"""
import argparse,json,pathlib,subprocess,sys,urllib.parse,os
class Failure(Exception):pass
def kubectl(args,body=None):
 p=subprocess.run(['kubectl','--request-timeout=15s',*args],input=None if body is None else json.dumps(body),text=True,capture_output=True)
 if p.returncode:
  if 'Conflict' in p.stderr:raise Failure('conflict')
  raise Failure('Kubernetes request failed')
 return json.loads(p.stdout) if p.stdout.strip() else {}
def items(path):
 continuation=''
 while True:
  doc=kubectl(['get','--raw',path+'?'+urllib.parse.urlencode({'limit':100,'continue':continuation})])
  yield from doc.get('items',[])
  continuation=doc.get('metadata',{}).get('continue','')
  if not continuation:break
def replace(secret,backup):
 meta=secret['metadata'];ns,name=meta['namespace'],meta['name']
 for attempt in range(5):
  meta=secret['metadata'];meta.setdefault('annotations',{})['kms.local/rewrite-batch']=backup
  try: return kubectl(['replace','-f','-','-o','json'],secret)
  except Failure as e:
   if str(e)!='conflict' or attempt==4:raise
   secret=kubectl(['get','secret',name,'-n',ns,'-o','json'])
def checkpoint(path,done):
 tmp=path.with_suffix('.tmp');fd=os.open(tmp,os.O_CREAT|os.O_WRONLY|os.O_TRUNC,0o600)
 with os.fdopen(fd,'w') as f:json.dump(sorted(done),f);f.flush();os.fsync(f.fileno())
 os.replace(tmp,path)
 fd=os.open(path.parent,os.O_RDONLY);os.fsync(fd);os.close(fd)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--execute',action='store_true');p.add_argument('--backup-id');p.add_argument('--resume',required=True);a=p.parse_args()
 if a.execute and (not a.backup_id or not __import__('re').fullmatch('[a-zA-Z0-9_-]{1,80}',a.backup_id)):raise Failure('confirmed backup ID required')
 path=pathlib.Path(a.resume);done=set(json.loads(path.read_text())) if path.exists() else set();count=0
 for ns in items('/api/v1/namespaces'):
  name=ns['metadata']['name']
  for secret in items('/api/v1/namespaces/'+urllib.parse.quote(name,safe='')+'/secrets'):
   identity=name+'/'+secret['metadata']['name']
   if identity in done:continue
   if a.execute:replace(secret,a.backup_id);done.add(identity);checkpoint(path,done)
   count+=1
 print(('rewritten' if a.execute else 'dry-run candidate count'),count)
if __name__=='__main__':
 try:main()
 except Exception:print('rewrite failed; existing checkpoint preserved; no Secret data logged',file=sys.stderr);sys.exit(1)
