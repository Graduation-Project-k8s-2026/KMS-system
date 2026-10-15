#!/usr/bin/env python3
"""Validate a supplied etcdctl --write-out=json range dump in memory. Never prints data."""
import argparse,base64,json,sys
PREFIX=b'k8s:enc:kms:v2:custom-kms:'
def verify(document,expected=None):
 if document.get('more'):raise ValueError('incomplete etcd range; pagination required')
 records=document.get('kvs',[])
 if 'count' in document and document['count']!=len(records):raise ValueError('etcd count mismatch')
 total=0
 seen=set()
 for entry in records:
  key=base64.b64decode(entry['key'],validate=True)
  if not key.startswith(b'/registry/secrets/'):continue
  if key in seen:raise ValueError('duplicate Secret key')
  seen.add(key)
  total+=1
  value=base64.b64decode(entry['value'],validate=True)
  if not value.startswith(PREFIX):raise ValueError('a current Secret is not encrypted with the expected KMS v2 provider')
 if not total:raise ValueError('no Secret records supplied')
 if expected is not None and total!=expected:raise ValueError('Secret count mismatch')
 return total
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',default='-');p.add_argument('--expected-count',type=int);a=p.parse_args()
 f=sys.stdin if a.input=='-' else open(a.input)
 count=verify(json.load(f),a.expected_count);print('verified encrypted Secret records:',count)
if __name__=='__main__':
 try:main()
 except Exception:print('FAIL: invalid, incomplete, or unencrypted Secret range',file=sys.stderr);sys.exit(1)
