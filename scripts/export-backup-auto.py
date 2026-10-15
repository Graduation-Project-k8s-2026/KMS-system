#!/usr/bin/env python3
"""Export the completed final backup without an interactive password prompt.

The encrypted archive is Git-ignored. The generated password file is outside
the repository and must be backed up separately. Neither is printed to logs.
"""
import argparse
import hashlib
import json
import os
import pathlib
import secrets
import subprocess
import tarfile

from kms_ops import atomic


def digest(stream):
    h = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        h.update(chunk)
    return h.hexdigest()


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    if os.geteuid() != 0:
        raise ValueError('Run with sudo')
    repo = pathlib.Path(__file__).resolve().parent.parent
    home = pathlib.Path('/home/ubuntu')
    owner = (home.stat().st_uid, home.stat().st_gid)
    source = pathlib.Path('/var/backups/custom-kms/final-kms-v2-20261011T1616Z')
    destination = repo / '.backup-download'
    keydir = home / '.kms-backup-keys'
    for folder in (destination, keydir):
        if folder.is_symlink():
            raise ValueError('Directory must not be a symlink')
        folder.mkdir(mode=0o700, exist_ok=True)
        os.chmod(folder, 0o700)
        os.chown(folder, *owner)
    archive = destination / 'kms-final-v2-auto.tar.gpg'
    password = keydir / 'kms-final-v2-auto.password'
    partial = destination / '.kms-final-v2-auto.partial'
    if any(p.exists() or p.is_symlink() for p in (archive, password, partial)):
        raise ValueError('Existing export or key found; inspect before retrying')
    if not json.loads((source / 'state.json').read_text())['complete']:
        raise ValueError('Incomplete backup')
    expected = {}
    for path in sorted(source.rglob('*')):
        if path.is_symlink():
            raise ValueError('Backup contains a symlink')
        if path.is_file():
            with path.open('rb') as stream:
                expected[str(path.relative_to(source))] = digest(stream)
    for name, checksum in json.loads((source / 'checksums.json').read_text()).items():
        if pathlib.Path(name).name != name or expected.get(name) != checksum:
            raise ValueError('Backup checksum mismatch')
    # A random 384-bit password; never written inside the archive or repository.
    fd = os.open(password, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(secrets.token_urlsafe(48) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
        os.fchown(stream.fileno(), *owner)
    base = ['gpg', '--batch', '--no-symkey-cache', '--pinentry-mode', 'loopback',
            '--passphrase-file', str(password)]
    # Stream plaintext only through an anonymous pipe, never into a repo file.
    with partial.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        process = subprocess.Popen(base + ['--cipher-algo', 'AES256', '--symmetric'],
                                   stdin=subprocess.PIPE, stdout=output,
                                   stderr=subprocess.DEVNULL)
        try:
            with tarfile.open(fileobj=process.stdin, mode='w|') as tar:
                for name in expected:
                    tar.add(source / name, arcname=source.name + '/' + name, recursive=False)
        finally:
            process.stdin.close()
            encryption_status = process.wait()
        if encryption_status != 0:
            raise ValueError('Encryption failed; preserve the key and inspect partial output')
        output.flush()
        os.fsync(output.fileno())
    # Actually decrypt and hash every member before presenting the export.
    process = subprocess.Popen(base + ['--decrypt', str(partial)],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    seen = set()
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as tar:
            for member in tar:
                name = str(pathlib.PurePosixPath(member.name).relative_to(source.name))
                if not member.isfile() or name in seen or name not in expected:
                    raise ValueError('Unexpected archive member')
                with tar.extractfile(member) as stream:
                    if digest(stream) != expected[name]:
                        raise ValueError('Decrypted archive checksum mismatch')
                seen.add(name)
        # Drain to EOF so GPG verifies the integrity trailer before success.
        while process.stdout.read(1024 * 1024):
            pass
    finally:
        process.stdout.close()
        if process.poll() is None and seen != set(expected):
            process.terminate()
        returncode = process.wait()
    if returncode != 0 or seen != set(expected):
        raise ValueError('Decryption verification failed')
    os.chown(partial, *owner)
    os.link(partial, archive)
    partial.unlink()
    with archive.open('rb') as stream:
        checksum = digest(stream)
    atomic(pathlib.Path(str(archive) + '.sha256'), checksum + '  ' + archive.name + '\n', owner=owner)
    report = {'backup_id': source.name, 'archive': str(archive.relative_to(repo)),
              'bytes': archive.stat().st_size, 'sha256': checksum,
              'decrypted_members_verified': len(seen), 'encrypted': True,
              'password_stored_outside_repository': True,
              'external_transfer_verified': False}
    atomic(repo / 'docs/release/evidence/steps12-16/local-backup-export.json',
           json.dumps(report, indent=2) + '\n', 0o644, owner=owner)
    print(json.dumps(report, indent=2))
    print('Download the encrypted archive and keep the password file separately: ' + str(password))


if __name__ == '__main__':
    main()
