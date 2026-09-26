"""Fail-closed distribution branding check: paths, bytes and recursive ZIPs.

The retired marker is assembled for QA so it is not embedded literally in
the distributable source. No file contents are printed in diagnostics.
"""
import argparse
import io
import json
from pathlib import Path
import zipfile

_MARKER=bytes((67,83,84,73)).decode('ascii').lower()
_PATTERNS=tuple(_MARKER.encode(enc) for enc in ('ascii','utf-16-le','utf-16-be'))
_TEXT_SUFFIXES=frozenset(('.py','.pyw','.txt','.md','.json','.log','.patch','.cmd',
                        '.bat','.ps1','.qss','.css','.html','.xml','.sql','.ini',
                        '.yaml','.yml','.csv','.spec','.toml','.cfg'))
_VISUAL_SUFFIXES=frozenset(('.png','.jpg','.jpeg','.gif','.webp','.svg','.ico','.pdf'))

def scan(target):
    target=Path(target)
    result={'schema_version':1,'status':'PASS','path_occurrences':0,
            'text_occurrences':0,'binary_occurrences':0,'nested_archives':0,
            'files_scanned':0,'visual_assets':[],'findings':[],'errors':[]}
    expanded=[0]
    def path_check(name):
        count=name.casefold().count(_MARKER)
        if count:
            result['path_occurrences']+=count
            result['findings'].append({'path':name,'kind':'path','count':count})
    def payload(name,data,depth=0):
        result['files_scanned']+=1
        suffix=Path(name).suffix.lower()
        if suffix in _VISUAL_SUFFIXES:result['visual_assets'].append(name)
        count=sum(data.lower().count(pattern) for pattern in _PATTERNS)
        if count:
            key='text_occurrences' if suffix in _TEXT_SUFFIXES else 'binary_occurrences'
            result[key]+=count
            result['findings'].append({'path':name,'kind':key,'count':count})
        if suffix=='.zip' or data.startswith(b'PK\x03\x04'):
            if depth>=8:raise ValueError('ARCHIVE_DEPTH_LIMIT')
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                result['nested_archives']+=1
                # zipfile.read checks CRC; resource bounds fail closed.
                for member in z.infolist():
                    expanded[0]+=member.file_size
                    if member.file_size>512*1024*1024 or expanded[0]>1024*1024*1024:
                        raise ValueError('ARCHIVE_SIZE_LIMIT')
                    entry=name+'!/'+member.filename
                    path_check(entry)
                    if not member.is_dir():payload(entry,z.read(member),depth+1)
    try:
        path_check(target.name)
        if target.is_dir():
            for p in sorted(target.rglob('*')):
                name=(Path(target.name)/p.relative_to(target)).as_posix()
                path_check(name)
                if p.is_symlink():raise ValueError('SYMLINK_NOT_DISTRIBUTABLE')
                if p.is_file():payload(name,p.read_bytes())
        else:payload(target.name,target.read_bytes())
    except (OSError,ValueError,RuntimeError,zipfile.BadZipFile,NotImplementedError) as exc:
        result['errors'].append(type(exc).__name__)
    if result['findings'] or result['errors']:result['status']='FAIL'
    return result

def require_clean(target):
    result=scan(target)
    if result['status']!='PASS':raise ValueError('BRANDING_SCAN_FAILED')
    return result

def main(argv=None):
    p=argparse.ArgumentParser(description='Configurador TI — distribution branding gate')
    p.add_argument('target');p.add_argument('--output')
    a=p.parse_args(argv);result=scan(a.target)
    serialized=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if a.output:Path(a.output).write_text(serialized,encoding='utf-8')
    print(serialized,end='')
    return 0 if result['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
