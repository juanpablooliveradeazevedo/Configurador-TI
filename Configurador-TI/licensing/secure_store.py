"""Atomic CurrentUser DPAPI storage; POSIX fallback requires explicit QA."""
import ctypes
from ctypes import wintypes
import json,os,tempfile,sys
from pathlib import Path
from .contracts import canonical,Denied
class DATA_BLOB(ctypes.Structure):
    _fields_=[('cbData',wintypes.DWORD),('pbData',ctypes.POINTER(ctypes.c_ubyte))]
def dpapi(data,decrypt=False):
    buf=(ctypes.c_ubyte*len(data)).from_buffer_copy(data)
    source,out=DATA_BLOB(len(data),buf),DATA_BLOB()
    crypt=ctypes.WinDLL('crypt32',use_last_error=True); kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    fn=crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    fn.argtypes=[ctypes.POINTER(DATA_BLOB),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(DATA_BLOB)]
    fn.restype=wintypes.BOOL; kernel.LocalFree.argtypes=[ctypes.c_void_p];kernel.LocalFree.restype=ctypes.c_void_p
    if not fn(ctypes.byref(source),None,None,None,None,1,ctypes.byref(out)): raise Denied('SECURE_STORE_UNAVAILABLE')
    try: return ctypes.string_at(out.pbData,out.cbData)
    finally: kernel.LocalFree(out.pbData)
class SecureStore:
    def __init__(self,path,*,qa=False):
        self.path,self.qa=Path(path),qa
        if os.name!='nt' and not qa: raise Denied('WINDOWS_SECURE_STORE_REQUIRED')
    def _safe(self):
        if getattr(sys,'_MEIPASS',None) and Path(sys._MEIPASS).resolve() in self.path.resolve().parents: raise Denied('INVALID_STORE_PATH')
        for p in (self.path,*self.path.parents):
            if p.is_symlink() or (hasattr(p,'is_junction') and p.is_junction()): raise Denied('INVALID_STORE_PATH')
    def read(self):
        self._safe()
        if not self.path.exists(): return {}
        if self.path.stat().st_size>131072: raise Denied('INVALID_CACHE')
        data=self.path.read_bytes()
        if os.name=='nt': data=dpapi(data,True)
        elif self.path.stat().st_mode & 0o077: raise Denied('INSECURE_QA_CACHE')
        try:
            result=json.loads(data)
            if not isinstance(result,dict): raise ValueError()
            return result
        except (ValueError,UnicodeError): raise Denied('INVALID_CACHE') from None
    def write(self,value):
        self._safe();self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        raw=canonical(value)
        if os.name=='nt': raw=dpapi(raw)
        fd,name=tempfile.mkstemp(dir=self.path.parent,prefix='.license-',suffix='.tmp')
        try:
            with os.fdopen(fd,'wb') as f: f.write(raw);f.flush();os.fsync(f.fileno())
            os.replace(name,self.path)
        finally:
            if os.path.exists(name): os.unlink(name)
