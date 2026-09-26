"""Separate administrative schema v1; serializable seat/device/refresh operations."""
import sqlite3,json,threading,os
from pathlib import Path
from contextlib import contextmanager
from licensing.contracts import Denied
KINDS=frozenset(('admin','tenant','user','plan','license','seat','device','enrollment','session','refresh','revocation','entitlement','lease','audit','code','challenge','fleet_agent','fleet_invite','fleet_nonce','fleet_command','fleet_idempotency','web_session','qa_login'))
class SqliteRepository:
    def __init__(self,path):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);self.local=threading.local()
        with self.transaction() as db:
            version=db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0,1): raise Denied('UNSUPPORTED_SCHEMA')
            db.execute('CREATE TABLE IF NOT EXISTS objects(kind TEXT NOT NULL,id TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(kind,id))')
            db.execute('PRAGMA user_version=1')
        if os.name!='nt': os.chmod(self.path,0o600)
    @contextmanager
    def transaction(self):
        if getattr(self.local,'db',None) is not None:
            yield self.local.db;return
        db=sqlite3.connect(self.path,timeout=10);self.local.db=db
        try:
            db.execute('BEGIN IMMEDIATE');yield db;db.commit()
        except BaseException: db.rollback();raise
        finally: self.local.db=None;db.close()
    def _kind(self,k):
        if k not in KINDS: raise Denied('INVALID_ENTITY')
    def put(self,kind,row):
        self._kind(kind)
        with self.transaction() as db: db.execute('INSERT OR REPLACE INTO objects VALUES(?,?,?)',(kind,row['id'],json.dumps(row,allow_nan=False)))
    def get(self,kind,identifier):
        self._kind(kind)
        with self.transaction() as db: row=db.execute('SELECT body FROM objects WHERE kind=? AND id=?',(kind,identifier)).fetchone()
        if not row: raise Denied('NOT_FOUND')
        return json.loads(row[0])
    def list(self,kind):
        self._kind(kind)
        with self.transaction() as db: rows=db.execute('SELECT body FROM objects WHERE kind=? ORDER BY id',(kind,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def delete(self,kind,identifier):
        self._kind(kind)
        with self.transaction() as db: db.execute('DELETE FROM objects WHERE kind=? AND id=?',(kind,identifier))
    def retain(self,kind,limit):
        self._kind(kind)
        with self.transaction() as db:
            db.execute('DELETE FROM objects WHERE kind=? AND rowid NOT IN (SELECT rowid FROM objects WHERE kind=? ORDER BY rowid DESC LIMIT ?)',(kind,kind,limit))
