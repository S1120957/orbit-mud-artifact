"""Atomic SQLite snapshots. HMAC detects edits.
An external monotone floor can detect replay. MemoryFloor models this trust boundary. Missing/corrupt stores fail closed.
"""
import hashlib,hmac,json,sqlite3
from pathlib import Path

class StateError(RuntimeError):pass

class MemoryFloor:
    def __init__(self,value=0):self.value=value
    def advance(self,value):
        if value<self.value:raise StateError('external-floor-regression')
        self.value=value

class Store:
    def __init__(self,path=None,key:bytes=b'',bootstrap=False,floor=None):
        self.path=path;self.key=key;self.floor=floor;self.generation=0;self.data={};self.db=None
        if path is None:return
        if len(key)<32:raise StateError('provision an external integrity key')
        exists=Path(path).exists()
        if not exists and not bootstrap:raise StateError('missing-state-rebootstrap-required')
        try:
            self.db=sqlite3.connect(path)
            self.db.execute('PRAGMA journal_mode=DELETE');self.db.execute('PRAGMA synchronous=FULL')
            if not exists:
                self.db.execute('CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL, body BLOB NOT NULL, mac BLOB NOT NULL)')
                self.db.commit();self.save({})
            else:
                row=self.db.execute('SELECT generation,body,mac FROM state WHERE id=1').fetchone()
                if row is None:raise StateError('empty-state')
                g,b,m=row
                if not hmac.compare_digest(m,self._mac(g,b)):raise StateError('state-integrity')
                if floor is not None and g<floor.value:raise StateError('state-below-external-floor')
                self.generation=g;self.data=json.loads(b)
        except (sqlite3.DatabaseError,ValueError,KeyError) as ex:raise StateError('unreadable-state') from ex
    def _mac(self,g,b):return hmac.new(self.key,g.to_bytes(8,'big')+b,hashlib.sha256).digest()
    def save(self,data):
        b=json.dumps(data,sort_keys=True,separators=(',',':')).encode();g=self.generation+1
        if self.db is not None:
            try:
                self.db.execute('BEGIN IMMEDIATE')
                row=self.db.execute('SELECT generation FROM state WHERE id=1').fetchone()
                if row and row[0]!=self.generation:raise StateError('concurrent-writer')
                # Advance trusted counter BEFORE commit: a crash may force recovery, never silent rollback.
                if self.floor is not None:self.floor.advance(g)
                self.db.execute('INSERT OR REPLACE INTO state VALUES(1,?,?,?)',(g,b,self._mac(g,b)));self.db.commit()
            except Exception:
                self.db.rollback();raise
        self.data=json.loads(b);self.generation=g
    def close(self):
        if self.db is not None:self.db.close();self.db=None
