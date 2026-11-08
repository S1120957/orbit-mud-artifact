"""Protocol objects and a manufacturer fixture with separate histories per class."""
from __future__ import annotations
from dataclasses import dataclass, asdict, replace
from .crypto import H, enc, scalar, public, commit, respond, signing_key, signing_public, sign, verify_sig
from .merkle import History, StatusTree, lh, verify_inclusion, verify_consistency

ZERO=b'\x00'*32

@dataclass(frozen=True)
class File:
    manufacturer:str
    cls:str
    url:str
    version:int
    policy:bytes
    signature:bytes=b''
    def body(self):return enc('ORBIT-FILE-v2',self.manufacturer,self.cls,self.url,self.version,self.policy)
    def digest(self):return H(self.body())

@dataclass(frozen=True)
class Leaf:
    index:int
    pub:bytes
    manufacturer:str
    cls:str
    epoch:int
    status:str='active'
    metadata:bytes=b''
    def body(self):return enc('ORBIT-LEAF-v2',self.index,self.pub,self.manufacturer,self.cls,self.epoch,self.status,H(enc('ORBIT-META-v2',self.metadata)))
    def digest(self):return lh(self.body())

@dataclass(frozen=True)
class Record:
    manufacturer:str
    cls:str
    version:int
    profile_digest:bytes
    epoch:int
    status_root:bytes
    population:int
    supported:bool
    emergency:bool
    valid_from:int
    valid_until:int
    previous:bytes
    sequence:int
    def body(self):return enc('ORBIT-RECORD-v2',*asdict(self).values())
    def digest(self):return H(self.body())

@dataclass(frozen=True)
class Checkpoint:
    manufacturer:str
    cls:str
    size:int
    root:bytes
    latest:bytes
    issued:int
    signature:bytes=b''
    endorsements:tuple=()
    def body(self):return enc('ORBIT-CP-v2',self.manufacturer,self.cls,self.size,self.root,self.latest,self.issued)
    def digest(self):return H(self.body())

@dataclass(frozen=True)
class Package:
    file:File
    record:Record
    checkpoint:Checkpoint
    log_index:int
    log_path:list[bytes]
    leaf:Leaf
    status_path:list[bytes]
    consistency:list[bytes]

@dataclass(frozen=True)
class Discover:
    url:str
    index:int
    epoch:int
    pub:bytes
    commitment:bytes

@dataclass(frozen=True)
class Offer:
    nonce:bytes
    lifecycle:bytes
    binding:bytes


def lifecycle(p:Package)->bytes:
    r=p.record
    return H(enc('ORBIT-LC-v2',p.checkpoint.digest(),r.status_root,r.profile_digest,r.version,r.epoch,r.sequence))

def transcript(xid:int,d:Discover,o:Offer)->bytes:
    return enc('ORBIT-POP-v2',xid,o.nonce,d.commitment,d.pub,d.index,H(d.url.encode()),o.lifecycle,o.binding)

def witness_body(identity:str,cp:Checkpoint)->bytes:
    return enc('ORBIT-WITNESS-v2',identity,cp.digest())

class Device:
    def __init__(self,index:int,url:str,epoch:int=1,key:int|None=None):
        self.index=index;self.url=url;self.epoch=epoch;self.key=key or scalar();self.pub=public(self.key)
        self.r=None;self.discover=None;self.answer=None
    def start(self)->Discover:
        self.r,R=commit();self.answer=None
        self.discover=Discover(self.url,self.index,self.epoch,self.pub,R)
        return self.discover
    def answer_offer(self,xid:int,offer:Offer)->int:
        if self.discover is None or self.r is None:raise ValueError('no active device session')
        t=transcript(xid,self.discover,offer)
        if self.answer is not None:
            if self.answer[0]!=t:raise ValueError('nonce already used for a different transcript')
            return self.answer[1]
        z=respond(self.key,self.r,t);self.answer=t,z;return z

class Witness:
    def __init__(self,name:str,key=None):
        self.name=name;self.key=key or signing_key();self.pub=signing_public(self.key);self.seen={}
    def endorse(self,cp:Checkpoint,manufacturer_pub:bytes,proof:list[bytes],now:int,max_age:int=3600):
        if not verify_sig(manufacturer_pub,cp.body(),cp.signature) or not 0<=now-cp.issued<=max_age:
            raise ValueError('witness signature/time')
        key=(cp.manufacturer,cp.cls);old=self.seen.get(key)
        if old and not verify_consistency(old.size,cp.size,old.root,cp.root,proof):
            raise ValueError('witness prefix')
        self.seen[key]=cp
        return self.name,sign(self.key,witness_body(self.name,cp))

class Manufacturer:
    def __init__(self,n=8,now=1_700_000_000,cls='gateway',key=None):
        self.name='manufacturer-A';self.cls=cls;self.key=key or signing_key();self.pub=signing_public(self.key)
        self.url='https://example.invalid/mud/gateway-v1.json'
        self.devices=[Device(i,self.url) for i in range(n)]
        self.leaves=[Leaf(i,d.pub,self.name,cls,1) for i,d in enumerate(self.devices)]
        self.status=StatusTree([l.digest() for l in self.leaves]);self.history=History();self.records=[];self.cps=[];self.files=[]
        self.publish(now)
    def publish(self,now:int,version:int|None=None,epoch:int|None=None,supported=True,emergency=False,valid_from:int|None=None,valid_until:int|None=None):
        last=self.records[-1] if self.records else None
        v=version if version is not None else (last.version if last else 1)
        e=epoch if epoch is not None else (last.epoch if last else 1)
        if last is not None and e!=last.epoch:
            self.leaves=[replace(l,epoch=e) for l in self.leaves];self.status=StatusTree([l.digest() for l in self.leaves])
        f=File(self.name,self.cls,self.url,v,b'allow:manufacturer-service;deny:other')
        f=replace(f,signature=sign(self.key,f.body()))
        r=Record(self.name,self.cls,v,f.digest(),e,self.status.root,len(self.leaves),supported,emergency,
                 now-60 if valid_from is None else valid_from,now+3600 if valid_until is None else valid_until,
                 last.digest() if last else ZERO,len(self.records)+1)
        self.history.append(r.body());self.records.append(r);self.files.append(f)
        cp=Checkpoint(self.name,self.cls,len(self.records),self.history.root(),r.digest(),now)
        cp=replace(cp,signature=sign(self.key,cp.body()));self.cps.append(cp)
        return cp
    def set_status(self,index:int,status:str):
        if status not in ('active','revoked','suspended'):raise ValueError('status')
        self.leaves[index]=replace(self.leaves[index],status=status);self.status.update(index,self.leaves[index].digest())
    def endorse(self,witnesses:list[Witness],now:int):
        cp=self.cps[-1];endorsements=[]
        for w in witnesses:
            old=w.seen.get((self.name,self.cls));proof=self.history.consistency(old.size) if old else []
            endorsements.append(w.endorse(cp,self.pub,proof,now))
        self.cps[-1]=replace(cp,endorsements=tuple(endorsements))
    def package(self,index:int=0,old_size:int=0)->Package:
        cp=self.cps[-1]
        return Package(self.files[-1],self.records[-1],cp,cp.size-1,self.history.inclusion(cp.size-1),
                       self.leaves[index],self.status.proof(index),self.history.consistency(old_size) if old_size else [])

# Explicit JSON conversion for local TCP fixtures. No pickle or dynamic imports.
_TYPES={x.__name__:x for x in (File,Leaf,Record,Checkpoint,Package,Discover,Offer)}
def to_wire(x):
    if isinstance(x,bytes):return {'bytes':x.hex()}
    if type(x).__name__ in _TYPES:return {'type':type(x).__name__,'fields':{k:to_wire(v) for k,v in x.__dict__.items()}}
    if isinstance(x,(tuple,list)):return [to_wire(v) for v in x]
    if isinstance(x,dict):return {k:to_wire(v) for k,v in x.items()}
    return x

def from_wire(x):
    if isinstance(x,list):return [from_wire(v) for v in x]
    if isinstance(x,dict):
        if set(x)=={'bytes'}:return bytes.fromhex(x['bytes'])
        if set(x)=={'type','fields'}:
            cls=_TYPES[x['type']];return cls(**{k:from_wire(v) for k,v in x['fields'].items()})
        return {k:from_wire(v) for k,v in x.items()}
    return x
