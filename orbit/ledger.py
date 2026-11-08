"""Static-view, safety-first quorum finalizer (3 of 4 for f<=1).
Two signed phases, durable prepare locks, finalized-parent and lifecycle-prefix checks.
"""
from __future__ import annotations
from dataclasses import dataclass
import copy
from .crypto import H,enc,sign,verify_sig,signing_key,signing_public
from .merkle import History,lh,verify_inclusion,verify_consistency
from .model import Package,Checkpoint,Record,ZERO,to_wire,from_wire,_TYPES
from .storage import Store

CHAIN='ORBIT-REFERENCE-v2';EPOCH=1

@dataclass(frozen=True)
class Header:
    chain:str
    epoch:int
    height:int
    previous:bytes
    root:bytes
    count:int
    def body(self):return enc('ORBIT-BLOCK-v2',self.chain,self.epoch,self.height,self.previous,self.root,self.count)
    def digest(self):return H(self.body())

@dataclass(frozen=True)
class Proposal:
    header:Header
    packages:list[Package]

@dataclass(frozen=True)
class Vote:
    identity:str
    stage:str
    signature:bytes

@dataclass(frozen=True)
class Block:
    header:Header
    commits:list[Vote]

@dataclass(frozen=True)
class Anchor:
    chain:list[Block]
    index:int
    path:list[bytes]

_TYPES.update({x.__name__:x for x in (Header,Proposal,Vote,Block,Anchor)})

def anchor_body(cp:Checkpoint):
    return enc('ORBIT-ANCHOR-v2',cp.manufacturer,cp.cls,cp.digest(),cp.root,cp.size)

def vote_body(identity,stage,h):
    return enc('ORBIT-VOTE-v2',identity,stage,h.chain,h.epoch,h.height,h.digest())

def votes_valid(votes,stage,h,pubs,q=3):
    seen=set()
    for v in votes:
        if v.stage!=stage or v.identity in seen:continue
        pub=pubs.get(v.identity)
        if pub and verify_sig(pub,vote_body(v.identity,stage,h),v.signature):seen.add(v.identity)
    return len(seen)>=q

def validate_record_package(p:Package,pubs:dict)->bool:
    cp=p.checkpoint;r=p.record
    pub=pubs.get(cp.manufacturer)
    return bool(pub and (cp.manufacturer,cp.cls)==(r.manufacturer,r.cls)
      and verify_sig(pub,cp.body(),cp.signature)
      and r.sequence==cp.size and p.log_index==cp.size-1 and cp.latest==r.digest()
      and verify_inclusion(lh(r.body()),p.log_index,cp.size,p.log_path,cp.root))

def make_proposal(packages:list[Package],height=1,previous=ZERO)->Proposal:
    if not packages:raise ValueError('empty batch')
    t=History()
    for p in packages:t.append(anchor_body(p.checkpoint))
    return Proposal(Header(CHAIN,EPOCH,height,previous,t.root(),len(packages)),list(packages))

def make_anchor(proposal:Proposal,chain:list[Block],index=0)->Anchor:
    t=History()
    for p in proposal.packages:t.append(anchor_body(p.checkpoint))
    return Anchor(list(chain),index,t.inclusion(index))

class Validator:
    def __init__(self,name,manufacturer_pubs,validator_pubs,key=None,store=None):
        self.name=name;self.key=key or signing_key();self.pub=signing_public(self.key)
        self.manufacturers=manufacturer_pubs;self.pubs=validator_pubs;self.store=store or Store()
        if len(validator_pubs)!=4:raise ValueError('reference requires four configured validators')
        self.state=copy.deepcopy(self.store.data) or {'height':0,'head':ZERO.hex(),'locks':{},'classes':{}}
    def _validate(self,p):
        h=p.header
        if h.chain!=CHAIN or h.epoch!=EPOCH:raise ValueError('wrong-chain-or-epoch')
        if h.height!=self.state['height']+1 or h.previous.hex()!=self.state['head']:
            raise ValueError('not-next-finalized-parent')
        if h.count!=len(p.packages) or make_proposal(p.packages,h.height,h.previous).header.root!=h.root:
            raise ValueError('transaction-root')
        seen=set();updated=copy.deepcopy(self.state['classes'])
        for pkg in p.packages:
            if not validate_record_package(pkg,self.manufacturers):raise ValueError('invalid-checkpoint-record')
            cp=pkg.checkpoint;r=pkg.record;key=H(enc('ORBIT-CLASS-v2',cp.manufacturer,cp.cls)).hex()
            if key in seen:raise ValueError('duplicate-class-in-batch')
            seen.add(key);old=updated.get(key)
            if old:
                oldcp=from_wire(old['cp'])
                if cp.size==oldcp.size and cp.digest()!=oldcp.digest():raise ValueError('same-size-fork')
                if cp.size==oldcp.size+1 and r.previous!=oldcp.latest:raise ValueError('predecessor-digest')
                if not verify_consistency(oldcp.size,cp.size,oldcp.root,cp.root,[] if cp.digest()==oldcp.digest() else pkg.consistency):
                    raise ValueError('incompatible-prefix')
                if r.version<old['version'] or r.epoch<old['epoch']:raise ValueError('lifecycle-regression')
            updated[key]={'cp':to_wire(cp),'version':r.version,'epoch':r.epoch}
        return updated
    def prepare(self,p:Proposal)->Vote:
        self._validate(p);height=str(p.header.height);digest=p.header.digest().hex()
        if height in self.state['locks'] and self.state['locks'][height]!=digest:
            raise ValueError('conflicting-prepare-lock')
        s=copy.deepcopy(self.state);s['locks'][height]=digest
        self.store.save(s);self.state=s # MUST precede signature emission.
        return Vote(self.name,'prepare',sign(self.key,vote_body(self.name,'prepare',p.header)))
    def commit(self,p:Proposal,prepares:list[Vote])->Vote:
        self._validate(p)
        if not votes_valid(prepares,'prepare',p.header,self.pubs):raise ValueError('prepare-quorum')
        # Commit-voters also hold a durable one-digest lock for this height.
        self.prepare(p)
        return Vote(self.name,'commit',sign(self.key,vote_body(self.name,'commit',p.header)))
    def finalize(self,p:Proposal,commits:list[Vote])->Block:
        if not votes_valid(commits,'commit',p.header,self.pubs):raise ValueError('commit-quorum')
        updated=self._validate(p)
        s=copy.deepcopy(self.state);s.update(height=p.header.height,head=p.header.digest().hex(),classes=updated)
        s['locks'][str(p.header.height)]=p.header.digest().hex()
        self.store.save(s);self.state=s
        return Block(p.header,commits)

class Consortium:
    def __init__(self,manufacturers,stores=None):
        keys=[signing_key() for _ in range(4)]
        self.pubs={f'validator-{i}':signing_public(k) for i,k in enumerate(keys)}
        self.validators=[Validator(f'validator-{i}',manufacturers,self.pubs,k,None if stores is None else stores[i]) for i,k in enumerate(keys)]
        self.chain=[]
    def finalize(self,packages,available=None):
        vs=self.validators if available is None else [self.validators[i] for i in available]
        prev=self.chain[-1].header.digest() if self.chain else ZERO
        p=make_proposal(packages,len(self.chain)+1,prev)
        prepares=[v.prepare(p) for v in vs]
        commits=[v.commit(p,prepares) for v in vs]
        if not votes_valid(commits,'commit',p.header,self.pubs):raise ValueError('commit-quorum')
        for v in vs:v.finalize(p,commits)
        block=Block(p.header,sorted(commits,key=lambda v:v.identity)[:3]);self.chain.append(block)
        return p,make_anchor(p,self.chain)

class FinalityVerifier:
    def __init__(self,pubs:dict):
        if len(pubs)!=4:raise ValueError('four validators required')
        self.pubs=pubs
    def verify(self,cp:Checkpoint,a:Anchor|None,old_height=0,old_head=ZERO):
        if a is None or not a.chain:raise ValueError('missing-anchor')
        height=old_height;head=old_head
        # Full chain or an incremental suffix is accepted, but never an unlinked header.
        for b in a.chain:
            h=b.header
            if h.height<height:continue
            if h.height==height:
                if h.digest()!=head:raise ValueError('finalized-head-conflict')
                continue
            if h.chain!=CHAIN or h.epoch!=EPOCH or h.height!=height+1 or h.previous!=head:
                raise ValueError('unlinked-finality-chain')
            if not votes_valid(b.commits,'commit',h,self.pubs):raise ValueError('finality-quorum')
            height=h.height;head=h.digest()
        h=a.chain[-1].header
        if h.height!=height or h.digest()!=head:raise ValueError('stale-anchor-header')
        if not verify_inclusion(lh(anchor_body(cp)),a.index,h.count,a.path,h.root):raise ValueError('anchor-inclusion')
        return height,head
