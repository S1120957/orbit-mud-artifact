"""Integrated C1--C11 admission, session-scoped retry, and authenticated revalidation.
PEP is an executable policy model. Ingress handle registration is a trusted API.
"""
from __future__ import annotations
import copy, secrets
from dataclasses import dataclass
from .crypto import H,enc,verify_sig,verify_pop
from .merkle import lh,verify_inclusion,verify_consistency,StatusTree
from .model import Package,Discover,Offer,transcript,lifecycle,witness_body,to_wire,from_wire,ZERO
from .ledger import FinalityVerifier
from .storage import Store

class Rejection(ValueError):pass

@dataclass(frozen=True)
class Policy:
    witness_threshold:int=2
    max_age:int=3600
    skew:int=2
    grace:int=0
    session_ttl:int=30
    ledger_strict:bool=False
    fail_closed_classes:tuple=()

class PEP:
    def __init__(self):self.handles=set();self.installed={}
    def open_session(self,handle):
        if not isinstance(handle,str) or not handle:raise ValueError('handle')
        self.handles.add(handle)
    def install(self,handle,principal,expires,policy):
        if handle not in self.handles:raise Rejection('C10:untrusted-ingress-handle')
        prior=self.installed.get(handle)
        if prior and prior['principal']!=principal:raise Rejection('C10:handle-owned-by-other-key')
        self.installed[handle]={'principal':principal,'expires':expires,'policy':policy}
    def allowed(self,handle,now):
        p=self.installed.get(handle)
        return bool(p and now<=p['expires'])
    def withdraw(self,handle):return self.installed.pop(handle,None) is not None

class Controller:
    def __init__(self,manufacturer_pubs,witness_pubs=None,policy=None,store=None,pep=None,validator_pubs=None):
        self.manufacturers=manufacturer_pubs;self.witnesses=witness_pubs or {};self.policy=policy or Policy()
        self.store=store or Store();self.pep=pep or PEP();self.sessions={};self.consumed=set()
        self.state=copy.deepcopy(self.store.data) or {'classes':{},'height':0,'head':ZERO.hex()}
        self.finality=FinalityVerifier(validator_pubs) if validator_pubs else None
        if self.policy.ledger_strict and self.finality is None:raise Rejection('C11:missing-trust-configuration')
    @staticmethod
    def classkey(p):return H(enc('ORBIT-CLASS-v2',p.record.manufacturer,p.record.cls)).hex()
    def _validate(self,p:Package,now:int,anchor=None,online=True,allow_inactive=False):
        cp=p.checkpoint;r=p.record;f=p.file;leaf=p.leaf;key=self.classkey(p);pub=self.manufacturers.get(r.manufacturer)
        if not pub or not verify_sig(pub,f.body(),f.signature) or f.digest()!=r.profile_digest or (f.manufacturer,f.cls,f.version)!=(r.manufacturer,r.cls,r.version):
            raise Rejection('C1:profile-authenticity')
        if (cp.manufacturer,cp.cls)!=(r.manufacturer,r.cls) or not verify_sig(pub,cp.body(),cp.signature):
            raise Rejection('C2:checkpoint-authenticity')
        old=self.state['classes'].get(key)
        if old is None and self.policy.witness_threshold:
            ids={wid for wid,sig in cp.endorsements if wid in self.witnesses and verify_sig(self.witnesses[wid],witness_body(wid,cp),sig)}
            if len(ids)<self.policy.witness_threshold:raise Rejection('C3:witness-quorum')
        if (r.sequence!=cp.size or p.log_index!=cp.size-1 or r.digest()!=cp.latest or
            not verify_inclusion(lh(r.body()),p.log_index,cp.size,p.log_path,cp.root)):
            raise Rejection('C4:not-latest-in-checkpoint')
        if old:
            prev=from_wire(old['cp'])
            if cp.size==prev.size and cp.digest()!=prev.digest():raise Rejection('C5:same-size-checkpoint-conflict')
            if not verify_consistency(prev.size,cp.size,prev.root,cp.root,[] if cp.digest()==prev.digest() else p.consistency):raise Rejection('C5:history-prefix')
            if cp.size==prev.size+1 and r.previous!=prev.latest:raise Rejection('C4:predecessor-digest')
            if r.sequence<old['sequence'] or r.version<old['version'] or r.epoch<old['epoch']:raise Rejection('C6:monotonicity')
        eps=self.policy.skew;window=self.policy.max_age
        if not online:
            if r.cls in self.policy.fail_closed_classes:raise Rejection('C7:offline-critical-class')
            window+=self.policy.grace
        if (r.valid_until<r.valid_from or now+eps<r.valid_from or now-eps>r.valid_until or
            cp.issued>now+eps or now-cp.issued>window+eps):raise Rejection('C7:time-window')
        if not allow_inactive and (not r.supported or r.emergency):raise Rejection('C8:class-denied')
        if ((leaf.manufacturer,leaf.cls,leaf.epoch)!=(r.manufacturer,r.cls,r.epoch) or
            not StatusTree.verify(leaf.digest(),leaf.index,r.population,p.status_path,r.status_root)):
            raise Rejection('C9:status-membership')
        if not allow_inactive and leaf.status!='active':raise Rejection('C9:inactive-device')
        height=self.state['height'];head=bytes.fromhex(self.state['head'])
        if self.policy.ledger_strict:
            try:height,head=self.finality.verify(cp,anchor,height,head)
            except (ValueError,TypeError,AttributeError) as ex:raise Rejection('C11:'+str(ex)) from ex
        # Earliest limiting policy boundary, including explicit skew tolerance.
        expiry=min(r.valid_until+eps,cp.issued+window+eps)
        return key,height,head,expiry
    def begin(self,handle,xid,d:Discover,p:Package,now:int,anchor=None,online=True):
        if handle not in self.pep.handles:raise Rejection('C10:untrusted-ingress-handle')
        key,height,head,expiry=self._validate(p,now,anchor,online)
        if d.url!=p.file.url:raise Rejection('C1:device-url')
        if d.epoch!=p.record.epoch:raise Rejection('C8:device-epoch')
        if d.index!=p.leaf.index or d.pub!=p.leaf.pub:raise Rejection('C9:claimed-index-or-key')
        owner=self.pep.installed.get(handle)
        if owner and owner['principal']!=d.pub.hex():raise Rejection('C10:handle-owned-by-other-key')
        sid=H(enc('ORBIT-SESSION-v2',handle,xid,d.commitment,d.pub,d.index,H(d.url.encode()))).hex()
        existing=self.sessions.get(sid)
        if existing and now<=existing['deadline'] and existing['digest']==p.checkpoint.digest():
            return sid,existing['offer']
        if d.commitment in self.consumed:raise Rejection('C10:commitment-reused-across-session')
        # Pending nonces must also not be re-challenged under another context.
        if any(s['discover'].commitment==d.commitment for s in self.sessions.values()):raise Rejection('C10:pending-commitment-context-change')
        offer=Offer(secrets.token_bytes(32),lifecycle(p),H(enc('ORBIT-HANDLE-v2',handle)))
        self.sessions[sid]={'offer':offer,'discover':d,'xid':xid,'handle':handle,'package':p,'anchor':anchor,
            'online':online,'digest':p.checkpoint.digest(),'deadline':min(now+self.policy.session_ttl,expiry),
            'done':False,'response':None}
        return sid,offer
    def finish(self,sid,z,now):
        s=self.sessions.get(sid)
        if s is None or now>s['deadline']:raise Rejection('C10:expired-or-unknown-session')
        p=s['package'];d=s['discover'];handle=s['handle']
        key,height,head,expiry=self._validate(p,now,s['anchor'],s['online'])
        # _validate rechecks status / head after concurrent update or revocation.
        if s['done']:
            if z!=s['response'] or not self.pep.allowed(handle,now):raise Rejection('C10:invalid-retransmission')
            return True
        if not verify_pop(d.pub,d.commitment,z,transcript(s['xid'],d,s['offer'])):raise Rejection('C10:proof')
        state=copy.deepcopy(self.state)
        state['classes'][key]={'cp':to_wire(p.checkpoint),'sequence':p.record.sequence,'version':p.record.version,'epoch':p.record.epoch}
        state.update(height=height,head=head.hex())
        # Durable state commit precedes positive PEP activation. Failure cannot grant access.
        self.store.save(state);self.state=state
        self.pep.install(handle,d.pub.hex(),expiry,p.file.policy.hex())
        s['done']=True;s['response']=z;self.consumed.add(d.commitment)
        return True
    def admit(self,handle,xid,device,p,now,anchor=None,online=True):
        d=device.start();sid,o=self.begin(handle,xid,d,p,now,anchor,online)
        return self.finish(sid,device.answer_offer(xid,o),now)
    def revalidate(self,handle,p:Package,now:int,anchor=None,online=True):
        old=self.pep.installed.get(handle)
        if not old:raise Rejection('C9:no-installed-principal')
        key,height,head,expiry=self._validate(p,now,anchor,online,allow_inactive=True)
        if old['principal']!=p.leaf.pub.hex():raise Rejection('C9:withdrawal-identity')
        deny=p.leaf.status!='active' or not p.record.supported or p.record.emergency
        # Conservative ordering: withdraw stale policy FIRST; a failed persistence step stays fail-closed.
        self.pep.withdraw(handle)
        state=copy.deepcopy(self.state)
        state['classes'][key]={'cp':to_wire(p.checkpoint),'sequence':p.record.sequence,'version':p.record.version,'epoch':p.record.epoch}
        state.update(height=height,head=head.hex());self.store.save(state);self.state=state
        if not deny:self.pep.install(handle,old['principal'],expiry,p.file.policy.hex())
        return deny
