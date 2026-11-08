from dataclasses import replace
from pathlib import Path
import copy,sqlite3,shutil,itertools
import pytest
from orbit.crypto import *
from orbit.merkle import *
from orbit.model import *
from orbit.controller import *
from orbit.ledger import *
from orbit.storage import *

T=1700000000
KEY=b'K'*32

def world(n=8,policy=None,store=None,ledger=False):
    m=Manufacturer(n,T);ws=[Witness(f'w{i}') for i in range(3)];m.endorse(ws,T)
    cons=Consortium({m.name:m.pub}) if ledger else None
    c=Controller({m.name:m.pub},{w.name:w.pub for w in ws},policy or Policy(ledger_strict=ledger),store=store,validator_pubs=cons.pubs if cons else None)
    c.pep.open_session('port-0');c.pep.open_session('port-1')
    return m,ws,c,cons

def fork(m):
    b=object.__new__(Manufacturer);b.__dict__=m.__dict__.copy()
    for k in ('leaves','records','cps','files'):setattr(b,k,list(getattr(m,k)))
    b.history=copy.deepcopy(m.history);b.status=copy.deepcopy(m.status)
    return b

def join(c,m,p=None,now=T,anchor=None,xid=1,handle='port-0',index=0):
    return c.admit(handle,xid,m.devices[index],p or m.package(index),now,anchor)

def reject_begin(c,m,p,expected,now=T,anchor=None,d=None,handle='port-0'):
    with pytest.raises(Rejection,match=expected):c.begin(handle,22,d or m.devices[0].start(),p,now,anchor)


def test_native_schnorr_and_invalid_points():
    k=scalar();r,R=commit();P=public(k);z=respond(k,r,b'transcript')
    assert verify_pop(P,R,z,b'transcript')
    assert not verify_pop(P,R,z,b'changed')
    assert not verify_pop(b'\x00'*33,R,z,b'transcript')
    assert not verify_pop(P,R,ORDER,b'transcript')


def test_history_all_prefix_and_inclusion_pairs():
    t=History()
    for i in range(128):t.append(enc(i))
    for n in range(1,129):
        for m in range(n+1):
            proof=t.consistency(m,n)
            assert verify_consistency(m,n,t.root(m),t.root(n),proof)
            if proof:assert not verify_consistency(m,n,t.root(m),t.root(n),[b'x'*32]+proof[1:])
        for i in range(n):assert verify_inclusion(t.leaves[i],i,n,t.inclusion(i,n),t.root(n))

@pytest.mark.parametrize('n',[1,2,3,8,19,1000])
def test_status_incremental_updates(n):
    t=StatusTree([lh(enc(i)) for i in range(n)])
    for i in sorted(set([0,n//2,n-1])):
        t.update(i,lh(enc('revoked',i)))
        for j in sorted(set([0,n//2,n-1])):assert StatusTree.verify(t.levels[0][j],j,n,t.proof(j),t.root)
        rebuilt=StatusTree(t.levels[0][:n]);assert rebuilt.root==t.root


def test_honest_join_and_same_session_retransmission():
    m,ws,c,_=world();d=m.devices[0].start();p=m.package()
    sid,o=c.begin('port-0',7,d,p,T);sid2,o2=c.begin('port-0',7,d,p,T)
    assert sid==sid2 and o==o2
    z=m.devices[0].answer_offer(7,o);assert m.devices[0].answer_offer(7,o)==z
    assert c.finish(sid,z,T) and c.finish(sid,z,T+1)
    assert c.pep.allowed('port-0',T+1)


def test_retransmission_after_nonempty_prefix_update():
    m,ws,c,_=world();join(c,m);m.publish(T+1,version=2);m.endorse(ws,T+1)
    d=m.devices[0].start();p=m.package(old_size=1);sid,o=c.begin('port-0',2,d,p,T+1)
    z=m.devices[0].answer_offer(2,o);assert c.finish(sid,z,T+1);assert c.finish(sid,z,T+2)


def test_replay_other_session_rejected():
    m,_,c,_=world();d=m.devices[0].start();p=m.package();sid,o=c.begin('port-0',3,d,p,T);z=m.devices[0].answer_offer(3,o);c.finish(sid,z,T)
    reject_begin(c,m,p,'C10',d=d,handle='port-1')


def test_expired_session_and_nonce_reuse_guard():
    m,_,c,_=world();d=m.devices[0].start();sid,o=c.begin('port-0',1,d,m.package(),T)
    z=m.devices[0].answer_offer(1,o)
    with pytest.raises(Rejection,match='C10'):c.finish(sid,z,T+31)
    with pytest.raises(ValueError,match='nonce already'):m.devices[0].answer_offer(1,replace(o,nonce=b'0'*32))


def test_wrong_proof_and_handle_binding():
    m,_,c,_=world();d=m.devices[0].start();sid,o=c.begin('port-0',1,d,m.package(),T)
    z=m.devices[0].answer_offer(1,replace(o,binding=H(b'another-port')))
    with pytest.raises(Rejection,match='C10'):c.finish(sid,z,T)
    assert not c.pep.installed


def test_unknown_handle_rejected():
    m,_,c,_=world();reject_begin(c,m,m.package(),'C10',handle='attacker-chosen')


def test_other_key_cannot_overwrite_handle():
    m,_,c,_=world();join(c,m)
    reject_begin(c,m,m.package(1),'C10',d=m.devices[1].start())


def test_forged_mud_and_checkpoint():
    m,_,c,_=world();p=m.package()
    reject_begin(c,m,replace(p,file=replace(p.file,signature=b'invalid')),'C1')
    reject_begin(c,m,replace(p,checkpoint=replace(p.checkpoint,signature=b'invalid')),'C2')


def test_cross_class_checkpoint_substitution():
    m,_,c,_=world();p=m.package();cp=replace(p.checkpoint,cls='other');cp=replace(cp,signature=sign(m.key,cp.body()))
    reject_begin(c,m,replace(p,checkpoint=cp),'C2')

@pytest.mark.parametrize('count,accept',[(0,False),(1,False),(2,True),(3,True)])
def test_witness_availability(count,accept):
    m,_,c,_=world();p=m.package();p=replace(p,checkpoint=replace(p.checkpoint,endorsements=p.checkpoint.endorsements[:count]))
    if accept:assert join(c,m,p)
    else:reject_begin(c,m,p,'C3')


def test_duplicate_witness_not_quorum():
    m,_,c,_=world();p=m.package();e=p.checkpoint.endorsements[0]
    reject_begin(c,m,replace(p,checkpoint=replace(p.checkpoint,endorsements=(e,e,e))),'C3')


def test_historical_record_inside_new_checkpoint_rejected():
    m,ws,c,_=world();old=m.package();m.publish(T+1,version=2);m.endorse(ws,T+1);new=m.package()
    p=replace(new,file=old.file,record=old.record,log_index=0,log_path=m.history.inclusion(0))
    reject_begin(c,m,p,'C4',now=T+1)


def test_complete_old_package_replay():
    m,ws,c,_=world();old=m.package();join(c,m,old)
    m.publish(T+1,version=2);m.endorse(ws,T+1);assert join(c,m,m.package(old_size=1),T+1)
    reject_begin(c,m,old,'C5',now=T+2)


def test_complete_old_package_after_restart(tmp_path):
    path=tmp_path/'controller.db';s=Store(path,KEY,True);m,ws,c,_=world(store=s);old=m.package();join(c,m,old)
    m.publish(T+1,version=2);m.endorse(ws,T+1);join(c,m,m.package(old_size=1),T+1);s.close()
    c2=Controller({m.name:m.pub},{w.name:w.pub for w in ws},store=Store(path,KEY));c2.pep.open_session('port-0')
    reject_begin(c2,m,old,'C5',now=T+2);assert join(c2,m,m.package(old_size=2),T+2)


def test_state_missing_corrupt_and_valid_old_snapshot(tmp_path):
    path=tmp_path/'state.db';floor=MemoryFloor()
    with pytest.raises(StateError,match='missing'):Store(path,KEY)
    s=Store(path,KEY,True,floor);s.save({'x':1});s.close();old=path.read_bytes()
    s=Store(path,KEY,floor=floor);s.save({'x':2});s.close();path.write_bytes(old)
    with pytest.raises(StateError,match='floor'):Store(path,KEY,floor=floor)
    # Deliberate negative result: HMAC alone does not detect authentic snapshot rollback.
    s=Store(path,KEY);assert s.data=={'x':1};s.close()
    db=sqlite3.connect(path);db.execute("UPDATE state SET body=?",(b'{"x":9}',));db.commit();db.close()
    with pytest.raises(StateError,match='integrity'):Store(path,KEY)


def test_persistence_failure_cannot_install():
    class Broken(Store):
        def save(self,data):raise StateError('injected disk failure')
    m,_,c,_=world(store=Broken())
    with pytest.raises(StateError):join(c,m)
    assert not c.pep.installed

@pytest.mark.parametrize('change',[{'version':0},{'epoch':0}])
def test_monotonic_version_and_epoch(change):
    m,ws,c,_=world();join(c,m);m.publish(T+1,**change);m.endorse(ws,T+1)
    reject_begin(c,m,m.package(old_size=1),'C6',now=T+1)

@pytest.mark.parametrize('delta,accepted',[(-3,False),(-2,True),(3602,True),(3603,False)])
def test_time_skew_boundaries(delta,accepted):
    m,_,c,_=world()
    if accepted:assert join(c,m,now=T+delta)
    else:reject_begin(c,m,m.package(),'C7',now=T+delta)


def test_record_not_yet_valid_independent_of_checkpoint_age():
    m,ws,c,_=world();m.publish(T,valid_from=T+100);m.endorse(ws,T)
    reject_begin(c,m,m.package(),'C7')


def test_first_contact_time_valid_old_package_is_accepted():
    m,ws,c,_=world();old=m.package();m.publish(T+1,version=2)
    assert join(c,m,old,T+2)


def test_offline_grace_does_not_extend_record_interval():
    m,ws,c,_=world(policy=Policy(grace=600));p=m.package()
    reject_begin(c,m,p,'C7',now=T+3700) # record expired independently of age grace
    m.publish(T,valid_until=T+5000);m.endorse(ws,T);p=m.package()
    d=m.devices[0].start();sid,o=c.begin('port-0',1,d,p,T+3700,online=False);assert c.finish(sid,m.devices[0].answer_offer(1,o),T+3700)

@pytest.mark.parametrize('status',['revoked','suspended'])
def test_inactive_member_onboarding(status):
    m,ws,c,_=world();m.set_status(0,status);m.publish(T+1);m.endorse(ws,T+1)
    reject_begin(c,m,m.package(),'C9',now=T+1)


def test_claimed_merkle_index_and_key_match():
    m,_,c,_=world();d=m.devices[0].start();reject_begin(c,m,m.package(),'C9',d=replace(d,index=1))
    reject_begin(c,m,m.package(),'C9',d=replace(d,pub=m.devices[1].pub))


def test_validly_signed_equal_and_unequal_size_forks():
    m,ws,c,_=world();join(c,m);b=fork(m)
    m.publish(T+1,version=2);m.endorse(ws,T+1);join(c,m,m.package(old_size=1),T+1)
    b.publish(T+1,version=3)
    reject_begin(c,b,b.package(old_size=2),'C5',now=T+1)
    b.publish(T+2,version=4);reject_begin(c,b,b.package(old_size=2),'C5',now=T+2)
    assert verify_sig(b.pub,b.cps[-1].body(),b.cps[-1].signature)


def test_two_of_three_witness_collusion_negative_result():
    m,ws,_,_=world();b=fork(m);m.publish(T+1,version=2);b.publish(T+1,version=3)
    # Byzantine w0 signs both; w1 and w2 are honest but observe different branches.
    for branch,honest in [(m,ws[1]),(b,ws[2])]:
        cp=branch.cps[-1];e0=(ws[0].name,sign(ws[0].key,witness_body(ws[0].name,cp)))
        eh=honest.endorse(cp,branch.pub,branch.history.consistency(1),T+1)
        branch.cps[-1]=replace(cp,endorsements=(e0,eh))
        c=Controller({m.name:m.pub},{w.name:w.pub for w in ws});c.pep.open_session('port-0');assert join(c,branch,now=T+1)
    assert m.cps[-1].root!=b.cps[-1].root


def test_live_signed_revocation_withdraws_only_target():
    m,ws,c,_=world();join(c,m);join(c,m,m.package(1),handle='port-1',index=1,xid=2)
    m.set_status(0,'revoked');m.publish(T+1);m.endorse(ws,T+1)
    assert c.revalidate('port-0',m.package(0,old_size=1),T+1)
    assert not c.pep.allowed('port-0',T+1) and c.pep.allowed('port-1',T+1)
    assert not c.revalidate('port-1',m.package(1,old_size=2),T+1)


def test_unauthenticated_update_cannot_withdraw():
    m,ws,c,_=world();join(c,m);m.set_status(0,'revoked');m.publish(T+1);m.endorse(ws,T+1);p=m.package(old_size=1)
    bad=replace(p,checkpoint=replace(p.checkpoint,signature=b'bad'))
    with pytest.raises(Rejection):c.revalidate('port-0',bad,T+1)
    assert c.pep.allowed('port-0',T+1)


def test_pending_request_cannot_restore_revoked_policy():
    m,ws,c,_=world();join(c,m);d=m.devices[0].start();p=m.package();sid,o=c.begin('port-0',2,d,p,T);z=m.devices[0].answer_offer(2,o)
    m.set_status(0,'revoked');m.publish(T+1);m.endorse(ws,T+1);c.revalidate('port-0',m.package(old_size=1),T+1)
    with pytest.raises(Rejection,match='C5'):c.finish(sid,z,T+1)
    assert not c.pep.installed

@pytest.mark.parametrize('kwargs',[{'supported':False},{'emergency':True}])
def test_authenticated_class_withdrawal(kwargs):
    m,ws,c,_=world();join(c,m);m.publish(T+1,**kwargs);m.endorse(ws,T+1)
    assert c.revalidate('port-0',m.package(old_size=1),T+1)


def test_policy_lease_expires_without_update_delivery():
    m,_,c,_=world();join(c,m)
    assert c.pep.allowed('port-0',T+3602);assert not c.pep.allowed('port-0',T+3603)


def test_integrated_c11_missing_and_valid_anchor():
    m,_,c,l=world(ledger=True);reject_begin(c,m,m.package(),'C11');_,a=l.finalize([m.package()]);assert join(c,m,anchor=a)


def test_integrated_c11_tamper_duplicate_and_wrong_chain():
    m,_,c,l=world(ledger=True);_,a=l.finalize([m.package()]);b=a.chain[-1]
    bad=replace(a,chain=[replace(b,commits=[b.commits[0]]*3)])
    reject_begin(c,m,m.package(),'C11',anchor=bad)
    bad=replace(a,chain=[replace(b,header=replace(b.header,chain='another-chain'))])
    reject_begin(c,m,m.package(),'C11',anchor=bad)
    bad=replace(a,index=1);reject_begin(c,m,m.package(),'C11',anchor=bad)


def test_strict_withdrawal_requires_new_valid_anchor():
    m,ws,c,l=world(ledger=True);_,a=l.finalize([m.package()]);join(c,m,anchor=a)
    m.set_status(0,'revoked');m.publish(T+1);m.endorse(ws,T+1);p=m.package(old_size=1)
    with pytest.raises(Rejection,match='C11'):c.revalidate('port-0',p,T+1,a)
    _,a2=l.finalize([p]);assert c.revalidate('port-0',p,T+1,a2)


def test_validator_rejects_signed_forks_at_different_sizes():
    m,ws,c,l=world(ledger=True);_,a=l.finalize([m.package()]);b=fork(m)
    m.publish(T+1,version=2);m.endorse(ws,T+1);l.finalize([m.package(old_size=1)])
    b.publish(T+1,version=3)
    p=make_proposal([b.package(old_size=2)],3,l.chain[-1].header.digest())
    with pytest.raises(ValueError,match='fork'):l.validators[0].prepare(p)
    b.publish(T+2,version=4);b.publish(T+3,version=5);p=make_proposal([b.package(old_size=2)],3,l.chain[-1].header.digest())
    with pytest.raises(ValueError,match='prefix'):l.validators[0].prepare(p)


def test_validator_durable_lock_survives_restart(tmp_path):
    m=Manufacturer(now=T);l=Consortium({m.name:m.pub});v=l.validators[0]
    st=Store(tmp_path/'validator.db',KEY,True);v=Validator(v.name,{m.name:m.pub},l.pubs,v.key,st)
    p=make_proposal([m.package()]);v.prepare(p);st.close()
    v2=Validator(v.name,{m.name:m.pub},l.pubs,v.key,Store(tmp_path/'validator.db',KEY))
    b=fork(m);b.publish(T+1,version=2);bad=make_proposal([b.package()])
    with pytest.raises(ValueError,match='lock'):v2.prepare(bad)


def test_quorum_unavailability_and_one_offline():
    m,_,_,l=world(ledger=True)
    with pytest.raises(ValueError,match='quorum'):l.finalize([m.package()],available=[0,1])
    # Exact retry of locked proposal can still finalize with three responsive validators.
    _,a=l.finalize([m.package()],available=[0,1,2]);assert len(a.chain)==1


def test_quorum_intersection_exhaustive():
    for n,q,f,expected in [(3,2,1,True),(4,3,1,False)]:
        pairs=0
        for A in itertools.combinations(range(n),q):
            for B in itertools.combinations(range(n),q):
                for faulty in itertools.combinations(range(n),f):
                    if set(A)&set(B)<=set(faulty):pairs+=1
        assert bool(pairs)==expected


def test_schnorr_leakage_only_one_key():
    m=Manufacturer(now=T);k=m.devices[0].key;r,R=commit();msg=b'containment';z=respond(k,r,msg)
    assert verify_pop(m.devices[0].pub,R,z,msg) and not verify_pop(m.devices[1].pub,R,z,msg)

@pytest.mark.parametrize('url_length',[42,128,240,255])
def test_dhcp_wire_roundtrip(url_length):
    from orbit.wire import discover_options,offer_options,request_options,decode_discover,decode_offer,dhcp,ipv4_udp,checksum
    m,_,c,_=world();d=replace(m.devices[0].start(),url='https://example.invalid/'+('a'*(url_length-24)))
    assert len(d.url)==url_length
    assert decode_discover(discover_options(d))==d
    o=Offer(b'a'*32,b'b'*32,b'c'*32);assert decode_offer(offer_options(o))==o
    for typ,custom in [(1,discover_options(d)),(2,offer_options(o)),(3,request_options(1,o))]:
        pkt=ipv4_udp(dhcp(typ,1,custom),typ==2)
        assert checksum(pkt[:20])==0 and len(pkt)==int.from_bytes(pkt[2:4],'big')


def test_network_quorum_and_partition(tmp_path):
    from orbit.network import NetworkConsortium
    m,_,_,_=world()
    with NetworkConsortium({m.name:m.pub},tmp_path/'network') as n:
        _,a,_=n.finalize([m.package()],available=[0,1,2]);assert FinalityVerifier(n.pubs).verify(m.cps[-1],a)[0]==1
        with pytest.raises(ValueError,match='quorum'):n.finalize([m.package()],available=[0,1])
