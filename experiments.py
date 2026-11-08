"""Reproduce revision measurements. Raw measurements.
Usage: python experiments.py --out results --runs 200 [--quick]
"""
from __future__ import annotations
import argparse,copy,csv,gc,itertools,json,os,platform,random,resource,ssl,sys,tempfile,time
from pathlib import Path
from dataclasses import replace
import numpy as np
import cryptography
from orbit.crypto import *
from orbit.model import *
from orbit.controller import *
from orbit.ledger import *
from orbit.storage import *
from orbit.baselines import Baseline
from orbit.merkle import *
from orbit.wire import *
from orbit.network import NetworkConsortium

T=1700000000
SEED=20261108

def output(path,data):Path(path).write_text(json.dumps(data,indent=2,sort_keys=True))
def csvwrite(path,rows):
    if not rows:return
    with open(path,'w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def timed(fn):
    a=time.perf_counter_ns();value=fn();return (time.perf_counter_ns()-a)/1e6,value

def stats(xs):
    a=np.asarray(xs,dtype=float);rng=np.random.default_rng(SEED)
    medians=np.median(rng.choice(a,size=(4000,len(a)),replace=True),axis=1)
    return {'n':len(a),'median_ms':float(np.median(a)),'q1_ms':float(np.quantile(a,.25)),
            'q3_ms':float(np.quantile(a,.75)),'ci_low_ms':float(np.quantile(medians,.025)),
            'ci_high_ms':float(np.quantile(medians,.975)),'mean_ms':float(a.mean())}

def fixture():
    m=Manufacturer(32,T);ws=[Witness(f'w{i}') for i in range(3)];m.endorse(ws,T)
    return m,ws

def ctrl(m,ws,mode,validators=None,store=None):
    c=Controller({m.name:m.pub},{w.name:w.pub for w in ws},Policy(witness_threshold=0 if mode=='B4' else 2,ledger_strict=mode=='B6'),store=store,validator_pubs=validators)
    c.pep.open_session('port-0');return c

def latency(out,runs):
    m,ws=fixture();p=m.package();k=scalar();P=public(k);con=Consortium({m.name:m.pub});_,anchor=con.finalize([p]);d=m.devices[0]
    rows=[];modes=['B1','B2','B3','B4-first','B5-first','B6-first','B4-return','B5-return','B6-return']
    rng=random.Random(SEED)
    for rep in range(runs+10):
        order=modes.copy();rng.shuffle(order)
        for name in order:
            mode=name[:2]
            if mode in ('B1','B2','B3'):
                b=Baseline(mode,m.pub,P);fn=lambda:b.admit(p.file,p.file.url,k,xid=rep+1)
            else:
                c=ctrl(m,ws,mode,con.pubs)
                if name.endswith('return'):c.admit('port-0',1,d,p,T,anchor)
                fn=lambda:c.admit('port-0',rep+2,d,p,T,anchor)
            ms,ok=timed(fn);assert ok
            if rep>=10:rows.append({'operation':name,'run':rep-10,'ms':ms})
    # Device/verification operations are software costs, never embedded timings.
    for name in ['device_commit_and_response','device_response_only','schnorr_verify','anchor_uncached','authenticated_withdrawal']:
        for rep in range(runs+10):
            if name=='authenticated_withdrawal':
                mm,ww=fixture();cc=ctrl(mm,ww,'B5');cc.admit('port-0',1,mm.devices[0],mm.package(),T)
                mm.set_status(0,'revoked');mm.publish(T+1);mm.endorse(ww,T+1);pp=mm.package(old_size=1)
                fn=lambda:cc.revalidate('port-0',pp,T+1)
            elif name=='anchor_uncached':fn=lambda:FinalityVerifier(con.pubs).verify(p.checkpoint,anchor)
            else:
                r,R=commit();msg=enc('benchmark',R,P,rep);z=respond(k,r,msg)
                if name=='schnorr_verify':fn=lambda:verify_pop(P,R,z,msg)
                elif name=='device_response_only':fn=lambda:respond(k,r,msg)
                else:
                    def fn():
                        rr,RR=commit();return respond(k,rr,enc('benchmark',RR,P,rep))
            ms,_=timed(fn)
            if rep>=10:rows.append({'operation':name,'run':rep-10,'ms':ms})
    # Durable admission includes the SQLite/HMAC commit, not just in-memory maxima.
    with tempfile.TemporaryDirectory() as tmp:
        st=Store(Path(tmp)/'state.db',b'K'*32,True);c=ctrl(m,ws,'B5',store=st)
        c.admit('port-0',999,d,p,T)
        for rep in range(runs):
            ms,ok=timed(lambda:c.admit('port-0',1000+rep,d,p,T));assert ok
            rows.append({'operation':'B5-return-durable','run':rep,'ms':ms})
        st.close()
    csvwrite(out/'latency_raw.csv',rows)
    summary={name:stats([r['ms'] for r in rows if r['operation']==name]) for name in sorted({r['operation'] for r in rows})}
    output(out/'latency_summary.json',summary);return summary

def scaling(out,quick=False):
    status_rows=[];raw=[]
    for n in ([100,1000,10000] if quick else [100,1000,10000,100000,1000000]):
        gc.collect();start=time.perf_counter_ns();leaves=[lh(enc('synthetic-status',i)) for i in range(n)]
        leaf_ms=(time.perf_counter_ns()-start)/1e6
        build_ms,t=timed(lambda:StatusTree(leaves));i=n//3
        estimated=sum(sys.getsizeof(a)+sum(sys.getsizeof(x) for x in a) for a in t.levels)
        for rep in range(100):
            g,path=timed(lambda:t.proof(i));v,ok=timed(lambda:StatusTree.verify(t.levels[0][i],i,n,path,t.root));assert ok
            u,_=timed(lambda:t.update(i,lh(enc('update',rep,i))))
            raw.append({'tree':'status','size':n,'run':rep,'proof_gen_ms':g,'verify_ms':v,'update_or_append_ms':u})
        vals=[r for r in raw if r['tree']=='status' and r['size']==n]
        status_rows.append({'N':n,'leaf_hash_ms':leaf_ms,'build_ms':build_ms,'path_nodes':len(path),'proof_bytes':32*len(path),
            'verify_us':1000*float(np.median([r['verify_ms'] for r in vals])),
            'update_us':1000*float(np.median([r['update_or_append_ms'] for r in vals])),
            'proof_gen_us':1000*float(np.median([r['proof_gen_ms'] for r in vals])),
            'python_tree_bytes_estimate':estimated,'raw_hash_bytes':sum(len(a) for a in t.levels)*32})
        del t,leaves;gc.collect()
    log_rows=[]
    for n in ([1,10,1000] if quick else [1,10,1000,10000,100000]):
        t=History();a=time.perf_counter_ns()
        for i in range(n):t.append(enc('synthetic-lifecycle',i,b'x'*96))
        build_ms=(time.perf_counter_ns()-a)/1e6;i=n//3;m=n//2+1 if n>1 else 1
        path=t.inclusion(i);cp=t.consistency(m);old=t.root(m);root=t.root()
        for rep in range(100):
            g,_=timed(lambda:t.inclusion(i,n));v,ok=timed(lambda:verify_inclusion(t.leaves[i],i,n,path,root));assert ok
            c,ok=timed(lambda:verify_consistency(m,n,old,root,cp));assert ok
            ap,_=timed(lambda:t.append(enc('append',rep,n)))
            raw.append({'tree':'history','size':n,'run':rep,'proof_gen_ms':g,'verify_ms':v,'update_or_append_ms':ap})
            # separate consistency metric retained without changing raw schema
            raw.append({'tree':'history-consistency','size':n,'run':rep,'proof_gen_ms':0,'verify_ms':c,'update_or_append_ms':0})
        vals=[r for r in raw if r['tree']=='history' and r['size']==n]
        cs=[r['verify_ms'] for r in raw if r['tree']=='history-consistency' and r['size']==n]
        log_rows.append({'L':n,'old_prefix':m,'build_ms':build_ms,'inclusion_nodes':len(path),'consistency_nodes':len(cp),
            'inclusion_bytes':32*len(path),'consistency_bytes':32*len(cp),
            'inclusion_verify_us':1000*float(np.median([r['verify_ms'] for r in vals])),
            'consistency_verify_us':1000*float(np.median(cs)),
            'append_us':1000*float(np.median([r['update_or_append_ms'] for r in vals]))})
    csvwrite(out/'tree_raw.csv',raw);csvwrite(out/'status_scaling.csv',status_rows);csvwrite(out/'history_scaling.csv',log_rows)
    return status_rows,log_rows

def networking(out,runs=30):
    rows=[];summary={};m,ws=fixture()
    for delay in [0,2,10]:
        with tempfile.TemporaryDirectory() as tmp, NetworkConsortium({m.name:m.pub},tmp,delay) as n:
            for rep in range(runs+3):
                ms,result=timed(lambda:n.finalize([m.package()]))
                _,a,bytecount=result
                assert FinalityVerifier(n.pubs).verify(m.cps[-1],a)[0]==len(n.chain)
                if rep>=3:rows.append({'delay_per_rpc_ms':delay,'run':rep-3,'commit_and_replication_ms':ms,'application_bytes':bytecount})
        summary[str(delay)]=stats([r['commit_and_replication_ms'] for r in rows if r['delay_per_rpc_ms']==delay])
    with tempfile.TemporaryDirectory() as tmp,NetworkConsortium({m.name:m.pub},tmp) as n:
        n.processes[3].terminate();n.processes[3].join()
        ms,(_,a,b)=timed(lambda:n.finalize([m.package()]));one_ok=bool(FinalityVerifier(n.pubs).verify(m.cps[-1],a))
        n.processes[2].terminate();n.processes[2].join()
        try:n.finalize([m.package()]);two_closed=False
        except ValueError:two_closed=True
    output(out/'network_failures.json',{'one_terminated_process_committed':one_ok,'one_failure_ms':ms,'two_terminated_processes_fail_closed':two_closed,
        'transport':'loopback TCP','delay_model':'server sleep once per RPC; not WAN RTT','view_change':False})
    csvwrite(out/'network_raw.csv',rows);output(out/'network_summary.json',summary)
    return summary

def wire(out):
    rows=[];packets=[];m,ws=fixture();o=Offer(b'a'*32,b'b'*32,b'c'*32)
    for length in [42,128,240,255]:
        prefix='https://example.invalid/';d=replace(m.devices[0].start(),url=prefix+'a'*(length-len(prefix)))
        assert decode_discover(discover_options(d))==d
        for typ,label,custom in [(1,'Discover',discover_options(d)),(2,'Offer',offer_options(o)),(3,'Request',request_options(123,o))]:
            payload=dhcp(typ,length,custom);packet=ipv4_udp(payload,typ==2);packets.append(packet)
            rows.append({'url_bytes':length,'message':label,'custom_options_bytes':len(custom),'dhcp_payload_bytes':len(payload),'ipv4_udp_bytes':len(packet)})
    csvwrite(out/'wire_sizes.csv',rows);write_pcap(out/'synthetic_dhcp.pcap',packets);return rows

def anchoring(out,runs):
    rows=[];raw=[];base=Manufacturer(1,T)
    for B in [1,2,5,10,20,50,100]:
        ms=[Manufacturer(1,T,cls=f'class-{i}',key=base.key) for i in range(B)];packages=[m.package() for m in ms]
        con=Consortium({base.name:base.pub});p,a=con.finalize(packages);b=a.chain[-1]
        # Minimal finalized certificate retains exactly 3 distinct commits, not the 4 responses.
        b=replace(b,commits=b.commits[:3]);a=replace(a,chain=[b])
        encoded=enc('ORBIT-FINALIZED-v2',b.header.body())+b''.join(enc(v.identity,v.stage,v.signature) for v in b.commits)
        payload_bytes=sum(len(anchor_body(m.cps[-1])) for m in ms)
        for rep in range(runs):
            v,ok=timed(lambda:FinalityVerifier(con.pubs).verify(ms[0].cps[-1],a));assert ok
            raw.append({'batch':B,'run':rep,'verify_ms':v})
        rows.append({'batch':B,'header_certificate_bytes':len(encoded),'bytes_per_checkpoint':len(encoded)/B,
            'all_anchor_payload_bytes':payload_bytes,'inclusion_bytes':32*len(a.path),'verify_ms':float(np.median([r['verify_ms'] for r in raw if r['batch']==B]))})
    csvwrite(out/'anchoring_raw.csv',raw);csvwrite(out/'anchoring_summary.csv',rows);return rows

def security_matrix(out):
    rows=[]
    for mode in ['B1','B2','B3','B4','B5','B6']:
        for scenario in ['active','unregistered-key','revoked','full-package-rollback','expired-checkpoint']:
            m,ws=fixture();k=scalar();P=public(k);p=m.package();now=T
            if mode in ('B1','B2','B3'):
                b=Baseline(mode,m.pub,P)
                if scenario=='full-package-rollback':
                    old=p;m.publish(T+1,version=2);assert b.admit(m.package().file,m.url,k);p=old
                if scenario=='revoked':m.set_status(0,'revoked');m.publish(T+1);p=m.package()
                accepted=b.admit(p.file,p.file.url,scalar() if scenario=='unregistered-key' else k)
            else:
                con=Consortium({m.name:m.pub});_,a=con.finalize([p]);c=ctrl(m,ws,mode,con.pubs)
                device=m.devices[0]
                if scenario=='full-package-rollback':
                    old,olda=p,a;c.admit('port-0',1,device,p,T,a);m.publish(T+1,version=2);m.endorse(ws,T+1)
                    new=m.package(old_size=1);_,a=con.finalize([new]);c.admit('port-0',2,device,new,T+1,a);p,a=old,olda;now=T+2
                if scenario=='revoked':
                    m.set_status(0,'revoked');m.publish(T+1);m.endorse(ws,T+1);p=m.package(old_size=1);_,a=con.finalize([p]);now=T+1
                if scenario=='expired-checkpoint':now=T+7200
                if scenario=='unregistered-key':device=Device(0,m.url)
                try:accepted=c.admit('port-0',3,device,p,now,a)
                except Rejection:accepted=False
            expected=(scenario=='active' or (mode=='B1') or (scenario=='revoked' and mode in ('B2','B3')) or (scenario=='full-package-rollback' and mode=='B2') or (scenario=='expired-checkpoint' and mode in ('B2','B3')))
            assert bool(accepted)==expected,(mode,scenario,accepted,expected)
            rows.append({'configuration':mode,'scenario':scenario,'accepted':bool(accepted)})
    csvwrite(out/'security_matrix.csv',rows)
    pairs=[]
    for n,q in [(3,2),(4,3)]:
        count=bad=0
        for A in itertools.combinations(range(n),q):
            for B in itertools.combinations(range(n),q):
                for F in itertools.combinations(range(n),1):
                    count+=1;bad+=int(set(A)&set(B)<=set(F))
        pairs.append({'n':n,'q':q,'faulty':1,'combinations':count,'no_honest_intersection':bad})
    output(out/'quorum_exhaustive.json',pairs);return rows

def main():
    if os.environ.get('ORBIT_DEBUG'):
        import faulthandler
        faulthandler.dump_traceback_later(30,repeat=True)
    ap=argparse.ArgumentParser();ap.add_argument('--out',default='results');ap.add_argument('--runs',type=int,default=200);ap.add_argument('--quick',action='store_true');ap.add_argument('--section',choices=['all','latency','scaling','network','wire','anchoring','security'],default='all');args=ap.parse_args()
    out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    aff=sorted(os.sched_getaffinity(0)) if hasattr(os,'sched_getaffinity') else []
    if aff:os.sched_setaffinity(0,{aff[0]})
    meta={'python':sys.version,'cryptography':cryptography.__version__,'platform':platform.platform(),'openssl_system':ssl.OPENSSL_VERSION,
        'cpu_model':next((l.split(':',1)[1].strip() for l in Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')),'unknown'),
        'affinity_before':aff,'affinity_during':sorted(os.sched_getaffinity(0)) if aff else [],'runs':args.runs,'bootstrap_resamples':4000,'seed':SEED,
        'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'timing_clock':'perf_counter_ns','warmup_per_latency_condition':10,
        'scope':'native P-256 reference on one pinned Linux CPU; no constrained hardware; loopback validators share host and CPU'}
    if args.section=='all' or not (out/'environment.json').exists():output(out/'environment.json',meta)
    for name,fn in [('latency',lambda:latency(out,args.runs)),('scaling',lambda:scaling(out,args.quick)),('network',lambda:networking(out,5 if args.quick else 30)),('wire',lambda:wire(out)),('anchoring',lambda:anchoring(out,args.runs)),('security',lambda:security_matrix(out))]:
        if args.section not in ('all',name):continue
        print('START',name,flush=True);result=fn();print('DONE',name,flush=True)
    meta=json.loads((out/'environment.json').read_text());meta['last_completed_section']=args.section;meta['finished_utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime());output(out/'environment.json',meta)

if __name__=='__main__':main()
