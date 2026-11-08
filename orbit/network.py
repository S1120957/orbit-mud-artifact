"""Four independent validator processes over loopback TCP for experiment use.
Signed messages authenticate votes. Framing is length-prefixed JSON.
"""
import concurrent.futures,json,multiprocessing as mp,socket,struct,time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from .crypto import signing_key,signing_public
from .model import to_wire,from_wire,ZERO
from .ledger import Validator,make_proposal,make_anchor,Block,votes_valid
from .storage import Store

def _read(sock,n):
    out=b''
    while len(out)<n:
        chunk=sock.recv(n-len(out))
        if not chunk:raise ConnectionError('short frame')
        out+=chunk
    return out

def _recv(sock):
    n=struct.unpack('!I',_read(sock,4))[0]
    if n>16*1024*1024:raise ValueError('RPC too large')
    return from_wire(json.loads(_read(sock,n)))

def _send(sock,obj):
    b=json.dumps(to_wire(obj),separators=(',',':')).encode();sock.sendall(struct.pack('!I',len(b))+b)
    return len(b)+4

def _serve(name,key_pem,manufacturers,pubs,path,delay_ms,pipe):
    k=serialization.load_pem_private_key(key_pem,password=None)
    st=Store(path,b'N'*32,bootstrap=True)
    v=Validator(name,manufacturers,pubs,k,st)
    s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',0));s.listen()
    pipe.send(s.getsockname()[1]);pipe.close()
    try:
        running=True
        while running:
            conn,_=s.accept()
            with conn:
                try:
                    r=_recv(conn);cmd=r['command']
                    if cmd=='stop':running=False;result=True
                    else:
                        time.sleep(delay_ms/1000)
                        if cmd=='prepare':result=v.prepare(r['proposal'])
                        elif cmd=='commit':result=v.commit(r['proposal'],r['votes'])
                        elif cmd=='finalize':result=v.finalize(r['proposal'],r['votes'])
                        else:raise ValueError('unknown command')
                    _send(conn,{'ok':True,'result':result})
                except Exception as e:
                    _send(conn,{'ok':False,'error':str(e)})
    finally:s.close();st.close()

class NetworkConsortium:
    def __init__(self,manufacturers,directory,delay_ms=0):
        Path(directory).mkdir(parents=True,exist_ok=True)
        keys=[signing_key() for _ in range(4)]
        self.pubs={f'validator-{i}':signing_public(k) for i,k in enumerate(keys)}
        self.processes=[];self.ports=[];self.chain=[];self.bytes=0
        ctx=mp.get_context('spawn')
        for i,k in enumerate(keys):
            parent,child=ctx.Pipe(False)
            pem=k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
            p=ctx.Process(target=_serve,args=(f'validator-{i}',pem,manufacturers,self.pubs,str(Path(directory)/f'v{i}.db'),delay_ms,child))
            p.start();child.close();self.ports.append(parent.recv());parent.close();self.processes.append(p)
    def rpc(self,i,command,proposal=None,votes=None):
        with socket.create_connection(('127.0.0.1',self.ports[i]),timeout=0.75) as s:
            sent=_send(s,{'command':command,'proposal':proposal,'votes':votes});r=_recv(s)
        if not r['ok']:raise ValueError(r['error'])
        # Exact application JSON framing; excludes TCP/IP retransmits, ACKs and handshake.
        received=len(json.dumps(to_wire(r),separators=(',',':')).encode())+4
        return r['result'],sent+received
    def finalize(self,packages,available=None):
        selected=list(range(4)) if available is None else list(available)
        prev=self.chain[-1].header.digest() if self.chain else ZERO
        p=make_proposal(packages,len(self.chain)+1,prev);wire_bytes=0
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            def collect(command,votes=None):
                futures=[pool.submit(self.rpc,i,command,p,votes) for i in selected];results=[]
                for f in concurrent.futures.as_completed(futures):
                    try:results.append(f.result())
                    except (OSError,ValueError,ConnectionError):pass
                return results
            prepare_results=collect('prepare')
            prepares=[r[0] for r in prepare_results];wire_bytes+=sum(r[1] for r in prepare_results)
            if not votes_valid(prepares,'prepare',p.header,self.pubs):raise ValueError('prepare-quorum-unavailable')
            commit_results=collect('commit',prepares)
            commits=[r[0] for r in commit_results];wire_bytes+=sum(r[1] for r in commit_results)
            if not votes_valid(commits,'commit',p.header,self.pubs):raise ValueError('commit-quorum-unavailable')
            final_results=collect('finalize',commits);wire_bytes+=sum(r[1] for r in final_results)
        block=Block(p.header,sorted(commits,key=lambda v:v.identity)[:3]);self.chain.append(block);self.bytes+=wire_bytes
        return p,make_anchor(p,self.chain),wire_bytes
    def close(self):
        for i,p in enumerate(self.processes):
            try:self.rpc(i,'stop')
            except Exception:pass
            p.join(3)
            if p.is_alive():p.terminate();p.join()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
