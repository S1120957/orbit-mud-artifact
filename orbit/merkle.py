"""Incremental fixed-capacity status tree and RFC6962/9162-shaped history tree."""
from __future__ import annotations
from .crypto import H

def lh(v:bytes)->bytes: return H(b'\x00'+v)
def nh(a:bytes,b:bytes)->bytes: return H(b'\x01'+a+b)
EMPTY=H(b'')

class StatusTree:
    def __init__(self, digests:list[bytes]):
        if not digests or any(len(x)!=32 for x in digests): raise ValueError('32-byte nonempty leaves')
        self.n=len(digests); cap=1<<(self.n-1).bit_length()
        self.levels=[list(digests)+[lh(b'ORBIT-PAD-v2')]*(cap-self.n)]
        while len(self.levels[-1])>1:
            a=self.levels[-1]; self.levels.append([nh(a[i],a[i+1]) for i in range(0,len(a),2)])
    @property
    def root(self):return self.levels[-1][0]
    def proof(self,i:int):
        if not 0<=i<self.n:raise ValueError('index')
        path=[]
        for a in self.levels[:-1]:path.append(a[i^1]);i//=2
        return path
    def update(self,i:int,digest:bytes):
        if not 0<=i<self.n or len(digest)!=32:raise ValueError('leaf')
        self.levels[0][i]=digest
        for h in range(1,len(self.levels)):
            i//=2;a=self.levels[h-1];self.levels[h][i]=nh(a[2*i],a[2*i+1])
    @staticmethod
    def verify(digest,i,n,path,root):
        if n<1 or not 0<=i<n or len(path)!=(n-1).bit_length():return False
        for sibling in path:
            if len(sibling)!=32:return False
            digest=nh(sibling,digest) if i&1 else nh(digest,sibling);i//=2
        return digest==root

class History:
    """Caches complete dyadic subtrees; append changes O(log L) cached nodes."""
    def __init__(self):self.leaves=[];self.nodes={}
    def append(self,body:bytes):
        i=len(self.leaves);d=lh(body);self.leaves.append(d);self.nodes[i,1]=d
        width=1;start=i
        while start % (2*width)==width:
            d=nh(self.nodes[start-width,width],d);start-=width;width*=2
            self.nodes[start,width]=d
        return i
    def subroot(self,start:int,n:int):
        if n==0:return EMPTY
        if (start,n) in self.nodes:return self.nodes[start,n]
        k=1<<((n-1).bit_length()-1)
        return nh(self.subroot(start,k),self.subroot(start+k,n-k))
    def root(self,n:int|None=None):
        n=len(self.leaves) if n is None else n
        if not 0<=n<=len(self.leaves):raise ValueError('tree size')
        return self.subroot(0,n)
    def inclusion(self,i:int,n:int|None=None):
        n=len(self.leaves) if n is None else n
        if not 0<=i<n<=len(self.leaves):raise ValueError('index/size')
        def rec(i,start,n):
            if n==1:return []
            k=1<<((n-1).bit_length()-1)
            if i<k:return rec(i,start,k)+[self.subroot(start+k,n-k)]
            return rec(i-k,start+k,n-k)+[self.subroot(start,k)]
        return rec(i,0,n)
    def consistency(self,m:int,n:int|None=None):
        n=len(self.leaves) if n is None else n
        if not 0<=m<=n<=len(self.leaves):raise ValueError('size')
        if m==0 or m==n:return []
        def rec(m,start,n,complete):
            if m==n:return [] if complete else [self.subroot(start,n)]
            k=1<<((n-1).bit_length()-1)
            if m<=k:return rec(m,start,k,complete)+[self.subroot(start+k,n-k)]
            return rec(m-k,start+k,n-k,False)+[self.subroot(start,k)]
        return rec(m,0,n,True)

def verify_inclusion(digest:bytes,i:int,n:int,path:list[bytes],root:bytes)->bool:
    if n<1 or i<0 or i>=n:return False
    it=iter(path)
    def rec(i,n):
        if n==1:return digest
        k=1<<((n-1).bit_length()-1)
        if i<k:return nh(rec(i,k),next(it))
        a=rec(i-k,n-k);return nh(next(it),a)
    try:
        result=rec(i,n)
        try:next(it);return False
        except StopIteration:return result==root
    except (StopIteration,TypeError):return False

def verify_consistency(m:int,n:int,old:bytes,new:bytes,path:list[bytes])->bool:
    if not 0<=m<=n:return False
    if m==0:return not path and old==EMPTY
    if m==n:return not path and old==new
    if not path:return False
    fn=m-1;sn=n-1
    while fn&1:fn>>=1;sn>>=1
    ix=0
    if fn==0:fr=sr=old
    else:fr=sr=path[0];ix=1
    for p in path[ix:]:
        if sn==0 or len(p)!=32:return False
        if fn&1 or fn==sn:
            fr=nh(p,fr);sr=nh(p,sr)
            while fn and not(fn&1):fn>>=1;sn>>=1
        else:sr=nh(sr,p)
        fn>>=1;sn>>=1
    return sn==0 and fr==old and sr==new
