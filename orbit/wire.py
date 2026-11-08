"""Experimental DHCPv4 option encoding and synthetic IPv4/UDP PCAP export.
Option 224 is PRIVATE USE. These packets are serialized fixtures.
"""
import socket,struct
from .model import Discover,Offer
PRIVATE=224
MAGIC=b'\x63\x82\x53\x63'

def option(code,data):
    if not 0<code<255 or len(data)>255:raise ValueError('single DHCP option overflow')
    return bytes([code,len(data)])+data

def discover_options(d:Discover):
    data=struct.pack('!BII',2,d.index,d.epoch)+d.pub+d.commitment
    return option(161,d.url.encode())+option(PRIVATE,data)

def offer_options(o:Offer):return option(PRIVATE,b'\x02'+o.nonce+o.lifecycle+o.binding)
def request_options(z:int,o:Offer):return option(PRIVATE,b'\x02'+z.to_bytes(32,'big')+o.nonce)

def options_parse(data):
    i=0;out={}
    while i<len(data):
        tag=data[i];i+=1
        if tag==255:break
        if tag==0:continue
        if i>=len(data):raise ValueError('truncated length')
        n=data[i];i+=1
        if i+n>len(data) or tag in out:raise ValueError('truncated/duplicate option')
        out[tag]=data[i:i+n];i+=n
    return out

def decode_discover(options):
    d=options_parse(options);v,i,e=struct.unpack('!BII',d[PRIVATE][:9])
    if v!=2 or len(d[PRIVATE])!=75:raise ValueError('wire version/length')
    return Discover(d[161].decode(),i,e,d[PRIVATE][9:42],d[PRIVATE][42:75])

def decode_offer(options):
    b=options_parse(options)[PRIVATE]
    if len(b)!=97 or b[0]!=2:raise ValueError('offer length')
    return Offer(b[1:33],b[33:65],b[65:97])

def dhcp(message_type,xid,custom):
    mac=b'\x02\x00\x00\x00\x00\x01'
    head=struct.pack('!BBBBIHH4s4s4s4s16s64s128s',2 if message_type in (2,5) else 1,1,6,0,xid,0,0x8000,
        b'\0'*4,b'\0'*4,b'\0'*4,b'\0'*4,mac+b'\0'*10,b'\0'*64,b'\0'*128)
    ordinary=option(53,bytes([message_type]))+option(61,b'\x01'+mac)+option(57,struct.pack('!H',576))+option(55,bytes([1,3,6]))
    return head+MAGIC+ordinary+custom+b'\xff'

def checksum(b):
    if len(b)&1:b+=b'\0'
    n=sum(struct.unpack('!'+('H'*(len(b)//2)),b));n=(n>>16)+(n&65535);n+=(n>>16)
    return (~n)&65535

def ipv4_udp(payload,server=False):
    src=socket.inet_aton('192.0.2.1' if server else '0.0.0.0');dst=socket.inet_aton('255.255.255.255')
    sp,dp=(67,68) if server else (68,67);length=len(payload)+8
    hdr=struct.pack('!HHHH',sp,dp,length,0)
    cs=checksum(src+dst+struct.pack('!BBH',0,17,length)+hdr+payload) or 65535
    udp=struct.pack('!HHHH',sp,dp,length,cs)+payload
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),0,0,64,17,0,src,dst)
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return ip+udp

def write_pcap(path,packets):
    with open(path,'wb') as f:
        f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,101)) # LINKTYPE_RAW
        for i,b in enumerate(packets):f.write(struct.pack('<IIII',1700000000,i*1000,len(b),len(b))+b)
