#!/usr/bin/env python3
"""Reproduce the public 1200-byte VK Initial; no WARP keys or network access.

Requires python3-cryptography only for regeneration/verification. The generated
resource is shipped with the application. Packet protection follows RFC 9001,
sections 5.2, 5.3 and 5.4. The complete authenticated CRYPTO content is preserved.
"""
from pathlib import Path
import argparse,hashlib,hmac,struct
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PIN='f86d488593a65132c10e7e5b5e02f32ff8e0862988b30bebc6a671c5380f3976'
SALT=bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a')
def expand(secret,label,n):
    label=b'tls13 '+label;info=struct.pack('!H',n)+bytes([len(label)])+label+b'\0'
    return hmac.new(secret,info+b'\x01',hashlib.sha256).digest()[:n]
def var(data,pos):
    size=1<<(data[pos]>>6)
    if pos+size>len(data):raise ValueError('Truncated varint')
    return int.from_bytes(data[pos:pos+size],'big')&((1<<(size*8-2))-1),pos+size
def aes_block(key,data):
    encryptor=Cipher(algorithms.AES(key),modes.ECB()).encryptor()
    return encryptor.update(data)+encryptor.finalize()
def decode(data):
    packet=bytearray(data)
    if len(packet)<64 or packet[1:5]!=b'\0\0\0\x01':raise ValueError('Expected QUIC v1')
    pos=5;dcid=bytes(packet[pos+1:pos+1+packet[pos]]);pos+=1+packet[pos];pos+=1+packet[pos]
    token,pos=var(packet,pos);pos+=token;length_offset=pos;length,pn_offset=var(packet,pos)
    secret=expand(hmac.new(SALT,dcid,hashlib.sha256).digest(),b'client in',32)
    key=expand(secret,b'quic key',16);iv=expand(secret,b'quic iv',12);hp=expand(secret,b'quic hp',16)
    mask=aes_block(hp,bytes(packet[pn_offset+4:pn_offset+20]));packet[0]^=mask[0]&15
    pn_len=(packet[0]&3)+1
    for i in range(pn_len):packet[pn_offset+i]^=mask[i+1]
    header=bytes(packet[:pn_offset+pn_len]);pn=int.from_bytes(header[pn_offset:],'big')
    nonce=bytes(a^b for a,b in zip(iv,pn.to_bytes(12,'big')))
    plain=AESGCM(key).decrypt(nonce,bytes(packet[len(header):pn_offset+length]),header)
    return header,plain,key,nonce,hp,length_offset,pn_offset,pn_len
def compact(original):
    header,plain,key,nonce,hp,length_offset,pn_offset,pn_len=decode(original)
    if pn_offset-length_offset!=2 or len(plain)>1200-len(header)-16:raise ValueError('Initial cannot be safely resized')
    header=bytearray(header);header[length_offset:pn_offset]=struct.pack('!H',(1200-pn_offset)|0x4000)
    plain=plain+b'\0'*(1200-len(header)-16-len(plain))
    result=header+AESGCM(key).encrypt(nonce,plain,bytes(header))
    mask=aes_block(hp,bytes(result[pn_offset+4:pn_offset+20]));result[0]^=mask[0]&15
    for i in range(pn_len):result[pn_offset+i]^=mask[i+1]
    # Independent decrypt checks the new tag/AAD, header protection and payload.
    _,verified,*_=decode(result)
    if verified!=plain or len(result)!=1200:raise ValueError('Invalid compact Initial')
    return bytes(result)
def main():
    root=Path(__file__).resolve().parents[1]
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');args=p.parse_args()
    source=(root/'vendor/runtime/blobs/quic_vk.bin').read_bytes()
    if PIN and hashlib.sha256(source).hexdigest()!=PIN:raise ValueError('Upstream VK blob changed')
    result=compact(source);target=root/'resources/quic_vk_1200.bin'
    if args.check:
        if target.read_bytes()!=result:raise ValueError('Compact VK resource changed')
    else:target.write_bytes(result)
    print('VK Initial: full authenticated payload preserved; 1357 ->',len(result),'bytes; SHA256',hashlib.sha256(result).hexdigest())
if __name__=='__main__':main()
