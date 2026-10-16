# SPDX-License-Identifier: GPL-3.0-only
"""Independent source-address and complete batch-input checks for finite research."""
import hashlib,json
CHARSET="qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech(raw,hrp,size):
 assert type(raw)is str and raw==raw.lower()
 before,separator,data=raw.rpartition("1")
 assert separator and before==hrp and len(data)>6
 values=[CHARSET.index(c) for c in data]
 check=1
 for v in [ord(c)>>5 for c in hrp]+[0]+[ord(c)&31 for c in hrp]+values:
  top=check>>25;check=((check&0x1ffffff)<<5)^v
  for bit,constant in enumerate((0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3)):
   if (top>>bit)&1:check^=constant
 assert check==1
 result=bytearray();accumulator=bits=0
 for value in values[:-6]:
  accumulator=(accumulator<<5)|value;bits+=5
  while bits>=8:
   bits-=8;result.append((accumulator>>bits)&255)
 assert bits<5 and ((accumulator<<(8-bits))&255)==0
 assert len(result)==size
 return bytes(result)
def balances(config):
 out={}
 for row in config["GenesisBlocks"]["Blocks"]:
  address=bech(row["Address"],"z",20)
  for token,value in row["BalanceList"].items():
   key=b"\x03"+address+b"\x03"+bech(token,"zts",10)
   amount=int(value);assert 0<=amount<1<<256 and key not in out
   out[key]=amount.to_bytes(32,"big")
 assert len(out)==14091
 return out
def counts_and_state(raw,parser):
 indexed,error=parser.indexes(raw);assert error is None and len(indexed)<=1000000
 result={"Puts":0,"Deletes":0,"KeyBytes":0,"ValueBytes":0,"BalancePuts":0,"StoragePuts":0};state={}
 for kind,kpos,klen,vpos,vlen in indexed:
  key=raw[kpos:kpos+klen];value=raw[vpos:vpos+vlen]
  result["KeyBytes"]+=len(key)
  if kind:
   result["Puts"]+=1;result["ValueBytes"]+=len(value);state[key]=value
   if len(key)>=22 and key[0]==3:
    if key[21]==3:result["BalancePuts"]+=1
    if key[21]==4:result["StoragePuts"]+=1
  else:result["Deletes"]+=1;state.pop(key,None)
 return result,state
def mapping_sha(items):
 h=hashlib.sha256()
 for key,value in sorted(items.items()):
  h.update(len(key).to_bytes(8,"big"));h.update(key)
  h.update(len(value).to_bytes(8,"big"));h.update(value)
 return h.hexdigest()
