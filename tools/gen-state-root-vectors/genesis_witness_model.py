# SPDX-License-Identifier: GPL-3.0-only
"""Selected-path update oracle; initial witnesses are independently derived."""
import hashlib,struct
ZERO=b"\0"*32
def digest(raw):return hashlib.sha3_256(raw).digest()
def parent(a,b):return ZERO if a==ZERO and b==ZERO else digest(a+b)
class Forest:
 def __init__(self,root,rows):
  self.nodes={(0,0):root};self.values={};self.positions=set()
  def put(key,value):
   if key in self.nodes:assert self.nodes[key]==value
   else:self.nodes[key]=value
  for row in rows:
   raw=bytes.fromhex(row["proof"]);position=bytes.fromhex(row["path"]);index=int.from_bytes(position,"big")
   assert raw[1:33]==position and raw[0] in (0,1)
   self.positions.add(position)
   if raw[0]:
    value=bytes.fromhex(row["value"]);self.values[position]=value;assert raw[33:65]==digest(position+value)
   else:assert raw[33:65]==ZERO and row["value"] is None
   put((256,index),raw[33:65]);count=int.from_bytes(raw[97:99],"big");offset=99;seen=0
   for height in range(256):
    sibling=ZERO
    if raw[65+height//8]&(1<<(7-height%8)):
     sibling=raw[offset:offset+32];assert len(sibling)==32 and sibling!=ZERO;offset+=32;seen+=1
    put((256-height,(index>>height)^1),sibling)
   assert seen==count
 def update(self,position,value):
  assert position in self.positions and (value is None or type(value)is bytes)
  if value is None:self.values.pop(position,None)
  else:self.values[position]=value
  index=int.from_bytes(position,"big");current=ZERO if value is None else digest(position+value)
  self.nodes[(256,index)]=current
  for depth in range(256,0,-1):
   sibling=self.nodes.get((depth,index^1),ZERO)
   current=parent(sibling,current) if index&1 else parent(current,sibling)
   index>>=1;self.nodes[(depth-1,index)]=current
  return current
 def root(self):return self.nodes[(0,0)]
 def proof(self,position):
  assert position in self.positions
  index=int.from_bytes(position,"big");value=self.values.get(position);present=position in self.values
  mask=bytearray(32);siblings=[]
  for height in range(256):
   sibling=self.nodes.get((256-height,(index>>height)^1),ZERO)
   if sibling!=ZERO:mask[height//8]|=1<<(7-height%8);siblings.append(sibling)
  leaf=ZERO if not present else digest(position+value)
  raw=bytes([int(present)])+position+leaf+bytes(mask)+struct.pack(">H",len(siblings))+b"".join(siblings)
  return raw+(struct.pack(">I",len(value))+value if present else b"")
