# SPDX-License-Identifier: GPL-3.0-only
"""Bounded sparse-root/proof model retaining two layers and selected witnesses."""
import hashlib,struct
ZERO=b"\0"*32
def digest(raw):return hashlib.sha3_256(raw).digest()
def model(paths,targets):
 assert type(paths)is dict and len(paths)<=100000 and all(type(k)is bytes and len(k)==32 and type(v)is bytes for k,v in paths.items())
 assert type(targets)is list and len(targets)<=128 and len(set(targets))==len(targets)
 assert all(type(k)is bytes and len(k)==32 for k in targets)
 values={int.from_bytes(k,"big"):v for k,v in paths.items()}
 layer={i:digest(i.to_bytes(32,"big")+v) for i,v in values.items()}
 witnesses={p:[] for p in targets};peak=len(layer);hashes=len(layer)
 for height in range(256):
  for target in targets:witnesses[target].append(layer.get((int.from_bytes(target,"big")>>height)^1,ZERO))
  parents={}
  for index,current in layer.items():
   sibling=layer.get(index^1,ZERO)
   if index&1:
    if (index^1) in layer:continue
    left,right=sibling,current
   else:left,right=current,sibling
   result=ZERO if left==ZERO and right==ZERO else digest(left+right)
   hashes+=int(result!=ZERO)
   if result!=ZERO:parents[index>>1]=result
  layer=parents
  peak=max(peak,len(layer))
 root=layer.get(0,ZERO);proofs={}
 for target in targets:
  index=int.from_bytes(target,"big");present=index in values;value=values.get(index,b"")
  mask=bytearray(32);nonzero=[]
  for height,sibling in enumerate(witnesses[target]):
   if sibling!=ZERO:
    mask[height//8]|=1<<(7-height%8);nonzero.append(sibling)
  leaf=digest(target+value) if present else ZERO
  proof=bytes([int(present)])+target+leaf+bytes(mask)+struct.pack(">H",len(nonzero))+b"".join(nonzero)
  if present:proof+=struct.pack(">I",len(value))+value
  proofs[target]=proof
 return root,proofs,{"peak_single_layer_entries":peak,"sparse_parent_and_leaf_hashes":hashes,"full_256_layer_graph_retained":False,"selected_witness_paths":len(targets)}
