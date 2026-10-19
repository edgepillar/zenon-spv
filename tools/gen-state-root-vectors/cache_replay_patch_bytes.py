#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Independent byte checks for the selected recorded v1 ledger patch metadata.

The LevelDB Batch.Dump operation records have no log batch header. Manager.Add
appends three SetFrontier puts to the source changes. This reader checks that
framing, full identifiers, ordered account headers, the v1 SHA3 frame and the
concatenated patch digest. It does not authenticate a network header, establish
canonicality, validate source-patch execution or accept a state value.
"""
import hashlib
import struct
import re

MAX_METADATA_BYTES = 4 << 20
MAX_SOURCE_BYTES = 16 << 20
MAX_HEADERS = 40000
MAX_PROTO_FIELDS = MAX_HEADERS + 9

def _hex32(value):
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise ValueError("A canonical selected hash is required")
    return bytes.fromhex(value)

def _uint64(value, minimum=0):
    if type(value) is not int or not minimum <= value < 1 << 64:
        raise ValueError("A selected uint64 is required")
    return value

def uvar(raw, offset):
    if type(raw) is not bytes or type(offset) is not int or not 0 <= offset <= len(raw):
        raise ValueError("Bounded bytes and a valid offset are required")
    start=offset
    value=0
    for index in range(10):
        if offset>=len(raw):raise ValueError("Truncated varint")
        byte=raw[offset];offset+=1
        if index==9 and byte>1:raise ValueError("Varint overflow")
        value|=(byte&127)<<(index*7)
        if byte<128:
            if raw[start:offset]!=encode_uvar(value):raise ValueError("Noncanonical varint")
            return value,offset
    raise ValueError("Oversized varint")

def encode_uvar(value):
    if type(value)is not int or not 0<=value<1<<64:raise ValueError("Unsigned integer required")
    result=bytearray()
    while value>=128:
        result.append((value&127)|128);value>>=7
    result.append(value)
    return bytes(result)

def fields(raw,repeated=()):
    if type(raw)is not bytes or len(raw)>MAX_METADATA_BYTES:raise ValueError("Bounded protobuf bytes required")
    result={};offset=0;previous=0;count=0
    while offset<len(raw):
        token,offset=uvar(raw,offset);number,wire=token>>3,token&7
        if not 0<number<1<<29 or number<previous:raise ValueError("Unexpected protobuf field ordering")
        previous=number;count+=1
        if count>MAX_PROTO_FIELDS:raise ValueError("Protobuf field count exceeded")
        if wire==0:value,offset=uvar(raw,offset)
        elif wire==2:
            length,offset=uvar(raw,offset)
            if length>len(raw)-offset:raise ValueError("Truncated protobuf value")
            value=raw[offset:offset+length];offset+=length
        else:raise ValueError("Unsupported protobuf wire type")
        if number in repeated:result.setdefault(number,[]).append((wire,value))
        else:
            if number in result:raise ValueError("Duplicate protobuf scalar")
            result[number]=(wire,value)
    return result

def one(document,number,wire,default=None):
    if number not in document:return default
    actual,value=document[number]
    if actual!=wire:raise ValueError("Wrong protobuf wire type")
    return value

def hash_value(raw):
    document=fields(raw)
    if set(document)!={1}:raise ValueError("Unexpected hash protobuf")
    value=one(document,1,2)
    if type(value)is not bytes or len(value)!=32:raise ValueError("Wrong hash width")
    return value

def hash_height(raw,expected_hash,height):
    document=fields(raw)
    if set(document)!={1,2}or hash_value(one(document,1,2))!=expected_hash or one(document,2,0)!=height:
        raise ValueError("Wrong full frontier identifier")

def metadata_records(raw):
    if type(raw)is not bytes or not 0<len(raw)<=MAX_METADATA_BYTES:raise ValueError("Metadata batch exceeds its cap")
    rows=[];offset=0
    while offset<len(raw):
        if len(rows)>=3 or raw[offset]!=1:raise ValueError("Expected exactly three put operations")
        offset+=1;length,offset=uvar(raw,offset)
        if not 0<length<=64 or length>len(raw)-offset:raise ValueError("Invalid metadata key")
        key=raw[offset:offset+length];offset+=length
        length,offset=uvar(raw,offset)
        if length>len(raw)-offset:raise ValueError("Invalid metadata value")
        value=raw[offset:offset+length];offset+=length;rows.append((key,value))
    if len(rows)!=3:raise ValueError("Metadata put count differs")
    return rows

def verify_metadata(raw,identifier,previous_hash,timestamp,changes_hash,content_count):
    if type(identifier) is not dict or set(identifier) != {"hash", "height"}:
        raise ValueError("An exact selected identifier is required")
    digest = _hex32(identifier["hash"])
    height = _uint64(identifier["height"], 1)
    previous_hash_bytes = _hex32(previous_hash)
    timestamp = _uint64(timestamp)
    if type(changes_hash) is not bytes or len(changes_hash) != 32:
        raise ValueError("A selected changes hash is required")
    if type(content_count) is not int or not 0 <= content_count <= MAX_HEADERS:
        raise ValueError("A bounded selected account count is required")
    if len(digest)!=32 or type(height)is not int or not 1<=height<1<<64:raise ValueError("Wrong selected identifier")
    rows=metadata_records(raw)
    if [key for key,_ in rows]!=[b"\0",b"\1"+digest,b"\2"+struct.pack(">Q",height)]:
        raise ValueError("Frontier metadata keys or order differ")
    hash_height(rows[0][1],digest,height)
    if rows[1][1]!=struct.pack(">Q",height):raise ValueError("Hash-to-height metadata differs")
    body=rows[2][1];p=fields(body,repeated={8})
    if not {1,2,3,4,5,6,9}<=set(p)<=set(range(1,10)):raise ValueError("Unexpected v1 momentum protobuf")
    if any(one(p,key,0)!=value for key,value in((1,1),(2,1),(5,height),(6,timestamp))):
        raise ValueError("Wrong selected header scalars")
    if hash_value(one(p,3,2))!=digest or hash_value(one(p,4,2))!=previous_hash_bytes:
        raise ValueError("Wrong selected header identities")
    if hash_value(one(p,9,2))!=changes_hash:raise ValueError("Wrong source changes hash")
    content=p.get(8,[])
    if len(content)!=content_count:raise ValueError("Wrong source account header count")
    content_digest=hashlib.sha3_256();previous=None
    for wire,encoded in content:
        if wire!=2:raise ValueError("Wrong account header wire type")
        account=fields(encoded)
        if set(account)!={1,2}:raise ValueError("Wrong account header shape")
        address=fields(one(account,1,2))
        if set(address)!={1}:raise ValueError("Wrong address protobuf")
        address=one(address,1,2)
        if type(address)is not bytes or len(address)!=20:raise ValueError("Wrong address width")
        hh=fields(one(account,2,2))
        if set(hh)!={1,2}:raise ValueError("Wrong account hash-height protobuf")
        account_hash=hash_value(one(hh,1,2));account_height=one(hh,2,0)
        if type(account_height)is not int or not 0<account_height<1<<64:raise ValueError("Wrong account height")
        item=address+struct.pack(">Q",account_height)+account_hash
        if previous is not None and item<previous:raise ValueError("Account headers are not ordered")
        previous=item;content_digest.update(item)
    data=one(p,7,2,b"")
    frame=struct.pack(">QQ",1,1)+previous_hash_bytes+struct.pack(">QQ",height,timestamp)+hashlib.sha3_256(data).digest()+content_digest.digest()+changes_hash
    if len(frame)!=160 or hashlib.sha3_256(frame).digest()!=digest:raise ValueError("Independent v1 frame hash differs")
    return {"metadata_bytes":len(raw),"metadata_sha256":hashlib.sha256(raw).hexdigest(),
            "metadata_puts":3,"serialized_momentum_bytes":len(body),"content_headers":len(content),
            "independent_v1_frame_hex":frame.hex(),"independent_v1_frame_sha3_256":digest.hex()}

def verify_stored_patch(source_changes,metadata,identifier,previous_hash,timestamp,content_count):
    if type(source_changes)is not bytes or len(source_changes)>MAX_SOURCE_BYTES:raise ValueError("Source changes exceed their cap")
    report=verify_metadata(metadata,identifier,previous_hash,timestamp,hashlib.sha3_256(source_changes).digest(),content_count)
    digest=hashlib.sha256();digest.update(source_changes);digest.update(metadata)
    report.update(source_changes_bytes=len(source_changes),source_changes_sha256=hashlib.sha256(source_changes).hexdigest(),
                  expected_stored_bytes=len(source_changes)+len(metadata),expected_stored_sha256=digest.hexdigest())
    return report
