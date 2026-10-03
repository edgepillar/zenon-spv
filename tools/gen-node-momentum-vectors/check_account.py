"""Independent account-block wire projection and SHA3-256 preimage checks."""

import base64

from check import address_bytes, bech32_bytes, digest, require, uint64


def check_unsigned_projection(projection):
    for field in ("version", "chainIdentifier", "blockType", "height", "fusedPlasma", "difficulty"):
        uint64(projection[field])
    uint64(projection["momentumAcknowledged"]["height"])


def check_account(block, rpc):
    check_unsigned_projection(block)
    pending = [rpc]
    while pending:
        projection = pending.pop()
        check_unsigned_projection(projection)
        pending.extend(projection["descendantBlocks"])
    amount = block["amount"]
    require(amount == int(rpc["amount"]), "amount differs across wire forms")
    magnitude = abs(amount)
    encoded = magnitude.to_bytes(max(32, (magnitude.bit_length() + 7) // 8), "big")

    def field_bytes(field, size):
        value = bytes.fromhex(block[field])
        require(len(value) == size, f"wrong field width: {field}")
        return value

    for field in ("version", "chainIdentifier", "blockType", "previousHash", "height",
                  "momentumAcknowledged", "fromBlockHash", "fusedPlasma", "difficulty", "nonce"):
        require(block[field] == rpc[field], f"account projection mismatch: {field}")
    for field in ("address", "toAddress"):
        require(address_bytes(rpc[field]) == field_bytes(field, 20), f"wrong {field}")
    require(bech32_bytes(rpc["tokenStandard"], "zts", 10) == field_bytes("tokenStandard", 10), "wrong token bytes")
    for field in ("publicKey", "signature"):
        require(base64.b64decode(block[field] or "", validate=True) == base64.b64decode(rpc[field] or "", validate=True), f"wrong {field}")
    ack = block["momentumAcknowledged"]
    ack_hash = bytes.fromhex(ack["hash"])
    require(len(ack_hash) == 32, "wrong acknowledged hash width")
    data_hash = digest(base64.b64decode(rpc["data"] or "", validate=True))
    children = [bytes.fromhex(child["hash"]) for child in rpc["descendantBlocks"]]
    require(all(len(child) == 32 for child in children), "wrong descendant hash width")
    descendant_hash = digest(b"".join(children))
    require(data_hash == field_bytes("dataHash", 32), "wrong data digest")
    require(descendant_hash == field_bytes("descendantBlocksHash", 32), "wrong descendant digest")
    preimage = b"".join([
        uint64(block["version"]), uint64(block["chainIdentifier"]), uint64(block["blockType"]),
        field_bytes("previousHash", 32), uint64(block["height"]), ack_hash, uint64(ack["height"]),
        field_bytes("address", 20), field_bytes("toAddress", 20), encoded, field_bytes("tokenStandard", 10),
        field_bytes("fromBlockHash", 32), descendant_hash, data_hash,
        uint64(block["fusedPlasma"]), uint64(block["difficulty"]), field_bytes("nonce", 8),
    ])
    require(digest(preimage).hex() == block["hash"] == rpc["hash"], "account-block preimage mismatch")
    return encoded
