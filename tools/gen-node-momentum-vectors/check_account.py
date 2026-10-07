"""Independent account-block wire projection and SHA3-256 preimage checks."""

from check import address_bytes, base64_bytes, bech32_bytes, digest, hash_bytes, require, uint64


def hex_bytes(value, size):
    require(type(value) is str and len(value) == 2 * size, "expected a fixed-width hex string")
    parsed = bytes.fromhex(value)
    require(len(parsed) == size, "wrong parsed hex width")
    return parsed


def check_unsigned_projection(projection):
    for field in ("version", "chainIdentifier", "blockType", "height", "fusedPlasma", "difficulty"):
        uint64(projection[field])
    uint64(projection["momentumAcknowledged"]["height"])
    for field in ("hash", "previousHash", "fromBlockHash"):
        hash_bytes(projection[field])
    hash_bytes(projection["momentumAcknowledged"]["hash"])
    hex_bytes(projection["nonce"], 8)


def optional_base64(value):
    require(value is None or type(value) is str, "expected a nullable base64 string")
    return base64_bytes("" if value is None else value)


def account_bytes(block, rpc):
    """Return the checked amount encoding and complete signed-envelope bytes."""
    check_unsigned_projection(block)
    pending = [rpc]
    while pending:
        projection = pending.pop()
        check_unsigned_projection(projection)
        pending.extend(projection["descendantBlocks"])
    amount = block["amount"]
    require(type(amount) is int, "expected an integer account amount")
    wire_amount = rpc["amount"]
    require(type(wire_amount) is str, "expected a decimal account amount string")
    digits = wire_amount[1:] if wire_amount.startswith(("+", "-")) else wire_amount
    require(digits and all("0" <= digit <= "9" for digit in digits), "expected ASCII decimal digits")
    require(amount == int(wire_amount), "amount differs across wire forms")
    magnitude = abs(amount)
    encoded = magnitude.to_bytes(max(32, (magnitude.bit_length() + 7) // 8), "big")

    def field_bytes(field, size):
        return hex_bytes(block[field], size)

    for field in ("version", "chainIdentifier", "blockType", "previousHash", "height",
                  "momentumAcknowledged", "fromBlockHash", "fusedPlasma", "difficulty", "nonce"):
        require(block[field] == rpc[field], f"account projection mismatch: {field}")
    for field in ("address", "toAddress"):
        require(address_bytes(rpc[field]) == field_bytes(field, 20), f"wrong {field}")
    require(bech32_bytes(rpc["tokenStandard"], "zts", 10) == field_bytes("tokenStandard", 10), "wrong token bytes")
    for field in ("publicKey", "signature"):
        require(optional_base64(block[field]) == optional_base64(rpc[field]), f"wrong {field}")
    ack = block["momentumAcknowledged"]
    ack_hash = hash_bytes(ack["hash"])
    data_hash = digest(optional_base64(rpc["data"]))
    children = [hash_bytes(child["hash"]) for child in rpc["descendantBlocks"]]
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
    return encoded, preimage


def check_account(block, rpc):
    return account_bytes(block, rpc)[0]
