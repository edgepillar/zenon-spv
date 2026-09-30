package proof

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
)

type proofByteBudget struct {
	limit, remaining int
}

func (budget *proofByteBudget) exceeded() error {
	return &BundleByteLimitError{Field: "state_value_proofs.proof_nodes", Limit: budget.limit}
}

func (budget *proofByteBudget) decodeNode(d *json.Decoder, node *[]byte) error {
	return d.Decode(&proofNodeJSON{target: node, budget: budget})
}

type proofNodeJSON struct {
	target *[]byte
	budget *proofByteBudget
}

func (node *proofNodeJSON) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	var decoded []byte
	var err error
	switch {
	case len(raw) > 0 && raw[0] == '"':
		decoded, err = node.decodeBase64(raw)
	case len(raw) > 0 && raw[0] == '[':
		decoded, err = node.decodeArray(raw)
	default:
		// Preserve null and the standard type errors for other JSON values.
		err = json.Unmarshal(raw, &decoded)
	}
	if err != nil {
		return err
	}
	if len(decoded) > node.budget.remaining {
		return node.budget.exceeded()
	}
	node.budget.remaining -= len(decoded)
	*node.target = decoded
	return nil
}

func (node *proofNodeJSON) decodeBase64(raw []byte) ([]byte, error) {
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, err
	}
	// encoding/json accepts standard padded base64, ignoring CR and LF.
	// Count significant characters before allocating decoded storage. JSON
	// unescaping and the encoded string remain bounded by the input byte cap.
	significant, padding := 0, 0
	for i := 0; i < len(encoded); i++ {
		if encoded[i] == '\r' || encoded[i] == '\n' {
			continue
		}
		significant++
		if encoded[i] == '=' {
			padding++
		} else {
			padding = 0
		}
	}
	capacity := base64.StdEncoding.DecodedLen(significant)
	length := capacity
	if significant%4 == 0 {
		length -= min(padding, 2, length)
	}
	if length > node.budget.remaining {
		return nil, node.budget.exceeded()
	}
	// Keep the standard whole-value decoder as the base64 validity check.
	// Its padding allowance is at most two bytes above the remaining budget.
	// Removing CR/LF also prevents newline padding from inflating allocations.
	var source []byte
	if significant == len(encoded) {
		source = []byte(encoded)
	} else {
		source = make([]byte, 0, significant)
		for i := 0; i < len(encoded); i++ {
			if encoded[i] != '\r' && encoded[i] != '\n' {
				source = append(source, encoded[i])
			}
		}
	}
	decoded := make([]byte, capacity)
	n, err := base64.StdEncoding.Decode(decoded, source)
	if err != nil {
		return nil, err
	}
	return decoded[:n], nil
}

func (node *proofNodeJSON) decodeArray(raw []byte) ([]byte, error) {
	// encoding/json has already validated the complete value before invoking
	// UnmarshalJSON. Valid byte elements are decimal uint8 values or null, so
	// they cannot contain commas. Splitting these scalars avoids a Decoder
	// allocation per byte; other value shapes fail without decoding later rows.
	body := bytes.TrimSpace(raw[1 : len(raw)-1])
	decoded := make([]byte, 0)
	for len(body) > 0 {
		if len(decoded) >= node.budget.remaining {
			return nil, node.budget.exceeded()
		}
		element, rest, _ := bytes.Cut(body, []byte(","))
		element = bytes.TrimSpace(element)
		var value byte
		if !bytes.Equal(element, []byte("null")) {
			parsed, err := strconv.ParseUint(string(element), 10, 8)
			if err != nil {
				return nil, errors.New("proof node array must contain uint8 values or null")
			}
			value = byte(parsed)
		}
		decoded = append(decoded, value)
		body = bytes.TrimSpace(rest)
	}
	return decoded, nil
}
