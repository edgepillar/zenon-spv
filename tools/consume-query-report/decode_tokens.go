package main

const (
	maxConsumerStringBytes = 4096
	maxConsumerNumberBytes = 21
)

// Refuse tokens that cannot fit the existing decoded limits before json.Token
// allocates their strings. This is only a necessary-condition filter: the
// unchanged strict decoder still checks syntax, decoded lengths and shapes.
func consumerTokensBounded(raw []byte) bool {
	for i := 0; i < len(raw); {
		switch {
		case raw[i] == '"':
			i++
			start := i
			for i < len(raw) && raw[i] != '"' {
				if raw[i] == '\\' {
					i += 2 // Skip an escaped quote or backslash; syntax is checked later.
				} else {
					i++
				}
				// One decoded byte can require at most six JSON source bytes
				// (\u0000). UTF-8, escaped quotes and surrogate pairs fit that
				// ceiling too. Do not tighten it to the decoded byte limit.
				if i-start > 6*maxConsumerStringBytes {
					return false
				}
			}
			if i < len(raw) {
				i++
			}
		case raw[i] == '-' || raw[i] >= '0' && raw[i] <= '9':
			start := i
			for i < len(raw) && consumerNumberByte(raw[i]) {
				i++
				if i-start > maxConsumerNumberBytes {
					return false
				}
			}
		default:
			i++
		}
	}
	return true
}

func consumerNumberByte(c byte) bool {
	return c >= '0' && c <= '9' || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E'
}
