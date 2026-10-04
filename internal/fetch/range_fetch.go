package fetch

import (
	"context"
	"fmt"
)

// go-zenon's rpc/api/utils.go limits both height methods to 1,024 rows.
// Keep each selected peer's complete range together before quorum reconciliation.
const rpcRangePageSize = 1024

func fetchHeightRange[Wire, Parsed any](ctx context.Context, client *Client, method string,
	start, count uint64, params func(uint64, uint64) []any, rowTarget func(*Wire) any,
	convert func(Wire, uint64) (Parsed, error), budget *rpcResponseBudget,
) ([]Parsed, error) {
	var out []Parsed
	for offset := uint64(0); offset < count; {
		pageCount := min(count-offset, rpcRangePageSize)
		var rows []Wire
		decoder := rpcListDecoder[Wire]{target: &rows, count: pageCount, rowTarget: rowTarget}
		if err := client.callWithBudget(ctx, method, params(start+offset, pageCount), &decoder, budget); err != nil {
			return nil, fmt.Errorf("%s: %w", method, err)
		}
		if uint64(len(rows)) != pageCount {
			return nil, fmt.Errorf("%w: rpc returned %d rows, expected %d", ErrQueryMismatch, len(rows), pageCount)
		}
		for i, row := range rows {
			parsed, err := convert(row, offset+uint64(i))
			if err != nil {
				return nil, err
			}
			out = append(out, parsed)
		}
		offset += pageCount
	}
	return out, nil
}
