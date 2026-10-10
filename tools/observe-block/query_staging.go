package main

import (
	"context"
	"io"
	"os"
	"time"
)

// Stream the verifier report through the existing byte cap into one exclusively
// created private file. Return only after both stream copies and file closure;
// the consumer must never see an incomplete or unsuccessfully closed report.
func stageQueryReport(ctx context.Context, binary string, args []string, path string, timeout time.Duration) processResult {
	return stageQueryReportWithOpen(ctx, binary, args, path, timeout, func(path string) (io.WriteCloser, error) {
		return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	})
}

func stageQueryReportWithOpen(ctx context.Context, binary string, args []string, path string, timeout time.Duration, openFile func(string) (io.WriteCloser, error)) (result processResult) {
	file, err := openFile(path)
	if err != nil {
		return processResult{category: "input_unavailable", code: 70}
	}
	defer func() {
		if file.Close() != nil && result.category == "" {
			result.category, result.code = "input_unavailable", 70
		}
	}()
	return runProcessOutput(ctx, binary, args, maxReportBytes, timeout, file)
}
