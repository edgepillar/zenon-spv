//go:build !windows

package conformance_test

import "os"

func candidateBinaryIdentity(_ string, info os.FileInfo) (os.FileInfo, error) { return info, nil }
