//go:build !windows

package main

import "os"

func candidateIdentityInfo(_ string, info os.FileInfo) (os.FileInfo, error) { return info, nil }
