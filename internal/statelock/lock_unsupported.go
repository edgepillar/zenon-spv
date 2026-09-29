//go:build !darwin && !linux && !windows

package statelock

import "os"

func stateNameSupported(string) bool        { return true }
func openLockFile(string) (*os.File, error) { return nil, ErrUnsupported }
func tryLock(*os.File) error                { return ErrUnsupported }
func unlockFile(*os.File) error             { return ErrUnsupported }
