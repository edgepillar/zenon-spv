package conformance_test

import (
	"os"
	"syscall"
)

// Path FileInfo can defer Windows identity lookup until after replacement.
// Capture identity using a metadata handle and close it before the read open.
func candidateBinaryIdentity(path string, info os.FileInfo) (os.FileInfo, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(name, 0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	opened, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil || closeErr != nil || !opened.Mode().IsRegular() || opened.Size() != info.Size() {
		return nil, os.ErrInvalid
	}
	return opened, nil
}
