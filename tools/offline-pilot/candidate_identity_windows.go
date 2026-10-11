package main

import (
	"os"
	"syscall"
)

// Windows path FileInfo may defer loading identity until SameFile is called.
// Capture it from a metadata handle before opening the hashing descriptor.
// The final component is opened without following a reparse point; parent
// ownership and stable contents still remain caller inputs.
func candidateIdentityInfo(path string, info os.FileInfo) (os.FileInfo, error) {
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
