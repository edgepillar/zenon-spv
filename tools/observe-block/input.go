package main

import "os"

// Check each selected input again at the open boundary, then check the actual
// descriptor before reading. The callback makes replacement controls exact;
// it does not change process-wide open behavior. Callers still protect paths.
func checkedPreflightInput(path string, limit int64, openFile func(string) (*os.File, error)) (*os.File, int64, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, 0, os.ErrInvalid
	}
	f, err := openFile(path)
	if err != nil {
		return nil, 0, err
	}
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		_ = f.Close()
		return nil, 0, os.ErrInvalid
	}
	return f, info.Size(), nil
}
