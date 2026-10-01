//go:build windows

package conformance_test

import (
	"context"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getHandleInformation = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation")

func memoryHandleInformation(handle windows.Handle) (uint32, error) {
	var flags uint32
	ok, _, err := getHandleInformation.Call(uintptr(handle), uintptr(unsafe.Pointer(&flags)))
	if ok == 0 {
		return 0, err
	}
	return flags, nil
}

func TestWindowsProcessMemoryLifetime(t *testing.T) {
	t.Run("attach_after_exit", func(t *testing.T) {
		for range 16 {
			func() {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := memoryChildCommand(t, ctx, "exit")
				if err := cmd.Start(); err != nil {
					t.Fatal("child start failed")
				}
				defer func() {
					if cmd.ProcessState == nil {
						_ = cmd.Process.Kill()
						_ = cmd.Wait()
					}
				}()
				wait, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
				if err != nil {
					t.Fatal("child wait handle unavailable")
				}
				status, err := windows.WaitForSingleObject(wait, 10000)
				_ = windows.CloseHandle(wait)
				if err != nil || status != windows.WAIT_OBJECT_0 {
					t.Fatal("short-lived child did not exit")
				}
				// The child is definitely dead, but Go has not called Wait or
				// Release. Its original handle must still bind this PID.
				observer := startProcessMemory(cmd.Process)
				defer observer.close()
				if observer.handle == 0 || cmd.Wait() != nil {
					t.Fatal("cannot acquire an already-exited child's accounting")
				}
				checkNativeMemorySample(t, observer.finish(cmd.ProcessState))
				if flags, err := memoryHandleInformation(observer.handle); err != nil || flags&windows.HANDLE_FLAG_INHERIT != 0 {
					t.Fatal("observation handle was inherited or lost before query")
				}
				var created, exited, kernel, user windows.Filetime
				usage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage)
				if !ok || windows.GetProcessTimes(observer.handle, &created, &exited, &kernel, &user) != nil ||
					created.LowDateTime != usage.CreationTime.LowDateTime || created.HighDateTime != usage.CreationTime.HighDateTime {
					t.Fatal("observation handle differs from the original child identity")
				}
			}()
		}
	})
	t.Run("query_access_denied", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := memoryChildCommand(t, ctx, "exit")
		if err := cmd.Start(); err != nil {
			t.Fatal("child start failed")
		}
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
		waitErr := cmd.Wait()
		if err != nil || waitErr != nil {
			if handle != 0 {
				_ = windows.CloseHandle(handle)
			}
			t.Fatal("child accounting setup failed")
		}
		observer := processMemoryObserver{handle: handle}
		defer observer.close()
		// This real handle lacks query access. Native failure must not be
		// presented as zero bytes, a previous result, or an alternate metric.
		sample := observer.finish(cmd.ProcessState)
		if sample.source != "unavailable" || sample.bytes != nil {
			t.Fatal("failed native query fabricated a measurement")
		}
	})
	t.Run("missing_state_and_close", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := memoryChildCommand(t, ctx, "exit")
		if err := cmd.Start(); err != nil {
			t.Fatal("child start failed")
		}
		observer := startProcessMemory(cmd.Process)
		defer observer.close()
		if cmd.Wait() != nil || observer.handle == 0 {
			t.Fatal("child accounting setup failed")
		}
		if sample := observer.finish(nil); sample.bytes != nil || sample.source != "unavailable" {
			t.Fatal("missing completion fabricated a measurement")
		}
		handle := observer.handle
		observer.close()
		if _, err := memoryHandleInformation(handle); err != windows.ERROR_INVALID_HANDLE {
			t.Fatal("observation handle leaked after close")
		}
		observer.close()
		if sample := observer.finish(cmd.ProcessState); sample.bytes != nil || sample.source != "unavailable" || observer.handle != 0 {
			t.Fatal("closed handle was reused for a measurement")
		}
	})
}
