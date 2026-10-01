//go:build windows

package conformance_test

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PROCESS_MEMORY_COUNTERS uses DWORD for the first two fields and SIZE_T for
// the remainder. In particular PeakWorkingSetSize is bytes, not peak commit.
// https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters
type processMemoryCounters struct {
	cb, pageFaultCount                                 uint32
	peakWorkingSetSize, workingSetSize                 uintptr
	quotaPeakPagedPoolUsage, quotaPagedPoolUsage       uintptr
	quotaPeakNonPagedPoolUsage, quotaNonPagedPoolUsage uintptr
	pagefileUsage, peakPagefileUsage                   uintptr
}

var getProcessMemoryInfo = windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")

type processMemoryObserver struct{ handle windows.Handle }

func startProcessMemory(process *os.Process) processMemoryObserver {
	if process == nil {
		return processMemoryObserver{}
	}
	// Call only before cmd.Wait or Process.Release. Go's original process
	// handle keeps the process object and PID alive, even after child exit.
	// Acquire our own non-inheritable query handle while that handle exists;
	// never reopen a PID after Wait and never inspect Go's private handles.
	// https://devblogs.microsoft.com/oldnewthing/20110107-00/?p=11803
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(process.Pid))
	runtime.KeepAlive(process)
	if err != nil {
		return processMemoryObserver{}
	}
	return processMemoryObserver{handle: handle}
}

func (observer *processMemoryObserver) finish(state *os.ProcessState) processMemorySample {
	if observer.handle == 0 || state == nil || !state.Exited() {
		return unavailableProcessMemory()
	}
	var counters processMemoryCounters
	counters.cb = uint32(unsafe.Sizeof(counters))
	if getProcessMemoryInfo.Find() != nil {
		return unavailableProcessMemory()
	}
	// Query once after Wait with the retained handle. Do not substitute a
	// sampled maximum or a current working set if native accounting fails.
	// https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo
	ok, _, _ := getProcessMemoryInfo.Call(uintptr(observer.handle), uintptr(unsafe.Pointer(&counters)), uintptr(counters.cb))
	if ok == 0 || counters.peakWorkingSetSize == 0 {
		return unavailableProcessMemory()
	}
	peak := uint64(counters.peakWorkingSetSize)
	return processMemorySample{bytes: &peak, source: "windows_peak_working_set"}
}

func (observer *processMemoryObserver) close() {
	if observer.handle != 0 {
		_ = windows.CloseHandle(observer.handle)
		observer.handle = 0
	}
}
