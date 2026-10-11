package conformance_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"testing/iotest"
)

// Independently pinned with Python hashlib over 00 ff 80 5a 0a.
const candidateBinaryOpaqueSHA = "4f098c4eef5402c8eb37b2982fde9046579b2af7e942a09ee0da2f7559860498"

type candidateBinaryTestInput struct {
	reader   io.Reader
	closeErr error
	closed   int
}

func (input *candidateBinaryTestInput) Read(p []byte) (int, error) { return input.reader.Read(p) }
func (input *candidateBinaryTestInput) Close() error {
	input.closed++
	return input.closeErr
}

type candidateBinaryErrorReader struct{ err error }

func (reader candidateBinaryErrorReader) Read([]byte) (int, error) { return 0, reader.err }

type candidateBinaryDataEOFReader struct{ *bytes.Reader }

func (reader candidateBinaryDataEOFReader) Read(p []byte) (int, error) {
	n, err := reader.Reader.Read(p)
	if n > 0 && reader.Len() == 0 {
		err = io.EOF
	}
	return n, err
}

type candidateBinaryTestOutput struct {
	bytes.Buffer
	writeErr error
	closeErr error
	short    bool
	closed   int
}

func (output *candidateBinaryTestOutput) Write(p []byte) (int, error) {
	if output.writeErr != nil {
		return 0, output.writeErr
	}
	if output.short && len(p) > 0 {
		return output.Buffer.Write(p[:len(p)-1])
	}
	return output.Buffer.Write(p)
}

func (output *candidateBinaryTestOutput) Close() error {
	output.closed++
	return output.closeErr
}

func TestCandidateBinaryReadContract(t *testing.T) {
	raw := []byte{0, 0xff, 0x80, 'Z', '\n'}
	privateReadErr := errors.New("PRIVATE_READ_FAILURE")
	privateCloseErr := errors.New("PRIVATE_CLOSE_FAILURE")
	for _, tc := range []struct {
		name string
		size int64
		mode string
		want error
	}{
		{"opaque_bytes", 5, "complete", nil},
		{"short_reads", 5, "short", nil},
		{"EOF_with_data", 5, "data_EOF", nil},
		{"zero_size", 0, "complete", os.ErrInvalid},
		{"negative_size", -1, "complete", os.ErrInvalid},
		{"oversized", candidateBinaryLimit + 1, "complete", os.ErrInvalid},
		{"shrink", 6, "complete", io.ErrUnexpectedEOF},
		{"grow", 4, "complete", os.ErrInvalid},
		{"read_error", 5, "read_error", privateReadErr},
		{"close_error", 5, "close_error", privateCloseErr},
		{"read_error_before_close_error", 5, "both_errors", privateReadErr},
		{"EOF_probe_error", 5, "tail_error", privateReadErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := &candidateBinaryTestInput{reader: bytes.NewReader(raw)}
			switch tc.mode {
			case "short":
				input.reader = iotest.OneByteReader(input.reader)
			case "data_EOF":
				input.reader = candidateBinaryDataEOFReader{bytes.NewReader(raw)}
			case "read_error", "both_errors":
				input.reader = candidateBinaryErrorReader{privateReadErr}
			case "tail_error":
				input.reader = io.MultiReader(input.reader, candidateBinaryErrorReader{privateReadErr})
			}
			if tc.mode == "close_error" || tc.mode == "both_errors" {
				input.closeErr = privateCloseErr
			}
			digest, err := readCandidateBinary(input, tc.size, io.Discard)
			if input.closed != 1 || !errors.Is(err, tc.want) {
				t.Fatal("read disposition or exactly-once close disagrees")
			}
			if (tc.want == nil && digest != candidateBinaryOpaqueSHA) || (tc.want != nil && digest != "") {
				t.Fatal("complete raw hash or refusal without a digest disagrees")
			}
		})
	}
	for _, mode := range []string{"complete", "short", "write", "short_write", "output_close", "input_close", "both_close", "grow", "pin"} {
		t.Run("copy_"+mode, func(t *testing.T) {
			input := &candidateBinaryTestInput{reader: bytes.NewReader(raw)}
			output := new(candidateBinaryTestOutput)
			pin, size := candidateBinaryOpaqueSHA, int64(len(raw))
			var want error
			switch mode {
			case "short":
				input.reader = iotest.OneByteReader(input.reader)
			case "write":
				output.writeErr, want = privateReadErr, privateReadErr
			case "short_write":
				output.short, want = true, io.ErrShortWrite
			case "output_close":
				output.closeErr, want = privateCloseErr, privateCloseErr
			case "input_close":
				input.closeErr, want = privateReadErr, privateReadErr
			case "both_close":
				input.closeErr, output.closeErr, want = privateReadErr, privateCloseErr, privateReadErr
			case "grow":
				size, want = size-1, os.ErrInvalid
			case "pin":
				pin, want = "wrong expected digest", os.ErrInvalid
			}
			err := copyCandidateBinary(input, size, output, pin)
			if !errors.Is(err, want) || input.closed != 1 || output.closed != 1 {
				t.Fatal("copy disposition or both exactly-once closes disagree")
			}
			if want == nil && !bytes.Equal(output.Bytes(), raw) {
				t.Fatal("copy changed raw executable bytes")
			}
		})
	}
	t.Log("conformance-candidate-binary-read-controls {\"schema_version\":1,\"read_controls\":12,\"copy_controls\":9,\"complete_reads\":3,\"complete_copies\":2,\"refusals\":16,\"inputs_closed\":true,\"outputs_closed\":true,\"hash_buffer_bytes\":32768}")
}

func TestCandidateBinaryFileReadBounds(t *testing.T) {
	raw := []byte{0, 0xff, 0x80, 'Z', '\n'}
	for _, mode := range []string{"regular", "ceiling", "missing", "empty", "oversize", "directory", "opened_closed", "opened_directory", "opened_empty", "opened_oversize", "opened_size_changed", "opened_replacement"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "PRIVATE_EXECUTABLE")
			if mode != "missing" && mode != "directory" {
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			size := int64(len(raw))
			switch mode {
			case "ceiling", "empty", "oversize":
				size = 0
				switch mode {
				case "ceiling":
					size = candidateBinaryLimit
				case "oversize":
					size = candidateBinaryLimit + 1
				}
				// The exact ceiling oracle is 128 MiB of zero bytes.
				file, err := os.OpenFile(path, os.O_TRUNC|os.O_WRONLY, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				truncateErr, closeErr := file.Truncate(size), file.Close()
				if truncateErr != nil || closeErr != nil {
					t.Fatal("cannot prepare selected size control")
				}
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			var opened *os.File
			open := func(name string) (*os.File, error) {
				calls++
				switch mode {
				case "opened_directory":
					name = root
				case "opened_empty", "opened_oversize", "opened_size_changed":
					changed := int64(0)
					switch mode {
					case "opened_oversize":
						changed = candidateBinaryLimit + 1
					case "opened_size_changed":
						changed = int64(len(raw) + 1)
					}
					if err := os.Truncate(name, changed); err != nil {
						return nil, err
					}
				case "opened_replacement":
					if err := os.Rename(name, name+".selected"); err != nil {
						return nil, err
					}
					if err := os.WriteFile(name, raw, 0o600); err != nil {
						return nil, err
					}
				}
				file, err := openCandidateBinaryInput(name)
				opened = file
				if err == nil && mode == "opened_closed" {
					err = file.Close()
				}
				return file, err
			}
			file, gotSize, err := checkedCandidateBinaryInput(path, open)
			accepted := mode == "regular" || mode == "ceiling"
			if accepted {
				if err != nil || file == nil || gotSize != size || calls != 1 {
					if file != nil {
						_ = file.Close()
					}
					t.Fatal("bounded selected descriptor was refused")
				}
				digest, err := readCandidateBinary(file, gotSize, io.Discard)
				want := candidateBinaryOpaqueSHA
				if mode == "ceiling" {
					// Independently pinned Python hashlib over 128 MiB of zeros.
					want = "254bcc3fc4f27172636df4bf32de9f107f620d559b20d760197e452b97453917"
				}
				if err != nil || digest != want {
					t.Fatal("complete selected descriptor hash disagrees")
				}
			} else {
				if err == nil || file != nil || gotSize != 0 {
					if file != nil {
						_ = file.Close()
					}
					t.Fatal("invalid opened descriptor was accepted")
				}
				preflight := mode == "missing" || mode == "empty" || mode == "oversize" || mode == "directory"
				if (preflight && calls != 0) || (!preflight && calls != 1) {
					t.Fatal("selected or opened refusal happened at the wrong boundary")
				}
			}
			if opened != nil {
				if _, err := opened.Stat(); err == nil {
					_ = opened.Close()
					t.Fatal("selected descriptor remained open")
				}
			}
		})
	}
	t.Log("conformance-candidate-binary-file-controls {\"schema_version\":1,\"controls\":12,\"accepted_files\":2,\"refusals\":10,\"binary_ceiling_bytes\":134217728,\"exact_ceiling_passed\":true,\"descriptors_closed\":true,\"replacement_identity_checked\":true}")
}
