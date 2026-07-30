package modules

import (
	"errors"
	"testing"
	"time"
)

// TestDecodeNamePointerLoop is the guard against a hostile nameserver:
// before the pointer cap, a self-referential compression pointer spun
// decodeName forever. It must now return instead of hanging.
func TestDecodeNamePointerLoop(t *testing.T) {
	cases := map[string][]byte{
		// pointer at offset 0 targeting offset 0
		"self": {0xC0, 0x00},
		// two pointers targeting each other
		"cycle": {0xC0, 0x02, 0xC0, 0x00},
		// label then a pointer back to the start of that label
		"label": {0x01, 'a', 0xC0, 0x00},
	}
	for name, msg := range cases {
		done := make(chan error, 1)
		go func() {
			_, _, err := decodeName(msg, 0)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, errNamePointerLoop) {
				t.Errorf("%s: got err %v, want errNamePointerLoop", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: decodeName hung on a compression pointer loop", name)
		}
	}
}

// TestDecodeName covers the paths the loop guard must not break.
func TestDecodeName(t *testing.T) {
	// "www.example.com" uncompressed, then a pointer to it at offset 17.
	msg := []byte{
		0x00, 0x00, // filler so offset 0 is not a valid name start
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0xC0, 0x02,
	}
	name, end, err := decodeName(msg, 2)
	if err != nil || name != "www.example.com" || end != 19 {
		t.Fatalf("plain: got (%q, %d, %v), want (www.example.com, 19, nil)", name, end, err)
	}

	name, end, err = decodeName(msg, 19)
	if err != nil || name != "www.example.com" || end != 21 {
		t.Fatalf("compressed: got (%q, %d, %v), want (www.example.com, 21, nil)", name, end, err)
	}

	if _, _, err := decodeName(msg, len(msg)); err == nil {
		t.Error("out-of-range offset: want error, got nil")
	}
}

// TestNXDomainOnly pins the takeover rule: only a genuine NXDOMAIN counts.
func TestNXDomainOnly(t *testing.T) {
	if isNXDomain(nil) {
		t.Error("nil error must not be NXDOMAIN")
	}
	if isNXDomain(errors.New("i/o timeout")) {
		t.Error("generic error must not be NXDOMAIN")
	}
}
