package httpclient

import "testing"

func TestNew_HasTimeout(t *testing.T) {
	c := New()
	if c.Timeout <= 0 {
		t.Fatalf("Timeout = %v, want a positive value (a zero timeout means requests can hang forever)", c.Timeout)
	}
	if c.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", c.Timeout, DefaultTimeout)
	}
}
