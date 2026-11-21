package main

import "testing"

func TestIRCChannelLengthAndDistinctness(t *testing.T) {
	a := ircChannel("A very long question about the foundations of physics", "subpart", 32)
	b := ircChannel("A very long question about the foundations of chemistry", "subpart", 32)
	if len(a) > 32 || len(b) > 32 || a == b {
		t.Fatalf("bad channel naming: %q %q", a, b)
	}
}
