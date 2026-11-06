package main

import (
	"testing"
	"time"
)

func TestApplyRandToken(t *testing.T) {
	token := newRandToken()
	if len(token) != 16 || token == newRandToken() {
		t.Fatalf("unexpected token %q", token)
	}
	s := applyRandToken(Step{Input: "GET /{{rand}}.html HTTP/1.1", Output: "{{rand}}"}, "abc")
	if s.Input != "GET /abc.html HTTP/1.1" || s.Output != "abc" {
		t.Fatalf("substitution failed: %+v", s)
	}
}

func TestIsTimingMatch(t *testing.T) {
	ms := time.Millisecond
	cases := []struct {
		name    string
		step    Step
		elapsed []time.Duration
		idx     int
		want    bool
	}{
		{"no constraints", Step{}, []time.Duration{5 * ms}, 0, true},
		{"min met", Step{MinResponseMs: 1000}, []time.Duration{1500 * ms}, 0, true},
		{"min not met", Step{MinResponseMs: 1000}, []time.Duration{20 * ms}, 0, false},
		{"max met", Step{MaxResponseMs: 100}, []time.Duration{20 * ms}, 0, true},
		{"max not met", Step{MaxResponseMs: 100}, []time.Duration{200 * ms}, 0, false},
		{"10x faster", Step{FasterThanStep: 1, SpeedupFactor: 10}, []time.Duration{2000 * ms, 2 * ms}, 1, true},
		{"not 10x faster", Step{FasterThanStep: 1, SpeedupFactor: 10}, []time.Duration{2000 * ms, 500 * ms}, 1, false},
		{"default factor 1", Step{FasterThanStep: 1}, []time.Duration{20 * ms, 10 * ms}, 1, true},
		{"slower than ref", Step{FasterThanStep: 1}, []time.Duration{10 * ms, 20 * ms}, 1, false},
		{"ref not earlier", Step{FasterThanStep: 2}, []time.Duration{10 * ms, 1 * ms}, 1, false},
	}
	for _, c := range cases {
		if got := isTimingMatch(c.step, c.elapsed, c.idx); got != c.want {
			t.Errorf("%s: got %t, want %t", c.name, got, c.want)
		}
	}
}
