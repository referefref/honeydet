package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/TwiN/go-color"
)

// randPlaceholder is replaced in every step's input and output with a token that is
// new for each signature run but identical across that run's steps
const randPlaceholder = "{{rand}}"

func newRandToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func applyRandToken(step Step, token string) Step {
	step.Input = strings.ReplaceAll(step.Input, randPlaceholder, token)
	step.Output = strings.ReplaceAll(step.Output, randPlaceholder, token)
	return step
}

// isTimingMatch checks a step's optional timing constraints. elapsed holds the response
// time of each step so far (index idx is the current step); faster_than_step is 1-based.
func isTimingMatch(step Step, elapsed []time.Duration, idx int) bool {
	took := elapsed[idx]
	if step.MinResponseMs > 0 && took < time.Duration(step.MinResponseMs)*time.Millisecond {
		return false
	}
	if step.MaxResponseMs > 0 && took > time.Duration(step.MaxResponseMs)*time.Millisecond {
		return false
	}
	if step.FasterThanStep > 0 {
		ref := step.FasterThanStep - 1
		if ref >= idx {
			if *debug {
				fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] faster_than_step %d does not name an earlier step", step.FasterThanStep)))
			}
			return false
		}
		factor := step.SpeedupFactor
		if factor <= 0 {
			factor = 1
		}
		if float64(took)*factor > float64(elapsed[ref]) {
			return false
		}
	}
	return true
}

func hasTimingConstraint(step Step) bool {
	return step.MinResponseMs > 0 || step.MaxResponseMs > 0 || step.FasterThanStep > 0
}
