package stack

import (
	"testing"
)

// TestStack tests the correctness of the stack implementation
func TestStack(t *testing.T) {
	stack := New()

	const sz = 8
	var a, b [sz]int
	for i := 0; i < sz; i++ {
		stack.Push(i)
		a[i] = sz - i - 1
		b[i] = sz - i - 2
	}

	i := 0
	for !stack.Empty() {
		top, nextTop := stack.Peek(), stack.Peek2()

		nextTopValue := -1
		if nil != nextTop {
			nextTopValue = nextTop.(int)
		}
		if a[i] != top {
			t.Fatalf("invalid top value: want %v, got %v", a[i], top)
		}

		if b[i] != nextTopValue {
			t.Fatalf("invalid next top value: want %v, got %v", a[i], top)
		}

		stack.Pop()
		i++
	}
}
