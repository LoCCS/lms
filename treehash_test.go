package lms

import "testing"

// TestTreeHashIndexing checks the indexing of nodes for tree as
// 3                    1(15)
//             /                   \
// 2:         2(7)                  3(14)
//       /         \            /          \
// 1:   4(3)        5(6)       6(10)       7(13)
//     /   \      /    \      /    \      /     \
// 0: 8(1)  9(2) 10(4) 11(5) 12(8) 13(9) 14(11) 15(12)
// where the number in braces are the number of updates needed to
// estimate that node
func TestTreeHashIndexing(t *testing.T) {
	hVec := [15]uint32{
		0, 0, 1, 0, 0, 1, 2, 0, 0, 1, 0, 0, 1, 2, 3,
	}
	idxVec := [15]uint32{
		8, 9, 4, 10, 11, 5, 2, 12, 13, 6, 14, 15, 7, 3, 1,
	}

	const H = 3
	ths := NewTreeHashStack(0, H)
	nodeCache := make([][]byte, 1<<H)

	i := 0
	for !ths.IsCompleted() {
		ths.Update(1, nodeCache)
		node := ths.Top()

		if hVec[i] != node.height {
			t.Fatalf("invalid height: want %v, got %v", hVec[i], node.height)
		}
		if idxVec[i] != node.index {
			t.Fatalf("invalid index: want %v, got %v", idxVec[i], node.index)
		}
		i++
	}
}
