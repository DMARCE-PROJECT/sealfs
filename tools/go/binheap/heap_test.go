package heap_test

// go test -run SimpleMax
// go test -fuzz FuzzHeap -fuzztime 60s

import (
	"math"
	"sealfs/sealfs/binheap"
	"testing"
)

func Test_SimpleMin(t *testing.T) {
	h := heap.NewHeap[string](heap.Min)

	h.Insert(1, "hola")
	h.Insert(-12, "adios")
	h.Insert(2, "adios")
	h.Insert(1, "peque")
	h.Insert(18, "largo")
	lastKey := -13
	lastVal := ""
	for i := 0; i < 4; i++ {
		v, k, ok := h.Pop()
		if !ok {
			t.Errorf("bad pop, should be ok")
		}
		if k < lastKey {
			t.Errorf("bad min heap, last: %v,%v this:%v,%v", lastKey, lastVal, k, v)
		}
		lastKey = k
		lastVal = v
	}
}

func Test_SimpleMax(t *testing.T) {
	h := heap.NewHeap[string](heap.Max)

	h.Insert(-10, "hola")
	h.Insert(1, "hola")
	h.Insert(2, "adios")
	h.Insert(1, "peque")
	h.Insert(18, "largo")
	lastKey := 19
	lastVal := ""
	for i := 0; i < 4; i++ {
		v, k, ok := h.Pop()
		if !ok {
			t.Errorf("bad pop, should be ok")
		}
		if k > lastKey {
			t.Errorf("bad max heap, last: %v,%v this:%v,%v", lastKey, lastVal, k, v)
		}
		lastKey = k
		lastVal = v
	}
}

func FuzzHeap(f *testing.F) {
	h := heap.NewHeap[string](heap.Max)
	f.Add(5, "hello")
	f.Add(-5, "bye")
	f.Add(1000, "ante cabe bajo contra desde:")
	f.Fuzz(func(t *testing.T, i int, s string) {
		if i < 0 {
			lastKey := math.MaxInt
			lastVal := ""
			for j := 0; j < -i; j++ {
				v, k, ok := h.Pop()
				if !ok {
					return
				}
				if k > lastKey {
					t.Errorf("bad min heap, last: %v,%v this:%v,%v", lastKey, lastVal, k, v)
				}
				lastKey = k
				lastVal = v
			}
		}
		h.Insert(i, s)
	})
}
