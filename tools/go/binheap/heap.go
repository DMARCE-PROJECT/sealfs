package heap

import "fmt"

// Simple binary heap in go

import (
	"os"
)

const (
	DefaultHeap = 2048
	Debug = false
	ShrinkProp = 4	//cap > 4*len, then shrink, has to be greater than 2
)


type Heap [V any] struct  {
	keys []int
	vals []V

	kind int
	cmp func (keys []int, i int, j int) bool;
};

const (
	Min = iota
	Max
)

func (h *Heap[V]) String() string {
	s := "MinHeap["
	if h.kind == Max {
		s = "MaxHeap["
	}
	ins := ""
	for i, v := range(h.vals) {
		ins += fmt.Sprintf("%v : %v, ", h.keys[i], v)
		if i != 0 && (i % 128) == 0 {
			ins += "\n"
		}
	}
	if len(ins) > 2 {
		ins = ins[0:len(ins)-2]
	}
	return s + ins + "]"
}

func NewHeap [V any](kind int) (h *Heap[V]){
	h = &Heap[V]{}
	h.vals = make([]V, 0, DefaultHeap)
	h.keys = make([]int, 0, DefaultHeap)
	h.kind = kind
	switch kind {
		case Min:
			h.cmp = smallerThan
		case Max:
			h.cmp = greaterThan
		default:
			return nil	//make them fail
	}
	return h
}

func (h *Heap[V]) Insert(key int, val V) {
	h.keys = append(h.keys, key)
	h.vals = append(h.vals, val)
	h.heapifyBottomTop(len(h.keys) -1)
}

func smallerThan (keys []int, i int, j int) bool{
	return keys[i] < keys[j]
}

func greaterThan (keys []int, i int, j int) bool{
	return keys[i] > keys[j]
}

func (h *Heap[V]) heapifyBottomTop(index int) {
	if Debug { fmt.Fprintf(os.Stderr, "HeapifyBottomTop: %v\n", index) }
	parentIndex := (index - 1)/2
	if h.cmp(h.keys[:], index, parentIndex) {
		h.keys[parentIndex], h.keys[index] = h.keys[index], h.keys[parentIndex]
		//recursive call
		h.heapifyBottomTop(parentIndex)
	}
	if Debug { fmt.Fprintf(os.Stderr, "HeapifyBottomTop return: %v\n", index) }
}

const (
	Left = iota
	Right
	Nelem
)

func (h *Heap[V]) hasval(index int) bool {
	return index < len(h.keys) && index >= 0
}

func (h *Heap[V]) ismin(index[] int, side int, minIndex int) bool {
	keyIndex := index[side]
	return h.hasval(keyIndex) && h.cmp(h.keys[:], keyIndex, minIndex) 
}

func (h *Heap[V])heapifyTopBottom(parentIndex int) {
	if Debug { fmt.Fprintf(os.Stderr, "HeapifyTopBottom: %v,%v\n", parentIndex, h) }
	keyIndex := [Nelem]int{}
	min := parentIndex

	keyIndex[Left] = parentIndex*2+1
	keyIndex[Right] = parentIndex*2+2
	if h.ismin(keyIndex[:], Left, min) {
		min = keyIndex[Left]
	}
	if h.ismin(keyIndex[:], Right, min) {
		min = keyIndex[Right]
	}
	if min == parentIndex {
		if Debug { fmt.Fprintf(os.Stderr, "HeapifyTopBottom return: %v,%v\n", parentIndex, min) }
		return
	}
	h.keys[min], h.keys[parentIndex] = h.keys[parentIndex], h.keys[min] 
	h.heapifyTopBottom(min)
	if Debug { fmt.Fprintf(os.Stderr, "HeapifyTopBottom done: %v,%v\n", parentIndex, h) }
}

func (h *Heap[V])Pop() (val V, min int, ok bool) {
	//heap is empy, should ok?
	if len(h.keys) == 0 {
		return val, min, false
	}
	min = h.keys[0]
	val = h.vals[0]
	h.vals[0] = h.vals[len(h.vals) -1]
	h.keys[0] = h.keys[len(h.keys) -1]
	h.vals = h.vals[0:len(h.vals) -1]
	h.keys = h.keys[0:len(h.keys) -1]
	h.heapifyTopBottom(0)
	//time to shrink
	if cap(h.vals) > ShrinkProp*len(h.vals) {
		vals := h.vals
		h.vals = make([]V, 0, (ShrinkProp/2)*len(h.vals))
		h.vals = append(h.vals, vals...)
		keys := h.keys
		h.keys = make([]int, 0, (ShrinkProp/2)*len(h.keys))
		h.keys = append(h.keys, keys...)
	}
	return val, min, true
}


func (h *Heap[V])Len() int {
	return len(h.keys)
}