#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../sealfstypes.h" //shared with kernel module
#include "heap.h"

static void heapify_bottom_top(Heap *h,int index);
static void heapify_top_bottom(Heap *h, int parent_node);

Heap *
createheap(void)
{
	Heap *h = (Heap * )malloc(sizeof(Heap));
	if(h == NULL){
		return NULL;
	}
	h->count=0;
	return h;
}

int
insertheap(Heap *h, uint64_t key, void *val)
{
	if(h->count >= MaxHeapSz){
		return -1;
	}
	h->arr[h->count] = key;
	h->vals[h->count] = val;
	heapify_bottom_top(h, h->count);
	h->count++;
	return h->count;
}

static void
swap(Heap *h, int p, int q)
{
	uint64_t aux;
	void *auxp;
	aux = h->arr[p];
	h->arr[p] = h->arr[q];
	h->arr[q] = aux;

	auxp = h->vals[p];
	h->vals[p] = h->vals[q];
	h->vals[q] = auxp;
}

static void
heapify_bottom_top(Heap *h,int index)
{
	int parent_node;

	parent_node = (index-1)/2;
	if(h->arr[parent_node] > h->arr[index]){
		swap(h, parent_node, index);
		// recursive  call
		heapify_bottom_top(h,parent_node);
	}
}

static void
heapify_top_bottom(Heap *h, int parent_node)
{
	int left, right, min;

	left = parent_node*2+1;
	right = parent_node*2+2;
	if(left >= h->count || left <0)
		left = -1;
	if(right >= h->count || right <0)
		right = -1;

	if(left != -1 && h->arr[left] < h->arr[parent_node])
		min=left;
	else
		min =parent_node;
	if(right != -1 && h->arr[right] < h->arr[min])
		min = right;

	if(min != parent_node){
		swap(h, min, parent_node);
		// recursive  call
		heapify_top_bottom(h, min);
	}
}


void *
popminheap(Heap *h, uint64_t *min)
{
	void *val;
	if(h->count==0){
		/* heap is empty */
		return NULL;
	}
	// replace first node by last and delete last
	*min = h->arr[0];
	val = h->vals[0];
	h->arr[0] = h->arr[h->count-1];
	h->vals[0] = h->vals[h->count-1];
	h->count--;
	heapify_top_bottom(h, 0);
	return val;
}

void printheap(Heap *h){
	int i;
	fprintf(stderr, "offsets, counts: [");
	for(i=0;i< h->count;i++){
		fprintf(stderr, "%lu, ", h->arr[i]);
	}
	fprintf(stderr, "]\n");
}