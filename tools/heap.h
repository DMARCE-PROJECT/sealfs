
enum {
	MaxHeapSz = 1000,
};


struct Heap{
	uint64_t arr[MaxHeapSz];
	int val[MaxHeapSz];
	int count;
	int capacity;
	int heap_type; // for min heap , 1 for max heap
};
typedef struct Heap Heap;

extern Heap *createheap(void);
extern int insertheap(Heap *h, uint64_t key, int val);
extern uint64_t popminheap(Heap *h, int *valp);
extern void printheap(Heap *h);