
enum {
	MaxHeapSz = 1000,
};


struct Heap{
	uint64_t arr[MaxHeapSz];
	void *vals[MaxHeapSz];
	int count;
};
typedef struct Heap Heap;

extern Heap *createheap(void);
extern int insertheap(Heap *h, uint64_t key, void *val);
extern void *popminheap(Heap *h, uint64_t *valp);
extern void printheap(Heap *h);