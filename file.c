/*
 *  Copyright (c) 2019  Enrique Soriano, Gorka Guardiola
 *
 *  Based on Wrapfs:
 * Copyright (c) 1998-2017 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2017 Stony Brook University
 * Copyright (c) 2003-2017 The Research Foundation of SUNY
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */



#include "sealfs.h"

enum {
	DEBUGENTRY = 0
};

static ssize_t sealfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sealfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

	return err;
}

static void freehmac(struct sealfs_hmac_state *hmacstate)
{
	if(!hmacstate->hash_tfm){
		return;
	}
	crypto_free_shash(hmacstate->hash_tfm);
	kfree(hmacstate->hash_desc);
}



static int initshash(struct sealfs_hmac_state *hmacstate)
{
	hmacstate->hash_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if(IS_ERR(hmacstate->hash_tfm)) {
 		printk(KERN_ERR "sealfs: can't alloc hash_tfm struct\n");
		return -1;
	}
	hmacstate->hash_desc = kzalloc(sizeof(struct shash_desc) +
			       crypto_shash_descsize(hmacstate->hash_tfm), GFP_KERNEL);
	if(hmacstate->hash_desc == NULL){
		crypto_free_shash(hmacstate->hash_tfm);
		printk(KERN_ERR "sealfs: can't alloc hash_desc struct\n");
		return -1;
	}
	hmacstate->hash_desc->tfm = hmacstate->hash_tfm;
	return 0;
}

static void
dumpkey(u8 *key)
{
	int i;
	char str[3*FPR_SIZE];
	for(i = 0; i <FPR_SIZE; i++)
		sprintf(str+3*i, "%2.2x ", key[i]);
	printk("sealfs: KEY %s\n", str);
}

static inline int ratchet_key(char *key, loff_t ratchet_offset, int nratchet)
{
	int err = 0;

	uint64_t roff;
	uint64_t nr;

	struct sealfs_hmac_state hmacstate;
	nr = nratchet;
	hmacstate.hash_tfm = NULL;
	if(DEBUGENTRY){
		printk("sealfs: RATCHET: old, roff %llu ", ratchet_offset);
		dumpkey(key);
	}
	roff = (uint64_t)ratchet_offset;
	if(initshash(&hmacstate) < 0)
		return -1;
	err = crypto_shash_setkey(hmacstate.hash_tfm, key, FPR_SIZE);
	if(err){
		printk(KERN_ERR "sealfs: can't load hmac key\n");
		freehmac(&hmacstate);
		return -1;
	}
	err = crypto_shash_init(hmacstate.hash_desc);
	if(err){
		printk(KERN_ERR "sealfs: can't init hmac\n");
		freehmac(&hmacstate);
		return -1;
	}
	err = crypto_shash_update(hmacstate.hash_desc,
			(u8*) &roff, sizeof(uint64_t));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: ratchet offset\n");
		freehmac(&hmacstate);
		return -1;
	}
	err = crypto_shash_update(hmacstate.hash_desc,
			(u8*) &nr, sizeof(uint64_t));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: nratchet\n");
		freehmac(&hmacstate);
		return -1;
	}
	err = crypto_shash_final(hmacstate.hash_desc, (u8 *) key);
	if(err){
		printk(KERN_ERR "sealfs: can't final hmac\n");
		freehmac(&hmacstate);
		return -1;
	}
	if(DEBUGENTRY){
		printk("sealfs: RATCHET: new");
		freehmac(&hmacstate);
		dumpkey(key);
	}
	//no need, the key is around until next ratchet, and then this will
	//be overwritten yes?
	//err = crypto_shash_setkey(hmacstate.hash_tfm, zkey, FPR_SIZE);
	//if(err){
	//	printk(KERN_ERR "sealfs: can't reset hmac key\n");
	//	return -1;
	//}
	//freehmac calls crypto_free which overwrites the memory
	freehmac(&hmacstate);
	return 0;
}
static int do_hmac(const char __user *data, char *key,
	 		struct sealfs_logfile_entry *lentry)
{
	int err = 0;
	u8	*buf;
	struct page *p;
	uint64_t n, nc, nl;  

	struct sealfs_hmac_state hmacstate;
	hmacstate.hash_tfm = NULL;
	if(initshash(&hmacstate) < 0)
		return -1;
	err = crypto_shash_setkey(hmacstate.hash_tfm, key, FPR_SIZE);
	if(err){
		printk(KERN_ERR "sealfs: can't load hmac key\n");
		freehmac(&hmacstate);
		return -1;
	}
	err = crypto_shash_init(hmacstate.hash_desc);
	if(err){
		printk(KERN_ERR "sealfs: can't init hmac\n");
		freehmac(&hmacstate);
		return -1;
	}
	err = crypto_shash_update(hmacstate.hash_desc,
			(u8*) &lentry->ratchetoffset, sizeof(lentry->ratchetoffset));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: ratchetoffset\n");
		freehmac(&hmacstate);
		return -1;
	}

 	err = crypto_shash_update(hmacstate.hash_desc,
			(u8*) &lentry->inode, sizeof(lentry->inode));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: inode\n");
		freehmac(&hmacstate);
		return -1;
	}
	err = crypto_shash_update(hmacstate.hash_desc,
			(u8*) &lentry->offset, sizeof(lentry->offset));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: offset\n");
		freehmac(&hmacstate);
		return -1;
	}
	err = crypto_shash_update(hmacstate.hash_desc,
			(u8*) &lentry->count, sizeof(lentry->count));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: count\n");
		freehmac(&hmacstate);
		return -1;
	}
	err = crypto_shash_update(hmacstate.hash_desc,
			(u8*) &lentry->koffset, sizeof(lentry->koffset));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: koffset\n");
		freehmac(&hmacstate);
		return -1;
	}

	p = alloc_page(GFP_KERNEL);
	if(!p){
		printk(KERN_ERR "sealfs: can't allocate buf for hmac: koffset\n");
		freehmac(&hmacstate);
		return -1;
	}
	buf=kmap(p);
	n = lentry->count;
	while(n > 0){
		nc = PAGE_SIZE;
		if(n < PAGE_SIZE)
			nc = n;
		n -= nc;
		nl = copy_from_user(buf, data, nc);
		if(nl < 0 || nl >= nc){
			printk(KERN_ERR "sealfs: can't copy_from_user hmac: data\n");
			kunmap(p);
			__free_page(p);
			freehmac(&hmacstate);
			return -1;
		}
		n +=nl;
		err = crypto_shash_update(hmacstate.hash_desc, buf, nc-nl);
		if(err){
			printk(KERN_ERR "sealfs: can't updtate hmac: data\n");
			kunmap(p);
			__free_page(p);
			freehmac(&hmacstate);
			return -1;
		}
	}
	kunmap(p);
	__free_page(p);
	err = crypto_shash_final(hmacstate.hash_desc, (u8 *) lentry->fpr);
	if(err){
		printk(KERN_ERR "sealfs: can't final hmac\n");
		freehmac(&hmacstate);
		return -1;
	}
	//err = crypto_shash_setkey(hmacstate.hash_tfm, zkey, FPR_SIZE);
	//if(err){
	//	printk(KERN_ERR "sealfs: can't reset hmac key\n");
	//	freehmac(&hmacstate);
	//	return -1;
	//}
	//freehmac calls crypto_free which overwrites the memory
	freehmac(&hmacstate);
	return 0;
}
static int has_advanced_burnt(struct sealfs_sb_info *sb, loff_t oldburnt)
{
	loff_t newburnt;

	newburnt = atomic_long_read(&sb->burnt);
	return newburnt != oldburnt;
}

enum {
	/* max number of FPR_SIZE chunks to burn. DO NOT make it bigger
	 *  if you want to make it bigger, you need to kalloc
	 */
	MaxBurnBatch = 16
};


static int burn_key(struct sealfs_sb_info *sb, loff_t keyoff, int nentries)
{
	unsigned char buf[MaxBurnBatch*FPR_SIZE];
	int sz;
	
	if(nentries > MaxBurnBatch)
		nentries = MaxBurnBatch;
	
	sz = nentries * FPR_SIZE;
 	get_random_bytes(buf, sz);
	if(kernel_write(sb->kfile, buf, sz, &keyoff) != (size_t)sz){
		printk(KERN_ERR "sealfs: can't write key file\n");
		return -1;
	}
	return sz;
}

static int advance_burn(struct sealfs_sb_info *sb, loff_t burnt, loff_t unburnt)
{
	loff_t chkburnt;
	while(unburnt  < burnt) {
		/* burn with random from oldburnt to burnt */
		chkburnt = burn_key(sb, unburnt, (burnt - unburnt)/FPR_SIZE);
		if(chkburnt < 0) {
			printk(KERN_CRIT  "sealfs: error writing key file\n");
			break;
		}
		unburnt = unburnt + chkburnt;
	}
	return unburnt;
}

static int sealfs_thread_main(void *data, int freq, int do_update_hdr)
{
	struct sealfs_sb_info *sb=(struct sealfs_sb_info *)data;
	wait_queue_head_t *q =&sb->thread_q;
	int isadvance;
	loff_t burnt, unburnt, oldunburnt;

	isadvance = 1;
	/* starts after header */
	unburnt = sizeof(struct sealfs_keyfile_header);

repeat:
	burnt = atomic_long_read(&sb->burnt);
	oldunburnt = unburnt;
	// This lock is to make sure things are marked to go
	// to disk before someone else burns them
	mutex_lock(&sb->burnsyncmutex);
	unburnt = advance_burn(sb, burnt, unburnt);
	isadvance = oldunburnt != unburnt;
	vfs_fsync_range(sb->kfile, oldunburnt, unburnt, 1);
	mutex_unlock(&sb->burnsyncmutex);
	if(isadvance && do_update_hdr){
		sealfs_update_hdr(sb);
		isadvance = 0;
	}
	if (kthread_should_stop()){
		if(!has_advanced_burnt(sb, unburnt)){
			printk(KERN_ERR "sealfs: done oldburnt: %lld burnt: %lld\n",
				unburnt, burnt);
			return 0;
		}else
			goto repeat;
	}
	wait_event_interruptible_timeout(*q,
		kthread_should_stop() || has_advanced_burnt(sb, unburnt), freq);
	goto repeat;
}

static int sealfs_thread(void *data)
{
	return sealfs_thread_main(data, HZ, 1);
}

static loff_t read_key(struct sealfs_sb_info *sb, unsigned char *key, loff_t roff, loff_t oldoff)
{
	loff_t nr;
	loff_t t;
	loff_t keyoff;
	loff_t	ret;

	ret = -1;
	if(roff != 0){
		if(DEBUGENTRY)
			printk("sealfs: RATCHET koff %lld, roff: %lld", oldoff, roff);
		ratchet_key(key, roff, sb->nratchet);
		ret = oldoff;
		goto end;
	}
	if(DEBUGENTRY)
		printk("sealfs: BURN burn: %lld roff: %lld", oldoff, roff);

	if(oldoff + FPR_SIZE >= sb->maxkfilesz){
			printk(KERN_ERR "sealfs: burnt key\n");
			goto end;
	}
	keyoff = oldoff;
	t = 0ULL;
	
	while(t < FPR_SIZE){
		nr = kernel_read(sb->kfile, key+t, ((loff_t)FPR_SIZE)-t, &keyoff);
		if(unlikely(nr < 0)) {
			printk(KERN_ERR "sealfs: error while reading\n");
			goto end;
		}
		if(nr == 0){
			printk(KERN_ERR "sealfs: key file is burnt\n");
			goto end;
		}
  		t += nr;
	}
	ret = keyoff;
end:
	return ret;
}

static int isbuffull(struct sealfs_sb_info *sb) {
	 return CIRC_SPACE(sb->head, sb->tail, sb->size) >= 1;
}


static int sealfs_ratchet_thread(void *data)
{
	loff_t roff, nextkeyoff, keyoff;
	unsigned char key[FPR_SIZE];
	int got;

	struct sealfs_sb_info *sb=(struct sealfs_sb_info *)data;
		unsigned long head;
		unsigned long tail;

	keyoff = atomic_long_read(&sb->burnt);
	roff = 0;
	got = 0;
	while(!kthread_should_stop()){
		if(!got){
			if(roff == 0)
				nextkeyoff = read_key(sb, key, roff, keyoff);
			else
				read_key(sb, key, roff, keyoff);
			got++;
		}
		spin_lock(&sb->producer_lock);
		head = sb->head;
		tail = READ_ONCE(sb->tail);
		if (CIRC_SPACE(head, tail, sb->size) >= 1) {

			sb->buf[head].roff = roff;
			sb->buf[head].keyoff = keyoff;
			memmove(sb->buf[head].key, key, FPR_SIZE);

			smp_store_release(&sb->head, (head + 1) & (sb->size - 1));
			wake_up(&sb->consumerq);
			spin_unlock(&sb->producer_lock);
			//printk("produced keyoff: %lld roff: %lld\n", keyoff, roff);
			roff = (roff+1)%sb->nratchet;
			if(roff == 0)
				keyoff = nextkeyoff;
			got--;
		}else{
			wake_up(&sb->consumerq);
			spin_unlock(&sb->producer_lock);
			//printk("producer full\n");
			wait_event_interruptible(sb->producerq, kthread_should_stop()
				|| isbuffull(sb));
			//printk("producer up\n");
		}
	}
	return 0;
}

enum {
	NPRIMES=10,
};
static int sealfs_slow_thread(void *data)
{
	int period;
	int i;
	struct sealfs_sb_info *sb=(struct sealfs_sb_info *)data;
	/* sleeping cicada strategy, minimize wakeup collisions */
	int primes[NPRIMES]={11, 17, 31, 37, 43, 59, 73, 97, 139, 157};
	i = sb->nthreads - 1;	//first one is fast
	period = primes[i%NPRIMES];	//seconds
	return sealfs_thread_main(data, period*HZ, 0);
}

void sealfs_stop_thread(struct sealfs_sb_info *sb)
{
	int i;
	for(i = 0; i < NBURNTHREADS; i++){
		kthread_stop(sb->sync_thread[i]);
	}
	
}
void sealfs_start_thread(struct sealfs_sb_info *sb)
{
	int i;
	sb->nthreads = 0;
	init_waitqueue_head(&sb->thread_q);
	sb->sync_thread[0] = kthread_run(sealfs_thread, sb, "sealfs");
	sb->nthreads++;
	init_waitqueue_head(&sb->slow_thread_q);
	for(i = 1; i < NBURNTHREADS; i++){
		sb->sync_thread[i] = kthread_run(sealfs_slow_thread, sb, "sealfs");
		sb->nthreads++;
	}

	init_waitqueue_head(&sb->consumerq);
	init_waitqueue_head(&sb->producerq);
	sb->head = 0;
	sb->tail = 0;
	sb->size = NBUFRATCHET;
	spin_lock_init(&sb->consumer_lock);
	spin_lock_init(&sb->producer_lock);
	sb->ratchet_thread = kthread_run(sealfs_ratchet_thread, sb, "sealfs");

}

int sealfs_update_hdr(struct sealfs_sb_info *sb)
{
	struct sealfs_keyfile_header hdr;
	loff_t zoff;
	size_t x;
	zoff = 0;
	hdr = sb->kheader;	//only for the magic and nratchet
	hdr.burnt = atomic_long_read(&sb->burnt);
	/* hdr may be old by the time it is written
	 *  this is a benign race condition, we write the current version.
	 *  There is another race, where we write a *old* version
	 *  of the offset. This is no problem (unmount corrects it
	 * see sealfs_put_super). Worst case, if no unmount and the
	 * race is present, it will invalidate some log entries (but then,
	 * there are no guarantees anyway)
	 */
	x = sizeof(struct sealfs_keyfile_header);
	if(kernel_write(sb->kfile, (void*)&hdr, x, &zoff) != x){
		printk(KERN_ERR "sealfs: can't write key file header\n");
		return -1;
	}
	return 0;
}

static int isbufempty(struct sealfs_sb_info *sb, unsigned long head, unsigned long tail) {
	 return CIRC_CNT(sb->head, sb->tail, sb->size) >= 1;
}

static loff_t get_key(struct sealfs_sb_info *sb, unsigned char *key, loff_t *ratchetoff)
{
	loff_t keyoff;
	unsigned long head;
	unsigned long tail;
	int got;
	got = 0;
	
	do{	
		spin_lock(&sb->consumer_lock);
		/* Read index before reading contents at that index. */
		head = smp_load_acquire(&sb->head);
		tail = sb->tail;
		
		if (CIRC_CNT(head, tail, sb->size) >= 1) {
			/* consume item */
			got++;
			*ratchetoff = sb->buf[tail].roff;
			keyoff = sb->buf[tail].keyoff;
			memmove(key, sb->buf[tail].key, FPR_SIZE);
		        /* Finish reading descriptor before incrementing tail. */
			smp_store_release(&sb->tail, (sb->tail + 1) & (sb->size - 1));
			spin_unlock(&sb->consumer_lock);
			wake_up(&sb->producerq);
		}else{
			wake_up(&sb->producerq);
			spin_unlock(&sb->consumer_lock);
			//printk("consumer empty\n");
			wait_event_interruptible(sb->consumerq, isbufempty(sb, head, tail));
			//printk("consumer up\n");
		}
	}while(!got);
	//printk("consumed keyoff: %lld roff: %lld\n", keyoff, *ratchetoff);
	return keyoff;
}

static void
dumpentry(struct sealfs_logfile_entry *e)
{
	printk("ENTRY: ratchetoffset: %lld "
		"inode: %lld "
		"offset: %lld "
		"count: %lld "
		"koffset: %lld\n",
		e->ratchetoffset,
		e->inode,
		e->offset,
		e->count,
		e->koffset);
}

static int burn_entry(struct file *f, const char __user *buf, size_t count,
			loff_t offset, struct sealfs_sb_info *sb)
{
	int  sz;
	unsigned char key[FPR_SIZE];
	struct sealfs_logfile_entry lentry;
	loff_t o;
	loff_t keyoff, roff;
	int nks;

	lentry.inode = FAKEINODE;
	if(f != NULL)
		lentry.inode = (uint64_t) file_inode(f)->i_ino;
	lentry.offset = (uint64_t) offset;
	lentry.count = (uint64_t) count;

	mutex_lock(&sb->bbmutex);
	keyoff = get_key(sb, key, &roff);
	if(keyoff < 0) {
		printk(KERN_ERR "sealfs: readkey failed\n");
		return -1;
	}
	sb->ratchetoffset = roff;
	atomic_long_set(&sb->burnt, keyoff+FPR_SIZE);
	mutex_unlock(&sb->bbmutex);
	if(DEBUGENTRY)
		dumpkey(key);

	lentry.ratchetoffset = (uint64_t) roff;
	lentry.koffset =  (uint64_t) keyoff;
	if(DEBUGENTRY)
		dumpentry(&lentry);

	if(do_hmac(buf, key, &lentry) < 0){
		printk(KERN_ERR "sealfs: do_hash failed\n");
		return -1;
      	}
	sz = sizeof(struct sealfs_logfile_entry);

	nks = (keyoff-sizeof(struct sealfs_keyfile_header))/FPR_SIZE;
	o = sizeof(struct sealfs_logfile_header) + (nks*sb->nratchet+roff)*sz;

	if(kernel_write(sb->lfile, (void*)&lentry, sz, &o) != sz){
		printk(KERN_ERR "sealfs: can't write log file\n");
		return -1;
	}
	/* This wakeup could be done right after read_key with the mutex being held,
	 *  but in order to not miss any wakeups, the mutex has to be passed
	 *  to the kthread, slowing the write. Instead of that, if the wakeup is
	 *  missed, the kthread will catch up 1s later via timeout. This also make the
	 *  batching of burnts possible, the kthread if fully asynchronous.
	 */
	if (waitqueue_active(&sb->thread_q))
		wake_up(&sb->thread_q);
	return 0;
}

void sealfs_seal_ratchet(struct sealfs_sb_info *spd)
{
	unsigned char c;
	c = 0;

	if(DEBUGENTRY)
		printk("sealfs: RATCHETSEAL to go %d", spd->ratchetoffset);
	do{
		if(DEBUGENTRY)
			printk("sealfs: RATCHETSEAL roff: %d", spd->ratchetoffset);
		burn_entry(NULL, &c, 0, 0, spd);
	}while(spd->ratchetoffset != spd->nratchet - 1);
	//printk("seal DONE %ld\n", atomic_long_read(&spd->burnt));
	memset(spd->buf, 0, sizeof(spd->buf));
}

/*
 * TO FIX: if the task is signaled or killed while it's executiing burnt_entry
 * the log may become corrupted.
 */
static ssize_t sealfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct inode *ino;
	ssize_t wr;
 	struct sealfs_sb_info *sbinfo;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	loff_t woffset = -1;
	int debug;

	lower_file = sealfs_lower_file(file);

	if((file->f_flags & O_APPEND) == 0){
		 // NO APPEND-ONLY, NOT ALLOWED.
		 printk(KERN_INFO "sealfs: error, non append-only write on file %s\n",
	 		file->f_path.dentry->d_name.name);
		 return -EBADF;
	}

	sbinfo = (struct sealfs_sb_info*)
		file->f_path.mnt->mnt_sb->s_fs_info;
	/*
	* We can't trust ppos, it's the offset mantained by
	* the file descriptor, but it's not used by the write operation.
	* E.g.: the first write has always ppos=0, and it appends
	* the data correctly. After the first write, the offset in the
	* file descriptor is updated, but it may not be coherent with the
	* end of the file if other procs are using it.
	*
	* If we use ppos, we will have a race condition
	* for concurrent write operations over the same file.
	*
	* We can't allow concurrent writes for the same file if we
	* depend on the corresponding offset for each append-only write.
	*/


	ino = d_inode(dentry);

	/* Note: we use the inode to lock both lower_file and upper file to update offset */
	down_write(&ino->i_rwsem);
	wr = vfs_write(lower_file, buf, count, ppos); //ppos is ignored
	if(wr >= 0){
		fsstack_copy_inode_size(ino, file_inode(lower_file));
		fsstack_copy_attr_times(ino, file_inode(lower_file));
		woffset = ino->i_size - wr;
	}
	up_write(&ino->i_rwsem);
	/*
	 * NOTE: here, a write with a greater offset can overtake
	 * a write with a smaller offset FOR THE SAME FILE. Not
	 * probable, but possible. The verify tool compensates
	 *  for this (by using a small heap)
	 */
	if(wr < 0)
		return wr;

	if(burn_entry(file, buf, wr, woffset, sbinfo) < 0){
		printk(KERN_CRIT "sealfs: fatal error! "
			"can't burn entry for inode: %ld, %lld\n",
			ino->i_ino, woffset);
		wr = -EIO;
	}
	if(debug)
		printk(KERN_INFO
			"sealfs: append-only write  "
			"to file %s offset: %lld count: %ld\n",
			file->f_path.dentry->d_name.name,
			woffset,
			count);	
	if(wr != count) {
		printk(KERN_INFO "sealfs: warning! %ld bytes "
			"of %ld bytes have been written"
			" (inode: %ld)\n",
			wr, count, ino->i_ino);
	}
	return wr;
}

static int sealfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sealfs_lower_file(file);
	err = iterate_dir(lower_file, ctx);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}

static long sealfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = sealfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long sealfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = sealfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

/* Q disabled */
static int sealfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	return -EPERM;
}

static int sealfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;


	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct sealfs_file_info), GFP_KERNEL);
	if (!SEALFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link sealfs's file struct to lower's */
	sealfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = sealfs_lower_file(file);
		if (lower_file) {
			sealfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		sealfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(SEALFS_F(file));
	else
		fsstack_copy_attr_all(inode, sealfs_lower_inode(inode));
out_err:
	return err;
}

static int sealfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sealfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int sealfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = sealfs_lower_file(file);
	if (lower_file) {
		sealfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(SEALFS_F(file));
	return 0;
}

static int sealfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = sealfs_lower_file(file);
	sealfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	sealfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int sealfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sealfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Blackboxfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t sealfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = sealfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Blackboxfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
sealfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sealfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Q
 */
ssize_t
sealfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	return -EPERM;
}

const struct file_operations sealfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= sealfs_read,
	.write		= sealfs_write,
	.unlocked_ioctl	= sealfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sealfs_compat_ioctl,
#endif
	.mmap		= sealfs_mmap,
	.open		= sealfs_open,
	.flush		= sealfs_flush,
	.release	= sealfs_file_release,
	.fsync		= sealfs_fsync,
	.fasync		= sealfs_fasync,
	.read_iter	= sealfs_read_iter,
	.write_iter	= sealfs_write_iter,
};

/* trimmed directory options */
const struct file_operations sealfs_dir_fops = {
	.llseek		= sealfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= sealfs_readdir,
	.unlocked_ioctl	= sealfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sealfs_compat_ioctl,
#endif
	.open		= sealfs_open,
	.release	= sealfs_file_release,
	.flush		= sealfs_flush,
	.fsync		= sealfs_fsync,
	.fasync		= sealfs_fasync,
};
