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


/*
	myvfs_read and myvfs_write used to be vfs_read and vfs_write which used to be convenient
	this is probably faster but more fragile
*/

 #include <linux/uio.h>	//for iovec and so on in myvfs_* implementation

static ssize_t myvfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;
	struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = count };
	struct kiocb kiocb;
	struct iov_iter iter;

	if (file->f_op->write)
		ret = file->f_op->write(file, buf, count, pos);
	else if (file->f_op->write_iter) {
		init_sync_kiocb(&kiocb, file);
		kiocb.ki_pos = (pos ? *pos : 0);
		iov_iter_init(&iter, WRITE, &iov, 1, count);
		ret = file->f_op->write_iter(&kiocb, &iter);
		if (ret > 0 && pos)
			*pos = kiocb.ki_pos;
	} else
		ret = -EINVAL;
	return ret;
}

static ssize_t myvfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;
	struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = count };
	struct kiocb kiocb;
	struct iov_iter iter;

	if (file->f_op->read)
		ret = file->f_op->read(file, buf, count, pos);
	else if (file->f_op->read_iter) {
		init_sync_kiocb(&kiocb, file);
		kiocb.ki_pos = (pos ? *pos : 0);
		iov_iter_init(&iter, READ, &iov, 1, count);
		ret = file->f_op->read_iter(&kiocb, &iter);
		if (pos)
			*pos = kiocb.ki_pos;
	} else
		ret = -EINVAL;
	return ret;
}

static ssize_t sealfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sealfs_lower_file(file);
	err = myvfs_read(lower_file, buf, count, ppos);
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

static inline int ratchet_key(char *key, loff_t ratchet_offset, int nratchet, struct sealfs_hmac_state *hmacstate)
{
	int err = 0;

	uint64_t roff;
	uint64_t nr;

	nr = nratchet;
	if(DEBUGENTRY){
		printk("sealfs: RATCHET: old, roff %llu ", ratchet_offset);
		dumpkey(key);
	}
	roff = (uint64_t)ratchet_offset;
	err = crypto_shash_setkey(hmacstate->hash_tfm, key, FPR_SIZE);
	if(err){
		printk(KERN_ERR "sealfs: can't load hmac key\n");
		return -1;
	}
	err = crypto_shash_init(hmacstate->hash_desc);
	if(err){
		printk(KERN_ERR "sealfs: can't init hmac\n");
		return -1;
	}
	err = crypto_shash_update(hmacstate->hash_desc,
			(u8*) &roff, sizeof(uint64_t));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: ratchet offset\n");
		return -1;
	}
	err = crypto_shash_update(hmacstate->hash_desc,
			(u8*) &nr, sizeof(uint64_t));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: nratchet\n");
		return -1;
	}
	err = crypto_shash_final(hmacstate->hash_desc, (u8 *) key);
	if(err){
		printk(KERN_ERR "sealfs: can't final hmac\n");
		return -1;
	}
	if(DEBUGENTRY){
		printk("sealfs: RATCHET: new");
		dumpkey(key);
	}
	return 0;
}

//for debugging
/*
static int hash_userbuf_simple( struct sealfs_hmac_state *hmacstate, const char __user *data, uint64_t count)
{
	char *kd;
	int err;
	kd = kzalloc(count, GFP_KERNEL);
	if(kd == NULL) {
		printk("cannot allocate\n");
		return -1;
	}
	err = copy_from_user(kd, data, count);
	if(err) {
		printk("cannot copy\n");
		kfree(kd);
		return err;
	}
	err = crypto_shash_update(hmacstate->hash_desc, kd, count);
	if(err){
		printk("cannot hash\n");
		kfree(kd);
		return err;
	}
	kfree(kd);
	return 0;
}
*/

/* non precise, may give 1 more */
#define NPAGES(start, end)(1ULL+((((end)&PAGE_MASK)-((start)&PAGE_MASK))>>PAGE_SHIFT))

enum {
	MAX_PAGES=40
};
static int hash_userbuf( struct sealfs_hmac_state *hmacstate, const char __user *data, uint64_t count)
{
	u8	*buf;
	struct page *pages[MAX_PAGES];
	int64_t npages, np;
	int err = 0;
	int64_t  res;
	int rerr;
	uintptr_t start, end;
	uint64_t offset;
	uint64_t nbatch, nhash, nb;

	
	start = (uint64_t)data;
	offset = start-(start&PAGE_MASK);
	while(count > 0){
		nbatch = count;
		end = start + count;
		npages =  NPAGES(start, end);
		if(npages <= 0){
			printk(KERN_CRIT "sealfs: get_user_pages, npages <=0: %lld\n", npages);
		}
		if(npages > MAX_PAGES){
			npages = MAX_PAGES;
			nbatch = MAX_PAGES*PAGE_SIZE-offset;
		}

		res = get_user_pages_fast(start&PAGE_MASK,
					npages,
					0, /* Do not want to write into it */
					pages);
		if(res <= 0){
			printk(KERN_CRIT "sealfs: get_user_pages, no pages for hashing: %lld res %lld\n", npages, res);
			return -1;
		}
	      	/* could recover, but something is probably up */
		if(res < npages){
			npages = res;
			nbatch = npages*PAGE_SIZE-offset;
		}

		nb = nbatch;
		rerr = 0;
		for(np=0; np < npages; np++){
			buf = kmap(pages[np]);
			if((((uint64_t)buf+nb+offset)&PAGE_MASK) != (uint64_t)buf){
				/* if the end is in another page, the full page (if it is the first offset !=0 */
				nhash = PAGE_SIZE-offset;
			}else{
				/* whatever is left */
				nhash = nb;
			}
			err = crypto_shash_update(hmacstate->hash_desc, buf+offset, nhash);
			if(err)
				rerr = err;
			kunmap(pages[np]);
			put_page(pages[np]);
			offset = 0;	/* only for first page	*/
			nb -= nhash;
			if(nb <= 0)
				break;
		}
		if(rerr){
			return -1;
		}
		count -= nbatch;
		start += nbatch;
	}
	return 0;
}

static int do_hmac(const char __user *data, char *key,
	 		struct sealfs_logfile_entry *lentry, struct sealfs_hmac_state *hmacstate)
{
	int err = 0;

	err = crypto_shash_setkey(hmacstate->hash_tfm, key, FPR_SIZE);
	if(err){
		printk(KERN_ERR "sealfs: can't load hmac key\n");
		return -1;
	}
	err = crypto_shash_init(hmacstate->hash_desc);
	if(err){
		printk(KERN_ERR "sealfs: can't init hmac\n");
		return -1;
	}
	err = crypto_shash_update(hmacstate->hash_desc,
			(u8*) &lentry->ratchetoffset, sizeof(lentry->ratchetoffset));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: ratchetoffset\n");
		return -1;
	}

 	err = crypto_shash_update(hmacstate->hash_desc,
			(u8*) &lentry->inode, sizeof(lentry->inode));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: inode\n");
		return -1;
	}
	err = crypto_shash_update(hmacstate->hash_desc,
			(u8*) &lentry->offset, sizeof(lentry->offset));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: offset\n");
		return -1;
	}
	err = crypto_shash_update(hmacstate->hash_desc,
			(u8*) &lentry->count, sizeof(lentry->count));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: count\n");
		return -1;
	}
	err = crypto_shash_update(hmacstate->hash_desc,
			(u8*) &lentry->koffset, sizeof(lentry->koffset));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: koffset\n");
		return -1;
	}

	if(lentry->count > 0 && hash_userbuf(hmacstate, data, lentry->count) < 0){
		printk(KERN_ERR "sealfs: can't hash user buf\n");
		return -1;
	}

	err = crypto_shash_final(hmacstate->hash_desc, (u8 *) lentry->fpr);
	if(err){
		printk(KERN_ERR "sealfs: can't final hmac\n");
		return -1;
	}
	return 0;
}

/*
	http://open-std.org/JTC1/SC22/WG21/docs/papers/2016/p0124r1.html
	Documentation/atomic_t.txt
		" - RMW operations that have a return value are fully ordered;"
		"Fully ordered primitives are ordered against everything prior and everything
			subsequent. Therefore a fully ordered primitive is like having an smp_mb()
			before and an smp_mb() after the primitive."

	The problem which may appear is that we read the atomic and because of
	the relaxed memory semantics of C11 the buffer for the filesystem is not
	yet read and it mixes. This cannot happen in the linux kernel because atomics
	which return a value (per the standard above) run a full memory barrier.
	We hope (cross our fingers) this continues to be true.
*/
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

	do{	
		burnt = atomic_long_read(&sb->burnt);
		oldunburnt = unburnt;
		// This lock is to make sure things are marked to go
		// to disk before someone else burns them
		mutex_lock(&sb->burnsyncmutex);
		unburnt = advance_burn(sb, burnt, unburnt);
		isadvance = oldunburnt != unburnt;
		if(!isadvance)
			vfs_fsync_range(sb->kfile, oldunburnt, unburnt, 1);
		mutex_unlock(&sb->burnsyncmutex);
		if(isadvance && do_update_hdr){
			sealfs_update_hdr(sb);
			isadvance = 0;
		}
		wait_event_interruptible_timeout(*q,
			kthread_should_stop() || has_advanced_burnt(sb, unburnt), freq);
	}while(!kthread_should_stop()|| has_advanced_burnt(sb, unburnt));
	printk(KERN_ERR "sealfs: done oldburnt: %lld burnt: %lld\n",
		unburnt, burnt);
	return 0;
}

static int sealfs_thread(void *data)
{
	return sealfs_thread_main(data, HZ, 1);
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

static loff_t read_key(struct sealfs_sb_info *sb, unsigned char *key, loff_t *ratchetoff, struct sealfs_hmac_state *hmacstate)
{
	loff_t nr;
	loff_t t;
	loff_t oldoff, keyoff;
	loff_t roff;
	loff_t	ret;

	ret = -1;
	mutex_lock(&sb->bbmutex);
	/*
	  * Atomically
	 * 	- FPR_SIZE reading in key file (out of reach for futures reads)
	 *	- After reading key advance sb->burnt so that burners can see it.
	 *	- Later (without lock) writing sizeof(struct sealfs_logfile_entry) in log entry in the correct offset
	 *	- Updating offset header at start of key file at some point in the future (slow burner will do it)
	 *	- We will burn what is read asynchronously in the kthread driven by sb->burnt
	 *	-> With ratchet, we only advance burns when we run out of ratchets.
	 */
	oldoff = atomic_long_read(&sb->burnt);
	roff = sb->ratchetoffset;
	sb->ratchetoffset = (roff+1)%sb->nratchet;
	if(likely(roff != 0)){
		if(DEBUGENTRY)
			printk("sealfs: RATCHET koff %lld, roff: %lld", oldoff, roff);
		ratchet_key(sb->key, roff, sb->nratchet, hmacstate);
		memmove(key, sb->key, FPR_SIZE);
		ret = oldoff-FPR_SIZE;
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
	/* see comment in has_advanced_burnt */
	atomic_long_add(FPR_SIZE, &sb->burnt);
	if(sb->nratchet != 1)
		ratchet_key(key, 0, sb->nratchet, hmacstate);
	memmove(sb->key, key, FPR_SIZE);
	ret = oldoff;
end:
	mutex_unlock(&sb->bbmutex);
	*ratchetoff = roff;
	return ret;
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

static int burn_entry(struct inode *ino, const char __user *buf, size_t count,
			loff_t offset, struct sealfs_sb_info *sb, struct sealfs_hmac_state *hmacstate)
{
	int  sz;
	unsigned char key[FPR_SIZE];
	struct sealfs_logfile_entry lentry;
	loff_t o;
	loff_t keyoff, roff;
	int nks;

	lentry.inode = FAKEINODE;
	if(ino != NULL)
		lentry.inode = (uint64_t) ino->i_ino;
	lentry.offset = (uint64_t) offset;
	lentry.count = (uint64_t) count;

	keyoff = read_key(sb, key, &roff, hmacstate);
	if(keyoff < 0) {
		printk(KERN_ERR "sealfs: readkey failed\n");
		return -1;
	}
	if(DEBUGENTRY)
		dumpkey(key);

	lentry.ratchetoffset = (uint64_t) roff;
	lentry.koffset =  (uint64_t) keyoff;
	if(DEBUGENTRY)
		dumpentry(&lentry);

	if(do_hmac(buf, key, &lentry, hmacstate) < 0){
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
		wake_up_interruptible_sync(&sb->thread_q);	//sync, do not schedule this thread
	return 0;
}

void sealfs_seal_ratchet(struct sealfs_sb_info *spd)
{
	unsigned char c;
	struct sealfs_hmac_state hmacstate;
	c = 0;

	if(DEBUGENTRY)
		printk("sealfs: RATCHETSEAL to go %d", spd->ratchetoffset);
	if(initshash(&hmacstate) < 0){
		printk("sealfs: RATCHETSEAL could not seal");
		return;
	}
	while(spd->ratchetoffset != 0) {
		if(DEBUGENTRY)
			printk("sealfs: RATCHETSEAL roff: %d", spd->ratchetoffset);
		burn_entry(NULL, &c, 0, 0, spd, &hmacstate);
	}
	memset(spd->key, 0, FPR_SIZE);
	freehmac(&hmacstate);
}

/*
 *	TO FIX: if the task is signaled or killed while it's executiing burnt_entry
 *		the log my have zero entries (tooling needs to check for zero entries)
 */
static ssize_t sealfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct inode *ino, *low_ino;
	ssize_t wr;
 	struct sealfs_sb_info *sbinfo;
	struct file *lower_file;
	struct dentry *dentry;
	loff_t woffset = -1;
	int debug;
	loff_t our_ppos;
	loff_t new_ppos;

	struct sealfs_hmac_state hmacstate;	//for ratchet and content both
	if(initshash(&hmacstate) < 0)
		return -ENOMEM;

	dentry = file->f_path.dentry;
	lower_file = sealfs_lower_file(file);

	if((file->f_flags & O_APPEND) == 0){
		// Only append only. Do not allow anything else.
		printk(KERN_INFO "sealfs: error, non append-only write on file %s\n",
	 		file->f_path.dentry->d_name.name);
		freehmac(&hmacstate);
		return -EBADF;
	}

	sbinfo = (struct sealfs_sb_info*)
		file->f_path.mnt->mnt_sb->s_fs_info;

	ino = file_inode(file);

	/* Note: we use the lower inode to
	 *	lock both lower_file and upper file to update offset
	 *	on error, we already commited the offset.
	 */
	low_ino = file_inode(lower_file);
	down_write(&ino->i_rwsem);
	our_ppos = ino->i_size;
	new_ppos = our_ppos + wr;
	ino->i_size=new_ppos;
	woffset = our_ppos;
	up_write(&ino->i_rwsem);
	wr = myvfs_write(lower_file, buf, count, &woffset);
	if(wr >= 0){
		fsstack_copy_inode_size(ino, low_ino); // no need for lock (see comment in function)
		down_write(&ino->i_rwsem);
		*ppos = new_ppos;
		fsstack_copy_attr_times(ino, low_ino);
		up_write(&ino->i_rwsem);
	}
	/*
	 * NOTE: here, a write with a greater offset can overtake
	 * a write with a smaller offset FOR THE SAME FILE. Not
	 * probable, but possible. The verify tool compensates
	 *  for this (by using a small heap).
	 */
	if(wr < 0){
		freehmac(&hmacstate);
		return wr;
	}

	woffset = our_ppos;
	if(burn_entry(ino, buf, wr, woffset, sbinfo, &hmacstate) < 0){
		printk(KERN_CRIT "sealfs: fatal error! "
			"can't burn entry for inode: %ld)\n",
			ino->i_ino);
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
	freehmac(&hmacstate);
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
	/* open without append so we can trust the offset (we take care of it) */
	lower_file = dentry_open(&lower_path, file->f_flags&~O_APPEND, current_cred());
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

	//if(S_ISREG(file_inode(file)->i_mode) && !(file->f_mode & FMODE_CAN_READ)) {
	//	file->f_mode &= ~FMODE_ATOMIC_POS;
	//}
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

ssize_t sealfs_read_iter(struct kiocb *iocb, struct iov_iter *iter);

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

ssize_t sealfs_write_iter(struct kiocb *iocb, struct iov_iter *iter);

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
	.iterate_shared	= sealfs_readdir,
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
