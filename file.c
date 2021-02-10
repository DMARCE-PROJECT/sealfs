/*
 *  Copyright (c) 2019  Enrique Soriano
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


static int initshash(struct sealfs_sb_info *sb)
{
	sb->hash_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if(IS_ERR(sb->hash_tfm)) {
 		printk(KERN_ERR "sealfs: can't alloc hash_tfm struct\n");
		return -1;
	}
	sb->hash_desc = kzalloc(sizeof(struct shash_desc) +
			       crypto_shash_descsize(sb->hash_tfm), GFP_KERNEL);
	if(sb->hash_desc == NULL){
		crypto_free_shash(sb->hash_tfm);
		printk(KERN_ERR "sealfs: can't alloc hash_desc struct\n");
		return -1;
	}
	sb->hash_desc->tfm = sb->hash_tfm;
	//sb->hash_desc->flags = 0;
	return 0;
}

static int do_hmac(struct sealfs_sb_info *sb,
			const char __user *data, char *key,
	 		struct sealfs_logfile_entry *lentry)
{
	int err = 0;
	u8	*buf;

	if(sb->hash_tfm == NULL){
		if(initshash(sb) < 0)
			return -1;
	}
	err = crypto_shash_setkey(sb->hash_tfm, key, FPR_SIZE);
	if(err){
		printk(KERN_ERR "sealfs: can't load hmac key\n");
		return -1;
	}
	err = crypto_shash_init(sb->hash_desc);
	if(err){
		printk(KERN_ERR "sealfs: can't init hmac\n");
		return -1;
	}
 	err = crypto_shash_update(sb->hash_desc,
			(u8*) &lentry->inode, sizeof(lentry->inode));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: inode\n");
		return -1;
	}
	err = crypto_shash_update(sb->hash_desc,
			(u8*) &lentry->offset, sizeof(lentry->offset));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: offset\n");
		return -1;
	}
	err = crypto_shash_update(sb->hash_desc,
			(u8*) &lentry->count, sizeof(lentry->count));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: count\n");
		return -1;
	}
	err = crypto_shash_update(sb->hash_desc,
			(u8*) &lentry->koffset, sizeof(lentry->koffset));
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: koffset\n");
		return -1;
	}

	buf = kmalloc(lentry->count, GFP_KERNEL);
	if (!buf)
		return -1;
	if (copy_from_user(buf, data, lentry->count)) {
		printk(KERN_ERR "sealfs: cannot copy from user data\n");
		return -1;
	}
	err = crypto_shash_update(sb->hash_desc, (u8*)buf, lentry->count);
	if(err){
		printk(KERN_ERR "sealfs: can't updtate hmac: data\n");
		return -1;
	}
	kfree(buf);
	err = crypto_shash_final(sb->hash_desc, (u8 *) lentry->fpr);
	if(err){
		printk(KERN_ERR "sealfs: can't final hmac\n");
		return -1;
	}
	//zero the key and the internal data
	memset(key, 0, FPR_SIZE);
	err = crypto_shash_setkey(sb->hash_tfm, key, FPR_SIZE);
	if(err){
		printk(KERN_ERR "sealfs: can't reset hmac key\n");
		return -1;
	}
	return 0;
}
static int has_advanced_burnt(struct sealfs_sb_info *sb, loff_t oldburnt)
{
	loff_t newburnt;

	mutex_lock(&sb->bbmutex);
	newburnt = sb->kheader.burnt;
	mutex_unlock(&sb->bbmutex);
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

static int sealfs_thread(void *data)
{
	struct sealfs_sb_info *sb=(struct sealfs_sb_info *)data;
	wait_queue_head_t *q =&sb->thread_q;
	loff_t burnt, unburnt, chkburnt;
	int hdrpending;

	hdrpending = 1;
	/* starts after header */
	unburnt = sizeof(struct sealfs_keyfile_header);

repeat:
	mutex_lock(&sb->bbmutex);
	burnt = sb->kheader.burnt;
	mutex_unlock(&sb->bbmutex);
	while(unburnt  < burnt) {
		/* burn with random from oldburnt to burnt */
		chkburnt = burn_key(sb, unburnt, (burnt - unburnt)/FPR_SIZE);
		if(chkburnt < 0) {
			printk(KERN_ERR "sealfs: error writing key file\n");
			break;
		}
		unburnt = unburnt + chkburnt;
		hdrpending = 1;
	}
	/* update header */
	if(hdrpending){
		sealfs_update_hdr(sb);
		hdrpending = 0;
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
		kthread_should_stop() || has_advanced_burnt(sb, unburnt), HZ);
	goto repeat;
}

void sealfs_stop_thread(struct sealfs_sb_info *sb)
{
	kthread_stop(sb->sync_thread);
	
}
void sealfs_start_thread(struct sealfs_sb_info *sb)
{
	init_waitqueue_head(&sb->thread_q);
	sb->sync_thread = kthread_run(sealfs_thread, sb, "sealfs");
}

int sealfs_update_hdr(struct sealfs_sb_info *sb)
{
	struct sealfs_keyfile_header hdr;
	loff_t zoff;
	size_t x;
	zoff = 0;
	mutex_lock(&sb->bbmutex);
	hdr = sb->kheader;
	mutex_unlock(&sb->bbmutex);
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
		mutex_unlock(&sb->bbmutex);
		printk(KERN_ERR "sealfs: can't write key file header\n");
		return -1;
	}
	return 0;
}

/*
 * This operation need to be atomic for clients, bbmutex needs to be taken when called
 *	if it wasn't, one client overtaking other would provoke Burn before reading key (bad)
 */
static loff_t read_key(struct sealfs_sb_info *sb, unsigned char *k)
{
	loff_t nr;
	loff_t t;
	loff_t oldoff, keyoff;

	/*
	  * Updating sb->keytaken commits us to
	 * 	- FPR_SIZE reading in key file (out of reach for futures reads)
	 *	- then, atomically (w.r.t. the sb->bbmutex) sb->kheader.burnt (Burn *after* reading)
	 *	- Later (without lock) writing sizeof(struct sealfs_logfile_entry) in log entry in the correct offset
	 *	- Updating offset header at start of key file at some point in the future
	 *	- We will burn what is read asynchronously in the kthread driven by sb->kheader.burnt
	 */
	oldoff = sb->keytaken;
	if(sb->keytaken >= sb->maxkfilesz){
			printk(KERN_ERR "sealfs: burnt key\n");
			return -1;
	}
	sb->keytaken += FPR_SIZE;
	keyoff = oldoff;
	t = 0ULL;
	
	while(t < FPR_SIZE){
		nr = kernel_read(sb->kfile, k+t, ((loff_t)FPR_SIZE)-t, &keyoff);
		if(nr < 0) {
			mutex_unlock(&sb->bbmutex);
			printk(KERN_ERR "sealfs: error while reading\n");
			return -1;
		}
		if(nr == 0){
			mutex_unlock(&sb->bbmutex);
			printk(KERN_ERR "sealfs: key file is burnt\n");
			return -1;
		}
  		t += nr;
	}
	sb->kheader.burnt = sb->keytaken;

	return oldoff;
}

static int burn_entry(struct file *f, const char __user *buf, size_t count,
			loff_t offset, 	struct sealfs_sb_info *sb)
{
	unsigned char key[FPR_SIZE];
	int  sz;
	struct sealfs_logfile_entry lentry;
	loff_t o;
	loff_t keyoff;

	lentry.inode = (uint64_t) file_inode(f)->i_ino;
	lentry.offset = (uint64_t) offset;
	lentry.count = (uint64_t) count;

	mutex_lock(&sb->bbmutex);
	keyoff = read_key(sb, key);
	mutex_unlock(&sb->bbmutex);
	// maybe an option to do it synchronously, at least burn?
	// in that case UNLOCK FIRST (out of the function)
	//if(sealfs_update_hdr(sb) < 0)
	//	return -1;
	//if(burn_key(sb, keyoff, 1) < 0)
	//	return -1;
	if(keyoff < 0) {
		printk(KERN_ERR "sealfs: readkey failed\n");
		return -1;
	}
	lentry.koffset =  (uint64_t) keyoff;
	mutex_lock(&sb->hash_mutex);	/* careful hash_tfm and hash_desc */
	if(do_hmac(sb, buf, key, &lentry) < 0){
		printk(KERN_ERR "sealfs: do_hash failed\n");
		mutex_unlock(&sb->hash_mutex);
		return -1;
      	}
	mutex_unlock(&sb->hash_mutex);
	sz = sizeof(struct sealfs_logfile_entry);
	o = sizeof(struct sealfs_logfile_header) + (keyoff/FPR_SIZE)*sz;

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
	int debug = 0;

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
	 * probable, but possible. Verify compensates for this (by using a heap)
	 */
	if(wr < 0)
		return wr;

	if(burn_entry(file, buf, wr, woffset, sbinfo) < 0){
		printk(KERN_CRIT "sealfs: fatal error! "
			"can't burn entry for inode: %lld)\n",
			(long long) ino->i_ino);
		wr = -EIO;
	}
	if(debug)
		printk(KERN_INFO
			"sealfs: append-only write  "
			"to file %s offset: %lld count: %lld\n",
			file->f_path.dentry->d_name.name,
			(long long) woffset,
			(long long) count);	
	if(wr != count) {
		printk(KERN_INFO "sealfs: warning! %lld bytes "
			"of %lld bytes have been written"
			" (inode: %lld)\n",
			(long long) wr,
			(long long) count,
			(long long) ino->i_ino);
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
