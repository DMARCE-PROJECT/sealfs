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

// should be in linux/magic.h, just in case
#ifndef SEALFS_SUPER_MAGIC
#define SEALFS_SUPER_MAGIC	0xb550ca22
#endif

#ifndef _SEALFS_H_
#define _SEALFS_H_


#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/highmem.h>	//kmap
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/xattr.h>
#include <linux/exportfs.h>
#include <crypto/hash_info.h>
#include <crypto/hash.h>
#include <linux/random.h>
#include <linux/stat.h>
#include "sealfstypes.h" //shared with userland tools


/* the file system name */
#define SEALFS_NAME "sealfs"

/* sealfs root inode number */
#define SEALFS_ROOT_INO     1

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

/* operations vectors defined in specific files */
extern const struct file_operations sealfs_main_fops;
extern const struct file_operations sealfs_dir_fops;
extern const struct inode_operations sealfs_main_iops;
extern const struct inode_operations sealfs_dir_iops;
extern const struct inode_operations sealfs_symlink_iops;
extern const struct super_operations sealfs_sops;
extern const struct dentry_operations sealfs_dops;
extern const struct address_space_operations sealfs_aops, sealfs_dummy_aops;
extern const struct vm_operations_struct sealfs_vm_ops;
extern const struct export_operations sealfs_export_ops;

extern int sealfs_init_inode_cache(void);
extern void sealfs_destroy_inode_cache(void);
extern int sealfs_init_dentry_cache(void);
extern void sealfs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *sealfs_lookup(struct inode *dir, struct dentry *dentry,
				    unsigned int flags);
extern struct inode *sealfs_iget(struct super_block *sb,
				 struct inode *lower_inode);
extern int sealfs_interpose(struct dentry *dentry, struct super_block *sb,
			    struct path *lower_path);


/* file private data */
struct sealfs_file_info {
	struct file *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
};

/* sealfs inode data in memory */
struct sealfs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
};

/* sealfs dentry data in memory */
struct sealfs_dentry_info {
	spinlock_t lock;	/* protects the lower_path, from wrapfs */
	struct mutex imutex;	/* protects the inode's offset for sealfs */
	struct path lower_path;
};

#include <linux/kthread.h>
enum {
	NBURNTHREADS=3,
};

struct sealfs_hmac_state {
	struct crypto_shash *hash_tfm;
	struct shash_desc *hash_desc;
};

/* sealfs super-block data in memory */
struct sealfs_sb_info {
	struct super_block *lower_sb;
	int nratchet;
	struct mutex bbmutex;
	//synchronize burners and make sure they write to disk
	struct mutex burnsyncmutex;
	char *dev_name;
	char *kpathname;
	char *lpathname;
	char sync; // synchronous IO
 	struct file *kfile;
	struct file *lfile;

	atomic_long_t	burnt;
	//kheader contains the header as it was read when mounting
	//	burnt is tracked by the atomic above
	struct sealfs_keyfile_header kheader;
	struct sealfs_logfile_header lheader;

	//protected by readkey file/burn mutex (bbmutex)
	unsigned char key[FPR_SIZE];
	int ratchetoffset;

	loff_t maxkfilesz;
	wait_queue_head_t thread_q;	//first is different, higher freq and woken by clients
	wait_queue_head_t slow_thread_q;
	int nthreads;
	struct task_struct *sync_thread[NBURNTHREADS];
};

extern void sealfs_cleanup(struct sealfs_sb_info *);
extern int sealfs_update_hdr(struct sealfs_sb_info *);
extern void sealfs_stop_thread(struct sealfs_sb_info *);
extern void sealfs_start_thread(struct sealfs_sb_info *);
extern void sealfs_seal_ratchet(struct sealfs_sb_info *);
/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * sealfs_inode_info structure, SEALFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct sealfs_inode_info *SEALFS_I(const struct inode *inode)
{
	return container_of(inode, struct sealfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define SEALFS_D(dent) ((struct sealfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define SEALFS_SB(super) ((struct sealfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define SEALFS_F(file) ((struct sealfs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *sealfs_lower_file(const struct file *f)
{
	return SEALFS_F(f)->lower_file;
}

static inline void sealfs_set_lower_file(struct file *f, struct file *val)
{
	SEALFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *sealfs_lower_inode(const struct inode *i)
{
	return SEALFS_I(i)->lower_inode;
}

static inline void sealfs_set_lower_inode(struct inode *i, struct inode *val)
{
	SEALFS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *sealfs_lower_super(
	const struct super_block *sb)
{
	return SEALFS_SB(sb)->lower_sb;
}

static inline void sealfs_set_lower_super(struct super_block *sb,
					  struct super_block *val)
{
	SEALFS_SB(sb)->lower_sb = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void sealfs_get_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&SEALFS_D(dent)->lock);
	pathcpy(lower_path, &SEALFS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&SEALFS_D(dent)->lock);
	return;
}
static inline void sealfs_put_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	path_put(lower_path);
	return;
}
static inline void sealfs_set_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&SEALFS_D(dent)->lock);
	pathcpy(&SEALFS_D(dent)->lower_path, lower_path);
	spin_unlock(&SEALFS_D(dent)->lock);
	return;
}
static inline void sealfs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&SEALFS_D(dent)->lock);
	SEALFS_D(dent)->lower_path.dentry = NULL;
	SEALFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&SEALFS_D(dent)->lock);
	return;
}
static inline void sealfs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&SEALFS_D(dent)->lock);
	pathcpy(&lower_path, &SEALFS_D(dent)->lower_path);
	SEALFS_D(dent)->lower_path.dentry = NULL;
	SEALFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&SEALFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	inode_unlock(d_inode(dir));
	dput(dir);
}
#endif	/* not _SEALFS_H_ */
