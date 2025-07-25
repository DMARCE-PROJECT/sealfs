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

/*
 * The inode cache is used with alloc_inode for both our inode info and the
 * vfs inode.
 */
static struct kmem_cache *sealfs_inode_cachep;


/*
 * Free the extra fields for sealfs
 */
void sealfs_cleanup(struct sealfs_sb_info *spd)
{
 	kfree(spd->kpathname);
	kfree(spd->lpathname);
	if(spd->lfile){
		fput(spd->lfile);
	}
	if(spd->kfile){
		fput(spd->kfile);
	}
}

/* final actions when unmounting a file system */
static void sealfs_put_super(struct super_block *sb)
{
	struct sealfs_sb_info *spd;
	struct super_block *s;

	spd = SEALFS_SB(sb);
	if (!spd)
		return;
	/* decrement lower super references */
	s = sealfs_lower_super(sb);
	sealfs_set_lower_super(sb, NULL);
	atomic_dec(&s->s_active);

	sealfs_stop_thread(spd);
	if (waitqueue_active(&spd->thread_q))
		wake_up(&spd->thread_q);
	sealfs_seal_ratchet(spd);
	sealfs_update_hdr(spd);
	/* Q free the extra info resources */
 	sealfs_cleanup(spd);

	kfree(spd);
	sb->s_fs_info = NULL;
}

static int sealfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int err;
	struct path lower_path;

	sealfs_get_lower_path(dentry, &lower_path);
	err = vfs_statfs(&lower_path, buf);
	sealfs_put_lower_path(dentry, &lower_path);

	/* set return buf to our f/s to avoid confusing user-level utils */
	buf->f_type = SEALFS_SUPER_MAGIC;

	return err;
}

/*
 * @flags: numeric mount options
 * @options: mount options string
 */
static int sealfs_remount_fs(struct super_block *sb, int *flags, char *options)
{
	int err = 0;

	/*
	 * The VFS will take care of "ro" and "rw" flags among others.  We
	 * can safely accept a few flags (RDONLY, MANDLOCK), and honor
	 * SILENT, but anything else left over is an error.
	 */
	//if ((*flags & ~(MS_RDONLY | MS_MANDLOCK | MS_SILENT)) != 0) {
	//	printk(KERN_ERR
	//	       "sealfs: remount flags 0x%x unsupported\n", *flags);
	//	err = -EINVAL;
	//}

	return err;
}

/*
 * Called by iput() when the inode reference count reached zero
 * and the inode is not hashed anywhere.  Used to clear anything
 * that needs to be, before the inode is completely destroyed and put
 * on the inode free list.
 */
static void sealfs_evict_inode(struct inode *inode)
{
	struct inode *lower_inode;

	truncate_inode_pages(&inode->i_data, 0);
	clear_inode(inode);
	/*
	 * Decrement a reference to a lower_inode, which was incremented
	 * by our read_inode when it was created initially.
	 */
	lower_inode = sealfs_lower_inode(inode);
	sealfs_set_lower_inode(inode, NULL);
	iput(lower_inode);
}

static struct inode *sealfs_alloc_inode(struct super_block *sb)
{
	struct sealfs_inode_info *i;

	i = kmem_cache_alloc(sealfs_inode_cachep, GFP_KERNEL);
	if (!i)
		return NULL;

	/* memset everything up to the inode to 0 */
	memset(i, 0, offsetof(struct sealfs_inode_info, vfs_inode));

	i->vfs_inode.i_version.counter = 1;
	return &i->vfs_inode;
}

static void sealfs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(sealfs_inode_cachep, SEALFS_I(inode));
}

/* sealfs inode cache constructor */
static void init_once(void *obj)
{
	struct sealfs_inode_info *i = obj;

	inode_init_once(&i->vfs_inode);
}

int sealfs_init_inode_cache(void)
{
	int err = 0;

	sealfs_inode_cachep =
		kmem_cache_create("sealfs_inode_cache",
				  sizeof(struct sealfs_inode_info), 0,
				  SLAB_RECLAIM_ACCOUNT, init_once);
	if (!sealfs_inode_cachep)
		err = -ENOMEM;
	return err;
}

/* sealfs inode cache destructor */
void sealfs_destroy_inode_cache(void)
{
	rcu_barrier();
	if (sealfs_inode_cachep)
		kmem_cache_destroy(sealfs_inode_cachep);
}

/*
 * Used only in nfs, to kill any pending RPC tasks, so that subsequent
 * code can actually succeed and won't leave tasks that need handling.
 */
static void sealfs_umount_begin(struct super_block *sb)
{
	struct super_block *lower_sb;

	lower_sb = sealfs_lower_super(sb);
	if (lower_sb && lower_sb->s_op && lower_sb->s_op->umount_begin)
		lower_sb->s_op->umount_begin(lower_sb);
}

/*
 * Display the mount options in /proc/mounts.
 */
static int sealfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct sealfs_sb_info *sbi = root->d_sb->s_fs_info;

	seq_printf(m, ",kpath=%s, nratchet=%d", sbi->kpathname, sbi->nratchet);
	if (sbi->sync)
		seq_printf(m, ",syncio");
	return 0;
}

const struct super_operations sealfs_sops = {
	.put_super	= sealfs_put_super,
	.statfs		= sealfs_statfs,
	.remount_fs	= sealfs_remount_fs,
	.evict_inode	= sealfs_evict_inode,
	.umount_begin	= sealfs_umount_begin,
	.show_options	= sealfs_show_options,
	.alloc_inode	= sealfs_alloc_inode,
	.destroy_inode	= sealfs_destroy_inode,
	.drop_inode	= generic_delete_inode,
};

/* NFS support */

static struct inode *sealfs_nfs_get_inode(struct super_block *sb, u64 ino,
					  u32 generation)
{
	struct super_block *lower_sb;
	struct inode *inode;
	struct inode *lower_inode;

	lower_sb = sealfs_lower_super(sb);
	lower_inode = ilookup(lower_sb, ino);
	inode = sealfs_iget(sb, lower_inode);
	return inode;
}

static struct dentry *sealfs_fh_to_dentry(struct super_block *sb,
					  struct fid *fid, int fh_len,
					  int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    sealfs_nfs_get_inode);
}

static struct dentry *sealfs_fh_to_parent(struct super_block *sb,
					  struct fid *fid, int fh_len,
					  int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    sealfs_nfs_get_inode);
}

/*
 * all other funcs are default as defined in exportfs/expfs.c
 */

const struct export_operations sealfs_export_ops = {
	.fh_to_dentry	   = sealfs_fh_to_dentry,
	.fh_to_parent	   = sealfs_fh_to_parent
};
