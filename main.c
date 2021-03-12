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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/parser.h>
#include <linux/sched/signal.h>

/*
 * check only dentries of the lower path
 */
static int is_task_using(struct task_struct *task, struct path *path)
{
	struct files_struct *files = NULL;
 	struct file *file = NULL;
	struct fdtable *fdt;
	int i;

	files = task->files;
 	if (files) {
 		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		if(fdt){
			for (i=0; i < fdt->max_fds; i++) {
		        	file = fcheck_files(files, i);
				if(file){
					// should be the same pointer, the
					// dentry is cached... right?
					if(file->f_path.dentry->d_parent == path->dentry){
						spin_unlock(&files->file_lock);
  						return 1;
					}
				}
			}
		}
		spin_unlock(&files->file_lock);
	}
 	return 0;
}

static int files_in_use(struct path *lower_path)
{
	struct task_struct *task;
 	int found = 0;

  	for_each_process(task) {
		task_lock(task);
		found = is_task_using(task, lower_path);
		task_unlock(task);
		if(found)
			return 1;
	}
 	return 0;
}

/*
 * RDRW and bypassing the file cache
 */
static struct file * _openfile(char *s, char sync) {
	struct path p;
	struct file * f;
	int err;
	const struct cred *cred = current_cred();

	err = kern_path(s, 0, &p);
	if(err){
		return NULL;
	}
 	if(sync){
		f = dentry_open(&p, O_LARGEFILE|O_RDWR|O_SYNC, cred);
	}else{
		f = dentry_open(&p, O_LARGEFILE|O_RDWR, cred);
	}
	err = PTR_ERR(f);
	if (IS_ERR(f)){
		path_put(&p);
		return NULL;
	}
	path_put(&p);
	return f;
}

static loff_t get_keysz(struct sealfs_sb_info *info)
{
	struct kstat kst;
	int err;
	err = file_inode(info->kfile)->i_op->getattr(&info->kfile->f_path, &kst,
		STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
	if(err){
		printk(KERN_ERR "sealfs: can't get attr from key file\n");
		return -1;
	}
	return kst.size;
}

static int read_headers(struct sealfs_sb_info *info)
{
	loff_t nr;
	size_t lsz = sizeof(struct sealfs_logfile_header);
	size_t ksz = sizeof(struct sealfs_keyfile_header);
	loff_t o;

	o = 0;
	nr = kernel_read(info->kfile, (char*) &info->kheader, ksz, &o);
	if(nr != ksz){
		printk(KERN_ERR	"sealfs: error reading"
		" kheader: %lld bytes\n", nr);
		return -1;
	}
	atomic_long_set(&info->burnt, info->kheader.burnt);
	o = 0;
 	nr = kernel_read(info->lfile, (char*) &info->lheader, lsz, &o);
	if(nr != lsz){
		printk(KERN_ERR	"sealfs: error reading "
		"lheader: %lld\n", nr);
		return -1;
	}
	info->maxkfilesz = get_keysz(info);
	if (info->maxkfilesz <= 0){
		printk(KERN_ERR "sealfs: bad key file size\n");
		return -1;
	}
	pr_notice("sealfs: maxkfilesz: %lld\n", info->maxkfilesz);
	pr_notice("sealfs: kheader magic: %lld burnt: %lld\n",
			info->kheader.magic,
			info->kheader.burnt);
	pr_notice("sealfs: lheader magic: %lld\n",
			info->lheader.magic);
	return 0;
}

/*
 * There is no need to lock the sealfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int sealfs_read_super(struct super_block *sb,
				void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
 	struct inode *inode;
	struct sealfs_sb_info *info;

	sb->s_fs_info =  raw_data;
	info = (struct sealfs_sb_info*) raw_data;

	/* parse lower path */
	err = kern_path(info->dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"sealfs: error accessing "
		       "lower directory '%s'\n", info->dev_name);
		goto out_free;
	}

	/*
	 * Q check that no task is using files in the directory
	 * Note that there is a race: a process could open a lower file
	 * before this FS is actually on top. Moreover, a process with in other
	 * namespace could open any of the lower files without passing
	 * through this FS. This is only a check.
	 */
 	if (files_in_use(&lower_path)){
		printk(KERN_ERR
			"sealfs: files in lower dir already in use\n");
		err = -EBUSY;
 		goto out_free;
	}

	/* Q open keyfile and logfile */
	info->kfile = _openfile(info->kpathname, info->sync);
	if(!info->kfile){
		printk(KERN_ERR
			"sealfs: can't open kfile\n");
		err = -EBUSY;
 		goto out_free;
	}
	info->lfile = _openfile(info->lpathname, info->sync);
	if(!info->lfile){
		printk(KERN_ERR
			"sealfs: can't open lfile\n");
		err = -EBUSY;
		goto out_free;
	}
	if(read_headers(info) < 0){
		printk(KERN_ERR
			"sealfs: can't read headers\n");
		err = -EBUSY;
		goto out_free;
	}
	if(info->kheader.magic != info->lheader.magic){
		printk(KERN_ERR
			"sealfs: magic number is not ok\n");
		err = -EBUSY;
		goto out_free;
	}

	/* Q init the mutexes */
	mutex_init(&info->bbmutex);
	mutex_init(&info->burnsyncmutex);
	
	info->ratchetoffset = 0;
	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	sealfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &sealfs_sops;

	sb->s_export_op = &sealfs_export_ops; /* adding NFS support */

	/* get a new inode and allocate our root dentry */
	inode = sealfs_iget(sb, d_inode(lower_path.dentry));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &sealfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	sealfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "sealfs: mounted on top of %s type %s\n",
		       info->dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(SEALFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	/* Q free the extra info resources */
  	sealfs_cleanup(info);
	path_put(&lower_path);
out:
	sealfs_start_thread(info);
	return err;
}


enum {
	Opt_kpath,
	Opt_syncio,
	Opt_nratchet,
	Opt_err,
};

static const match_table_t tokens = {
	{Opt_kpath, "kpath=%s"},
	{Opt_syncio, "syncio"},
	{Opt_nratchet, "nratchet=%d"},
	{Opt_err, NULL}
};

struct dentry *sealfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
 	struct sealfs_sb_info *info;
	int token;
	char *p;
	char *options;
	substring_t args[MAX_OPT_ARGS];
	int ret = 0;
	int sz;
	int intarg;

	if (!dev_name) {
		printk(KERN_ERR
		       "sealfs: read_super: missing dev_name argument\n");
		return ERR_PTR(-EINVAL);
	}
 	info = (struct sealfs_sb_info *)
		kzalloc(sizeof(struct sealfs_sb_info), GFP_KERNEL);
	if (!info) {
		printk(KERN_CRIT "sealfs: read_super: out of memory\n");
 		return ERR_PTR(-ENOMEM);
	}
	info->dev_name = (char*) dev_name;
	options = (char *)raw_data;
	if (!options) {
		printk(KERN_CRIT "sealfs: option kpath is required\n");
 		ret = -EINVAL;
		goto error;
	}

	info->nratchet = NRATCHET;
	while((p = strsep(&options, ",")) != NULL){
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		switch(token){
		case Opt_kpath:
			info->kpathname = match_strdup(&args[0]);
			if (!info->kpathname) {
				ret = -ENOMEM;
				goto error;
			}
			break;
		case Opt_nratchet:
			if(match_int(&args[0], &intarg)){
				ret = -EINVAL;
				goto error;
			}
			info->nratchet = intarg;
			if(info->nratchet <= 0)
				info->nratchet = 1;
			break;
		case Opt_syncio:
			info->sync++;
			pr_notice("sealfs: synchronous IO\n");
			break;
		default:
			continue;
		}
	}
	if(!info->kpathname){
		printk(KERN_CRIT "sealfs: option kpath is required\n");
 		ret = -EINVAL;
		goto error;
	}
	sz = strlen(dev_name) + strlen(DEFAULTLNAME) + 2;
	info->lpathname = kzalloc(sz, GFP_KERNEL);
	snprintf(info->lpathname, sz, "%s/%s", dev_name, DEFAULTLNAME);
	pr_notice("sealfs: kpathname is %s\n", info->kpathname);
	pr_notice("sealfs: lpathname is %s\n", info->lpathname);
	return mount_nodev(fs_type, flags, info, sealfs_read_super);
error:
	if(info->lpathname)
		kfree(info->lpathname);
	if(info->kpathname)
		kfree(info->kpathname);
	kfree(info);
	return ERR_PTR(ret);
}

static struct file_system_type sealfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= SEALFS_NAME,
	.mount		= sealfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(SEALFS_NAME);

static int __init init_sealfs_fs(void)
{
	int err;

	pr_info("Registering sealfs " SEALFS_VERSION "\n");

	err = sealfs_init_inode_cache();
	if (err)
		goto out;
	err = sealfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&sealfs_fs_type);
out:
	if (err) {
		sealfs_destroy_inode_cache();
		sealfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_sealfs_fs(void)
{
	sealfs_destroy_inode_cache();
	sealfs_destroy_dentry_cache();
	unregister_filesystem(&sealfs_fs_type);
	pr_info("Completed sealfs module unload\n");
}

MODULE_AUTHOR("Enrique Soriano <esoriano@gsyc.urjc.es>");
MODULE_DESCRIPTION("Sealfs " SEALFS_VERSION);
MODULE_LICENSE("GPL");

module_init(init_sealfs_fs);
module_exit(exit_sealfs_fs);
