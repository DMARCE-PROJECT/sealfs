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

static int sealfs_create(struct user_namespace *ns, struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
        int err;
        struct dentry *lower_dentry;
        struct dentry *lower_parent_dentry = NULL;
        struct path lower_path;

        sealfs_get_lower_path(dentry, &lower_path);
        lower_dentry = lower_path.dentry;
        lower_parent_dentry = lock_parent(lower_dentry);

        err = vfs_create(ns, d_inode(lower_parent_dentry), lower_dentry, mode,
                         want_excl);
        if (err)
                goto out;
        err = sealfs_interpose(dentry, dir->i_sb, &lower_path);
        if (err)
                goto out;
        fsstack_copy_attr_times(dir, sealfs_lower_inode(dir));
        fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
        unlock_dir(lower_parent_dentry);
        sealfs_put_lower_path(dentry, &lower_path);
        return err;
}

/* disabled */
static int sealfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	return -EPERM;
}

/* disabled */
static int sealfs_unlink(struct inode *dir, struct dentry *dentry)
{
	return -EPERM;
}

/* disabled */
static int sealfs_symlink(struct user_namespace *ns, struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	return -EPERM;
}

/* disabled */
static int sealfs_mkdir(struct user_namespace *ns, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return -EPERM;
}

/* disabled */
static int sealfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	return -EPERM;
}

/* disabled */
static int sealfs_mknod(struct user_namespace *ns, struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	return -EPERM;
}

/*
 * Needed for rotating logs
 * unmodified wrapfs version
 * ported, now it needs a new parameter: flags
 */
static int sealfs_rename (struct user_namespace *ns, struct inode *old_dir, struct dentry *old_dentry,
                        struct inode *new_dir, struct dentry *new_dentry,
                        unsigned int flags)
{
	struct renamedata rd;
	int err = 0;
        struct dentry *lower_old_dentry = NULL;
        struct dentry *lower_new_dentry = NULL;
        struct dentry *lower_old_dir_dentry = NULL;
        struct dentry *lower_new_dir_dentry = NULL;
        struct dentry *trap = NULL;
        struct path lower_old_path, lower_new_path;

        sealfs_get_lower_path(old_dentry, &lower_old_path);
        sealfs_get_lower_path(new_dentry, &lower_new_path);
        lower_old_dentry = lower_old_path.dentry;
        lower_new_dentry = lower_new_path.dentry;
        lower_old_dir_dentry = dget_parent(lower_old_dentry);
        lower_new_dir_dentry = dget_parent(lower_new_dentry);

        trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
        /* source should not be ancestor of target */
        if (trap == lower_old_dentry) {
                err = -EINVAL;
                goto out;
        }
        /* target should not be ancestor of source */
        if (trap == lower_new_dentry) {
                err = -ENOTEMPTY;
                goto out;
        }
	rd.old_mnt_userns	= ns;
	rd.old_dir	= d_inode(lower_old_dir_dentry);
	rd.old_dentry	= lower_old_dentry;
	rd.new_mnt_userns	= ns;
	rd.new_dir	= d_inode(lower_new_dir_dentry);
	rd.new_dentry	= lower_new_dentry;
	rd.flags = flags;

        err = vfs_rename(&rd);
        if (err)
                goto out;

        fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
        fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
        if (new_dir != old_dir) {
                fsstack_copy_attr_all(old_dir,
                                      d_inode(lower_old_dir_dentry));
                fsstack_copy_inode_size(old_dir,
                                        d_inode(lower_old_dir_dentry));
        }

out:
        unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
        dput(lower_old_dir_dentry);
        dput(lower_new_dir_dentry);
        sealfs_put_lower_path(old_dentry, &lower_old_path);
        sealfs_put_lower_path(new_dentry, &lower_new_path);
        return err;
}
static int sealfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sealfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = d_inode(lower_dentry)->i_op->readlink(lower_dentry, buf, bufsiz);
	if (err < 0) {
		goto out;
	}
	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

out:
	sealfs_put_lower_path(dentry, &lower_path);
	return err;
}

static const char *sealfs_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	char *buf;
	int n;
	char *bufuser;
	int len = PAGE_SIZE, err;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		return buf;
	}

	bufuser = kmalloc(len, GFP_USER);
	if (!bufuser) {
		kfree(buf);
		buf = ERR_PTR(-ENOMEM);
		return buf;
	}

	/* read the symlink, and then we will follow it */
	err = sealfs_readlink(dentry, bufuser, len);
	if(err < 0)
		goto errout;
	n = copy_from_user(buf, bufuser, err);
	if(n < 0){
		err = n;
		goto errout;
	}
	buf[n] = '\0';
	kfree(bufuser);
	set_delayed_call(done, kfree_link, buf);
	return buf;
errout:
	kfree(bufuser);
	kfree(buf);
	buf = ERR_PTR(err);
	return buf;
}

static int sealfs_permission(struct user_namespace *ns, struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = sealfs_lower_inode(inode);
	err = inode_permission(ns, lower_inode, mask);
	return err;
}

static int sealfs_setattr(struct user_namespace *ns, struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = d_inode(dentry);

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 * Ported: inode_change_ok was removed, now it's setattr_prepare()
	 * and the first parameter is a dentry* (it was an inode*)
	 */
	err = setattr_prepare(ns, dentry, ia);
	if (err)
		goto out_err;

	sealfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = sealfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = sealfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(ns, lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	sealfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

/*
 * Ported for the new statx() syscall
 */
static int sealfs_getattr(struct user_namespace *ns, const struct path *path, struct kstat *stat,
                 u32 request_mask, unsigned int query_flags)
{
	int err;
	struct kstat lower_stat;
	struct path lower_path;

	sealfs_get_lower_path(path->dentry, &lower_path);

	err = vfs_getattr(&lower_path, &lower_stat,
		request_mask, query_flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(path->dentry),
			      d_inode(lower_path.dentry));
	generic_fillattr(ns, d_inode(path->dentry), stat);
	stat->blocks = lower_stat.blocks;
out:
	sealfs_put_lower_path(path->dentry, &lower_path);
	return err;
}

static ssize_t
sealfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sealfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->listxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, buffer, buffer_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sealfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
	Ported:
	see: https://patchwork.kernel.org/patch/9140641/
	All filesystems that support xattrs by now do so via xattr handlers.
	They all define sb->s_xattr, and their getxattr, setxattr, and
	removexattr inode operations use the generic inode operations.  On
	filesystems that don't support xattrs, the xattr inode operations are
	all NULL, and sb->s_xattr is also NULL.

	This means that we can remove the getxattr, setxattr, and removexattr
	inode operations and directly call the generic handlers, or better,
	inline expand those handlers into fs/xattr.c.

	Filesystems that do not support xattrs on some inodes should clear the
	IOP_XATTR i_opflags flag in those inodes.  (Right now, some filesystems
	have checks to disable xattrs on some inodes in the ->list, ->get, and
	->set xattr handler operations instead.)  The IOP_XATTR flag is
	automatically cleared in inodes of filesystems that don't have xattr
	support
 */

const struct inode_operations sealfs_symlink_iops = {
	.readlink	= sealfs_readlink,
	.permission	= sealfs_permission,
	.setattr	= sealfs_setattr,
	.getattr	= sealfs_getattr,
	.get_link	= sealfs_get_link,
 	.listxattr	= sealfs_listxattr,
};

const struct inode_operations sealfs_dir_iops = {
	.create		= sealfs_create,
	.lookup		= sealfs_lookup,
	.link		= sealfs_link,
	.unlink		= sealfs_unlink,
	.symlink	= sealfs_symlink,
	.mkdir		= sealfs_mkdir,
	.rmdir		= sealfs_rmdir,
	.mknod		= sealfs_mknod,
	.rename		= sealfs_rename,
	.permission	= sealfs_permission,
	.setattr	= sealfs_setattr,
	.getattr	= sealfs_getattr,
 	.listxattr	= sealfs_listxattr,
};

const struct inode_operations sealfs_main_iops = {
	.permission	= sealfs_permission,
	.setattr	= sealfs_setattr,
	.getattr	= sealfs_getattr,
 	.listxattr	= sealfs_listxattr,
};
