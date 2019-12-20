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

static ssize_t sealfs_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	/*
	 * This function should never be called directly.  We need it
	 * to exist, to get past a check in open_check_o_direct(),
	 * which is called from do_last().
	 */
	return -EINVAL;
}

const struct address_space_operations sealfs_aops = {
	.direct_IO = sealfs_direct_IO,
};

/*
 * mmap is forbiden for sealfs files, no vm_operations_struct handlers here.
 */
