#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

# Single threaded asynchronous ($sync) sequential writes (1MB I/Os) to
# a 1GB file.
# Stops after 1 series of 1024 ($count) writes has been done.

# symlinks must be in /tmp/links/testF/

set $dir=/tmp/links
set $cached=false
set $count=9000
set $iosize=100
set $sync=false
set $nproc=1
set $nthreads=1

define fileset name="testF",entries=$nproc,prealloc,size=0,path=$dir,dirwidth="0",reuse

define process name=filewriter,instances=$nproc
{
  thread name=filewriterthread,memsize=10m,instances=$nthreads
  {
    flowop appendfile name=write-file,dsync=$sync,filesetname="testF",iosize=$iosize,iters=$count
#    flowop finishoncount name=finish,value=0
  }
}

echo  "FileMicro-SeqWrite Version 2.2 personality successfully loaded"

run 60
echo "remember if you did not:"
echo "echo 0 > /proc/sys/kernel/randomize_va_space" 
