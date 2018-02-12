/*
 *  Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301, USA.
 */

/************************************************************************/
/*                                                                      */
/*  PROJECT : exFAT & FAT12/16/32 File System                           */
/*  FILE    : xattr.c                                                   */
/*  PURPOSE : sdFAT code for supporting xattr(Extended File Attributes) */
/*                                                                      */
/*----------------------------------------------------------------------*/
/*  NOTES                                                               */
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/dcache.h>
#include "sdfat.h"

#ifndef CONFIG_SDFAT_VIRTUAL_XATTR_SELINUX_LABEL
#define CONFIG_SDFAT_VIRTUAL_XATTR_SELINUX_LABEL	("undefined")
#endif

static const char default_xattr[] = CONFIG_SDFAT_VIRTUAL_XATTR_SELINUX_LABEL;

static int can_support(const char *name)
{
	if (!name || strcmp(name, "security.selinux"))
		return -1;
	return 0;
}

int sdfat_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
	if (can_support(name))
		return -EOPNOTSUPP;

	return 0;
}

ssize_t sdfat_getxattr(struct dentry *dentry, const char *name, void *value, size_t size)
{
	if (can_support(name))
		return -EOPNOTSUPP;

	if ((size > strlen(default_xattr)+1) && value)
		strcpy(value, default_xattr);

	return strlen(default_xattr);
}

ssize_t sdfat_listxattr(struct dentry *dentry, char *list, size_t size)
{
	return 0;
}

int sdfat_removexattr(struct dentry *dentry, const char *name)
{
	if (can_support(name))
		return -EOPNOTSUPP;

	return 0;
}


