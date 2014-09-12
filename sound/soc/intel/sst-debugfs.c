/*
 * Intel Smart Sound Technology (SST) debugfs support
 *
 * Copyright (C) 2014, Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>

#include "sst-dsp.h"
#include "sst-dsp-priv.h"

struct sst_dfsentry {
	struct dentry *dfsentry;
	size_t size;
	void *buf;
	struct sst_dsp *sst;
};

static int sst_dfsentry_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;

	return 0;
}

static ssize_t sst_dfsentry_read(struct file *file, char __user *buffer,
				 size_t count, loff_t *ppos)
{
	struct sst_dfsentry *dfse = file->private_data;
	int i, size;
	u32 *buf;

	pr_debug("%s: pbuf: %p, *ppos: 0x%llx", __func__, buffer, *ppos);

	size = dfse->size;

	if (*ppos >= size)
		return 0;
	if (*ppos + count > size)
		count = size - *ppos;

	size = (count + 3) & (~3);
	buf = kzalloc(size, GFP_KERNEL);
	if (!buf) {
		pr_err(" %s: kzalloc failed, aborting\n", __func__);
		return -ENOMEM;
	}

	for (i = 0; i < size / sizeof(*buf); i++)
		buf[i] = *(u32 *)(dfse->buf + *ppos + i * sizeof(*buf));

	if (copy_to_user(buffer, buf, count))
		return 0;
	kfree(buf);

	*ppos += count;

	pr_debug("%s: *ppos: 0x%llx, count: %zu", __func__, *ppos, count);

	return count;
}

static ssize_t sst_dfsentry_write(struct file *file, const char __user *buffer,
				  size_t count, loff_t *ppos)
{
	struct sst_dfsentry *dfse = file->private_data;
	int i, size;
	u32 *buf;

	pr_debug("%s: pbuf: %p, *ppos: 0x%llx", __func__, buffer, *ppos);

	size = dfse->size;

	if (*ppos >= size)
		return 0;
	if (*ppos + count > size)
		count = size - *ppos;

	size = (count + 3) & (~3);
	buf = kzalloc(size, GFP_KERNEL);
	if (!buf) {
		pr_err(" %s: kzalloc failed, aborting\n", __func__);
		return -ENOMEM;
	}

	if (copy_from_user(buf, buffer, count))
		return 0;

	for (i = 0; i < size / sizeof(*buf); i++)
		*(u32 *)(dfse->buf + *ppos + i * sizeof(*buf)) = buf[i];

	kfree(buf);
	*ppos += count;

	pr_debug("%s: *ppos: 0x%llx, count: %zu", __func__, *ppos, count);

	return count;
}

static const struct file_operations sst_dfs_fops = {
	.owner = THIS_MODULE,
	.open = sst_dfsentry_open,
	.read = sst_dfsentry_read,
	.write = sst_dfsentry_write,
};

int sst_debugfs_add_mmio_entry(struct sst_dsp *sst, struct sst_pdata *pdata,
			       const char *filename)
{
	struct sst_dfsentry *dfse;

	if (!sst || !pdata || !filename)
		return -EINVAL;

	dfse = kzalloc(sizeof(*dfse), GFP_KERNEL);
	if (!dfse) {
		pr_err("%s: cannot create debugfs entry.\n", __func__);
		return -ENOMEM;
	}

	if (!strcmp(filename, "mem")) {
		dfse->buf = sst->addr.lpe;
		dfse->size = pdata->lpe_size;
		sst->debugfs_bar0 = dfse;
	} else if (!strcmp(filename, "cfg")) {
		dfse->buf = sst->addr.pci_cfg;
		dfse->size = pdata->pcicfg_size;
		sst->debugfs_bar1 = dfse;
	} else {
		pr_err("%s: invalid filename\n", __func__);
		kfree(dfse);
		return -EINVAL;
	}

	dfse->dfsentry = debugfs_create_file(filename, 0644, sst->debugfs_root,
					     dfse, &sst_dfs_fops);
	if (!dfse->dfsentry) {
		pr_err("%s: cannot create debugfs entry.\n", __func__);
		kfree(dfse);
		return -ENODEV;
	}

	dfse->sst = sst;

	return 0;
}

void sst_debugfs_remove_mmio_entry(struct sst_dsp *sst, const char *filename)
{
	struct sst_dfsentry *dfse;

	if (!strcmp(filename, "mem"))
		dfse = sst->debugfs_bar0;
	else if (!strcmp(filename, "cfg"))
		dfse = sst->debugfs_bar1;
	else
		return;

	debugfs_remove(dfse->dfsentry);
	kfree(dfse);
}
