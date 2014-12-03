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
#include <linux/device.h>
#include <linux/pm_runtime.h>

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
	int size;
	u32 *buf;
	loff_t pos = *ppos;
	size_t ret;

	dev_dbg(dfse->sst->dev, "pbuf: %p, *ppos: 0x%llx\n", buffer, *ppos);

	size = dfse->size;

	if (pos < 0)
		return -EINVAL;
	if (pos >= size || !count)
		return 0;
	if (count > size - pos)
		count = size - pos;

	size = (count + 3) & (~3);
	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	pm_runtime_get(dfse->sst->dev);
	sst_memcpy_fromio_32(dfse->sst, buf, dfse->buf + pos, size);
	pm_runtime_put(dfse->sst->dev);

	ret = copy_to_user(buffer, buf, count);
	kfree(buf);

	if (ret == count)
		return -EFAULT;
	count -= ret;
	*ppos = pos + count;

	dev_dbg(dfse->sst->dev, "*ppos: 0x%llx, count: %zu\n", *ppos, count);

	return count;
}

static ssize_t sst_dfsentry_write(struct file *file, const char __user *buffer,
				  size_t count, loff_t *ppos)
{
	struct sst_dfsentry *dfse = file->private_data;
	int size;
	u32 *buf;
	loff_t pos = *ppos;
	size_t res;

	dev_dbg(dfse->sst->dev, "pbuf: %p, *ppos: 0x%llx\n", buffer, *ppos);

	size = dfse->size;

	if (pos < 0)
		return -EINVAL;
	if (pos >= size || !count)
		return 0;
	if (count > size - pos)
		count = size - pos;

	size = (count + 3) & (~3);
	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	res = copy_from_user(buf, buffer, count);
	if (res == count) {
		kfree(buf);
		return -EFAULT;
	}

	pm_runtime_get(dfse->sst->dev);
	sst_memcpy_toio_32(dfse->sst, buf, dfse->buf + pos, size);
	pm_runtime_put(dfse->sst->dev);

	kfree(buf);
	count -= res;
	*ppos = pos + count;

	dev_dbg(dfse->sst->dev, "*ppos: 0x%llx, count: %zu\n", *ppos, count);

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

	if (!dfse)
		return -ENOMEM;

	if (!strcmp(filename, "mem")) {
		dfse->buf = sst->addr.lpe;
		dfse->size = pdata->lpe_size;
		sst->debugfs_bar0 = dfse;
	} else if (!strcmp(filename, "cfg")) {
		dfse->buf = sst->addr.pci_cfg;
		dfse->size = pdata->pcicfg_size;
		sst->debugfs_bar1 = dfse;
	} else {
		dev_err(sst->dev, "invalid filename\n");
		kfree(dfse);
		return -EINVAL;
	}

	dfse->dfsentry = debugfs_create_file(filename, 0644, sst->debugfs_root,
					     dfse, &sst_dfs_fops);
	if (!dfse->dfsentry) {
		dev_err(sst->dev, "cannot create debugfs entry.\n");
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
