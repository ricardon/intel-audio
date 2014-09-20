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

#ifndef __SOUND_SOC_SST_DEBUGFS_H
#define __SOUND_SOC_SST_DEBUGFS_H

int sst_debugfs_add_mmio_entry(struct sst_dsp *sst, struct sst_pdata *pdata,
			       const char *filename);
void sst_debugfs_remove_mmio_entry(struct sst_dsp *sst, const char *filename);

#endif
