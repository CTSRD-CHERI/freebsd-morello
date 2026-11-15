/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023-2025 Ruslan Bukin <br@bsdpad.com>
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/cpuset.h>
#include <sys/hwt.h>
#include <sys/hwt_record.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <err.h>
#include <string.h>
#include <assert.h>

#include "hwt.h"
#include "hwt_elf.h"
#include "hwt_record.h"

#include "libpmcstat_stubs.h"
#include <libpmcstat.h>

#define	HWT_RECORD_DEBUG
#undef	HWT_RECORD_DEBUG

#ifdef	HWT_RECORD_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

int
hwt_record_fetch(struct trace_context *tc, int *nrecords, int wait)
{
	struct hwt_record_user_entry *entry;
	struct hwt_record_get record_get;
	struct hwt_wakeup w;
	int nentries;
	int error;
	int j;

	nentries = 256;
	tc->records = malloc(sizeof(struct hwt_record_user_entry) * nentries);

	record_get.records = tc->records;
	record_get.nentries = &nentries;
	record_get.wait = wait;

	error = ioctl(tc->thr_fd, HWT_IOC_RECORD_GET, &record_get);
	if (error != 0) {
		printf("RECORD_GET error %d entires %d\n",
		    error, nentries);
		return (error);
	}

	dprintf("%s: error %d: nent %d\n", __func__, error, nentries);

	*nrecords = 0;
	for (j = 0; j < nentries; j++) {
		entry = &tc->records[j];

		switch (entry->record_type) {
		case HWT_RECORD_MUNMAP:
		case HWT_RECORD_MMAP:
			printf("%s: address space record\n", __func__);
			/*
			 * The traced process' address space has changed.
			 * Allow the backend-specific decoders to update their
			 * internal maps by invoking the 'as_event_cb' callback.
			 */
			if (tc->backend->methods->as_event_cb != NULL &&
			    (error = tc->backend->methods->as_event_cb(tc, entry))) {
				ioctl(tc->thr_fd, HWT_IOC_WAKEUP, &w);
				return (error);
			}
			hwt_elf_link_pmcstat_img(tc, entry);

			if (entry->record_type != HWT_RECORD_KERNEL)
				hwt_mmap_received(tc, entry);
			break;
		case HWT_RECORD_KERNEL:
		case HWT_RECORD_EXECUTABLE:
			printf("%s: exec record\n", __func__);
			error = hwt_elf_process_exec(tc, entry);
			if (error) {
				warnx("%s: failed to process executable '%s'",
				    __func__, entry->fullpath);
				return (error);
			}
			break;
		case HWT_RECORD_THREAD_CREATE:
			/* Let the backend register the newly created thread. */
			if ((error = tc->backend->methods->mmap(tc, entry)) !=
			    0)
				return (error);
			break;
		case HWT_RECORD_THREAD_SET_NAME:
			break;
		case HWT_RECORD_BUFFER:
			printf("%s: buffer record\n", __func__);
			/* Invoke backend process method. */
			assert(tc->backend->methods->process_buffer != NULL);
			if ((error = tc->backend->methods->process_buffer(tc,
				entry->buf_id, entry->curpage,
				entry->offset)) != 0)
				return (error);
		default:
			break;
		}
	}
	free(tc->records);
	tc->records = NULL;

	*nrecords = nentries;

	return (error);
}
