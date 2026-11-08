/*-
 * Copyright (c) 2023 Bojan Novković  <bnovkov@freebsd.org>
 * All rights reserved.
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
#include <sys/cpuset.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/tree.h>
#include <sys/hwt.h>
#include <sys/hwt_record.h>

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include <libxo/xo.h>
#include <amd64/pt/pt.h>
#include <libipt/intel-pt.h>

#include "hwt.h"
#include "hwt_elf.h"
#include "hwt_pt.h"

typedef void (*pt_ctx_iter_cb)(struct trace_context *, struct pt_dec_ctx *,
    void *);
static int pt_ctx_compare(const void *n1, const void *n2);

/* Active decoder ops. */
static struct pt_decode_ops pt_decode_ops;

/*
 * Active decoder states.
 */
static struct pt_image_section_cache *pt_iscache;
static struct pt_dec_ctx *cpus;
static RB_HEAD(threads, pt_dec_ctx) threads;
RB_GENERATE_STATIC(threads, pt_dec_ctx, entry, pt_ctx_compare);

static int
pt_ctx_compare(const void *n1, const void *n2)
{
	const struct pt_dec_ctx *c1 = n1;
	const struct pt_dec_ctx *c2 = n2;

	return (c1->id < c2->id ? -1 : c1->id > c2->id ? 1 : 0);
}

/*
 * Iterate over all active decoders and invoked provided callback.
 */
static void
pt_foreach_ctx(struct trace_context *tc, pt_ctx_iter_cb callback, void *arg)
{
	int cpu_id;
	struct pt_dec_ctx *dctx;

	switch (tc->mode) {
	case HWT_MODE_CPU:
		CPU_FOREACH_ISSET(cpu_id, &tc->cpu_map) {
			callback(tc, &cpus[cpu_id], arg);
		}
		break;
	case HWT_MODE_THREAD:
		RB_FOREACH(dctx, threads, &threads) {
			callback(tc, dctx, arg);
		}
		break;
	default:
		errx(EXIT_FAILURE, "%s: unknown mode %d\n", __func__, tc->mode);
		break;
	}
}

/*
 * Initialize a trace decoder.
 * Invoked as a callback from 'pt_foreach_ctx'.
 */
static void
pt_cpu_ctx_init_cb(struct trace_context *tc, struct pt_dec_ctx *dctx,
    void *arg __unused)
{
	int cpu_id, fd;
	char filename[32];
	struct pt_config config;

	cpu_id = dctx - cpus;
	sprintf(filename, "/dev/hwt_%d_%d", tc->ident, cpu_id);
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		errx(EXIT_FAILURE, "Can't open %s\n", filename);
	}

	/*
	 * thr_fd is used to issue ioctls which control all
	 * cores use fd to the first cpu for this (thread is
	 * always 0).
	 */
	if (tc->thr_fd == 0) {
		tc->thr_fd = fd;
	}
	dctx->tracebuf = mmap(NULL, tc->bufsize, PROT_READ, MAP_SHARED, fd, 0);
	if (dctx->tracebuf == MAP_FAILED) {
		errx(EXIT_FAILURE,
		    "%s: failed to map tracing buffer for cpu %d: %s\n",
		    __func__, cpu_id, strerror(errno));
	}
	dctx->id = cpu_id;
	if (pt_decode_ops.init(tc, dctx) != 0)
		errx(EXIT_FAILURE,
		    "%s: failed to initialize decoder\n",
		    __func__);

	if (!tc->raw) {
		memset(&config, 0, sizeof(config));
		config.size = sizeof(config);
		config.begin = dctx->tracebuf;
		config.end = (uint8_t *)dctx->tracebuf + tc->bufsize;

		dctx->dec = pt_insn_alloc_decoder(&config);
		if (dctx->dec == NULL) {
			printf("%s: failed to allocate PT decoder for CPU %d\n",
			    __func__, cpu_id);
			free(dctx);
			return;
		}
	}
}

/*
 * Add a new ELF section to the trace decoder.
 * Invoked as a callback from 'pt_foreach_ctx'.
 */
static void
pt_update_image_cb(struct trace_context *tc __unused, struct pt_dec_ctx *dctx,
    void *arg)
{
	int isid;
	int error;
	struct pt_image *image;

	isid = *(int *)arg;
	image = pt_insn_get_image(dctx->dec);
	error = pt_image_add_cached(image, pt_iscache, isid, NULL);
	if (error)
		errx(EXIT_FAILURE,
		    "%s: failed to add cached section to decoder image: %s",
		    __func__, pt_strerror(error));
}

/*
 * Add all ELF sections to the trace decoder.
 * Invoked as a callback from 'pt_foreach_ctx'.
 */
static int
pt_image_load_cb(struct trace_context *tc, struct hwt_exec_img *img)
{
	int isid;

	if (tc->raw)
		return (0);
	isid = pt_iscache_add_file(pt_iscache, img->path, img->offs, img->size,
	    img->addr);
	if (isid < 0) {
		printf("%s: error adding file '%s' to the section cache: %s\n",
		    __func__, img->path, pt_strerror(isid));
		return (-1);
	}
	pt_foreach_ctx(tc, pt_update_image_cb, &isid);

	return (0);
}

static int
pt_init(struct trace_context *tc)
{

	/* Buffer size must be power of two. */
	assert((tc->bufsize & (tc->bufsize - 1)) == 0);

	if (tc->raw)
		pt_decode_ops = pt_dump_ops;
	else
		pt_decode_ops = pt_decode_generic_ops;

	pt_iscache = pt_iscache_alloc(tc->image_name);
	if (pt_iscache == NULL)
		errx(EXIT_FAILURE, "%s: failed to allocate section cache",
		    __func__);

	switch (tc->mode) {
	case HWT_MODE_CPU:
		cpus = calloc(hwt_ncpu(), sizeof(struct pt_dec_ctx));
		if (!cpus) {
			printf("%s: failed to allocate decoders\n", __func__);
			return (ENOMEM);
		}
		break;
	case HWT_MODE_THREAD:
		RB_INIT(&threads);
		break;
	default:
		printf("%s: invalid tracing mode %d\n", __func__, tc->mode);
		return (EINVAL);
	}

	return (0);
}

/*
 * Map and initialize the tracing buffer.
 * Called whenever a new traced thread gets created or
 * when HWT_MODE_CPU tracing is started.
 */
static int
pt_mmap(struct trace_context *tc, struct hwt_record_user_entry *rec)
{
	int tid, fd;
	char filename[32];
	struct pt_config config;
	struct pt_image *srcimg, *dstimg;
	struct pt_dec_ctx *dctx, *srcctx;

	switch (tc->mode) {
	case HWT_MODE_CPU:
		pt_foreach_ctx(tc, pt_cpu_ctx_init_cb, NULL);
		break;
	case HWT_MODE_THREAD:
		if (rec == NULL) {
			/* Have we already mapped the first thread? */
			if (tc->thr_fd != 0)
				return (EINVAL);
			tid = 0;
		} else {
			tid = rec->thread_id;
		}
		sprintf(filename, "/dev/hwt_%d_%d", tc->ident, tid);
		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			printf("Can't open %s\n", filename);
			return (-1);
		}
		if (tc->thr_fd == 0) {
			tc->thr_fd = fd;
		}
		dctx = calloc(1, sizeof(*dctx));
		if (dctx == NULL)
			return (ENOMEM);
		dctx->tracebuf = mmap(NULL, tc->bufsize, PROT_READ, MAP_SHARED,
		    fd, 0);
		if (dctx->tracebuf == MAP_FAILED) {
			printf(
			    "%s: failed to map tracing buffer for thread %d: %s\n",
			    __func__, tid, strerror(errno));
			free(dctx);
			return (ENOMEM);
		}
		dctx->id = tid;
		dctx->dev_fd = fd;
		if (pt_decode_ops.init(tc, dctx) != 0)
			return (-1);
		if (tc->raw) {
			RB_INSERT(threads, &threads, dctx);
			break;
		}

		/*
		 * Grab another context, if any, and copy its decoder
		 * image.
		 */
		if (!RB_EMPTY(&threads)) {
			srcctx = RB_ROOT(&threads);
			srcimg = pt_insn_get_image(srcctx->dec);
			dstimg = pt_insn_get_image(dctx->dec);
			pt_image_copy(dstimg, srcimg);
		}
		memset(&config, 0, sizeof(config));
		config.size = sizeof(config);
		config.begin = dctx->tracebuf;
		config.end = (uint8_t *)dctx->tracebuf + tc->bufsize;

		dctx->dec = pt_insn_alloc_decoder(&config);
		if (dctx->dec == NULL) {
			printf(
			    "%s: failed to allocate PT decoder for thread\n",
			    __func__);
			free(dctx);
			return (ENOMEM);
		}
		RB_INSERT(threads, &threads, dctx);
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

static int
pt_set_config(struct trace_context *tc)
{
	struct hwt_set_config sconf;
	struct pt_cpu_config *config;
	int i, error;
	uint64_t rtit_ctl = 0;

	config = calloc(1, sizeof(struct pt_cpu_config));
	/* Fill config */
	if (tc->mode == HWT_MODE_THREAD)
		rtit_ctl |= RTIT_CTL_USER;
	else
		rtit_ctl |= RTIT_CTL_OS;

	if (tc->nranges) {
		/* IP range filtering. */
		config->nranges = tc->nranges;
		for (i = 0; i < tc->nranges; i++) {
			config->ip_ranges[i].start = tc->addr_ranges[i * 2];
			config->ip_ranges[i].end = tc->addr_ranges[i * 2 + 1];
		}
	}
	rtit_ctl |= RTIT_CTL_BRANCHEN;

	config->rtit_ctl = rtit_ctl;
	tc->config = config;

	sconf.config = config;
	sconf.config_size = sizeof(struct pt_config);
	sconf.config_version = 1;
	sconf.pause_on_mmap = tc->suspend_on_mmap ? 1 : 0;

	error = ioctl(tc->thr_fd, HWT_IOC_SET_CONFIG, &sconf);

	return (error);
}

static struct pt_dec_ctx *
pt_get_decoder_ctx(struct trace_context *tc, int id)
{
	switch (tc->mode) {
	case HWT_MODE_CPU:
		assert(id < hwt_ncpu());
		return (&cpus[id]);
	case HWT_MODE_THREAD: {
		struct pt_dec_ctx srch;
		srch.id = id;
		return (RB_FIND(threads, &threads, &srch));
	}
	default:
		break;
	}

	return (NULL);
}

/*
 * Decode part of the tracing buffer.
 */
static int
pt_process_buffer(struct trace_context *tc, int id, int curpage,
    vm_offset_t offset)
{
	int error;
	uint64_t ts;
	uint64_t processed;
	struct pt_dec_ctx *dctx;
	size_t newoff, curoff, len;

	dctx = pt_get_decoder_ctx(tc, id);
	if (dctx == NULL) {
		printf("%s: unable to find decoder context for ID %d\n",
		    __func__, id);
		return (-1);
	}

	/*
	 * Check if the buffer wrapped since
	 * the last time we processed it
	 * and try to resync.
	 */
	ts = (curpage * PAGE_SIZE) + offset;
	if ((ts - dctx->ts) > tc->bufsize) {
		printf(
		    "%s: WARNING: buffer wrapped - re-syncing to last known offset\n",
		    __func__);
		dctx->curoff = (ts - dctx->ts) & (tc->bufsize - 1);
		dctx->ts = ts;
		return (0);
	}
	len = ts - dctx->ts;
	curoff = dctx->curoff;
	newoff = (curoff + len) % tc->bufsize;

	if (newoff > curoff) {
		/* New entries in the trace buffer. */
		len = newoff - curoff;
		error = pt_decode_ops.decode_chunk(tc, dctx, curoff, len,
		    &processed);
		if (error != 0)
			return (error);

		dctx->curoff += processed;
		dctx->ts += processed;
	} else if (newoff < curoff) {
		/* New entries in the trace buffer. Buffer wrapped. */
		len = tc->bufsize - curoff;
		error = pt_decode_ops.decode_chunk(tc, dctx, curoff, len,
		    &processed);
		if (error != 0)
			return (error);

		dctx->curoff += processed;
		dctx->ts += processed;

		curoff = 0;
		len = newoff;
		error = pt_decode_ops.decode_chunk(tc, dctx, curoff, len,
		    &processed);
		if (error != 0)
			return (error);

		dctx->curoff = processed;
		dctx->ts += processed;
	}

	return (0);
}

static void
pt_ctx_shutdown_cb(struct trace_context *tc, struct pt_dec_ctx *dctx,
    void *arg __unused)
{
	int error;
	struct hwt_bufptr_get bget;
	vm_offset_t offset;
	int curpage;

	bzero(&bget, sizeof(bget));
	bget.ident = &curpage;
	bget.offset = &offset;
	error = ioctl(dctx->dev_fd, HWT_IOC_BUFPTR_GET, &bget);
	if (error)
		return;
	error = pt_process_buffer(tc, dctx->id, curpage, offset);
	if (error)
		errx(EXIT_FAILURE, "pt_process_data");
}

static void
pt_shutdown(struct trace_context *tc)
{
	pt_foreach_ctx(tc, pt_ctx_shutdown_cb, NULL);
}

struct backend_methods pt_methods = {
	.init = pt_init,
	.mmap = pt_mmap,
	.shutdown = pt_shutdown,
	.process_buffer = pt_process_buffer,
	.set_config = pt_set_config,
	.image_load_cb = pt_image_load_cb
};
