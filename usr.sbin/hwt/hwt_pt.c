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
#include <sys/hwt.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/tree.h>

#include <err.h>
#include <libipt/intel-pt.h>
#include <libxo/xo.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>

#include "amd64/pt/pt.h"
#include "dev/hwt/hwt_event.h"
#include "hwt.h"
#include "hwt_pt.h"
#include "sys/_stdint.h"
#include "sys/systm.h"
#include "sys/types.h"

#define pt_strerror(errcode) pt_errstr(pt_errcode((errcode)))

static int pt_ctx_compare(const void *n1, const void *n2);

/*
 * Decoder state.
 */
struct pt_dec_ctx {
	size_t curoff;
	size_t total;
	void *tracebuf;
	struct pt_packet_decoder *dec;

	int id;
	RB_ENTRY(pt_dec_ctx) entry;
};

static struct pt_dec_ctx *cpus;
static RB_HEAD(threads, pt_dec_ctx) threads;
RB_GENERATE_STATIC(threads, pt_dec_ctx, entry, pt_ctx_compare);

static int kq_fd = -1;

static int
pt_ctx_compare(const void *n1, const void *n2)
{
	const struct pt_dec_ctx *c1 = n1;
	const struct pt_dec_ctx *c2 = n2;

	return (c1->id < c2->id ? -1 : c1->id > c2->id ? 1 : 0);
}

static int
hwt_pt_init(struct trace_context *tc)
{
	struct kevent ev[2];
	int error;

	if (tc->raw) {
		/* No decoder needed, just a file for raw data. */
		tc->raw_f = fopen(tc->filename, "w");
		if (tc->raw_f == NULL) {
			printf("%s: could not open file %s\n", __func__,
			    tc->filename);
			return (ENXIO);
		}
	}

	switch (tc->mode) {
	case HWT_MODE_CPU:
		cpus = calloc(hwt_ncpu(), sizeof(struct pt_dec_ctx));
		if (!cpus) {
			printf("%s: failed to allocate decoders\n", __func__);
			return (-1);
		}
		break;
	case HWT_MODE_THREAD:
		RB_INIT(&threads);
		break;
	default:
		printf("%s: invalid tracing mode %d\n", __func__, tc->mode);
		return (EINVAL);
	}

	tc->kqueue_fd = kqueue();
	if (tc->kqueue_fd == -1)
		err(EXIT_FAILURE, "kqueue() failed");
	kq_fd = tc->kqueue_fd; /* sig handler needs access to kq via global */

	/* Let hwt notify us when the buffer is ready. */
	EV_SET(&ev[0], HWT_KQ_BUFRDY_EV, EVFILT_USER, EV_ADD | EV_CLEAR,
	    NOTE_FFCOPY, 0, NULL);
	/* Let hwt notify us when something gets mapped into the process. */
	EV_SET(&ev[1], HWT_KQ_NEW_RECORD_EV, EVFILT_USER, EV_ADD | EV_CLEAR,
	    NOTE_FFCOPY, 0, NULL);

	error = kevent(tc->kqueue_fd, ev, 2, NULL, 0, NULL);
	if (error == -1)
		err(EXIT_FAILURE, "kevent register");
	if ((ev[0].flags | ev[1].flags) & EV_ERROR)
		// TODO: properly check per-event errors
		errx(EXIT_FAILURE, "Event error: %s", strerror(ev[0].data));

	printf("%s kqueue_fd:%d\n", __func__, tc->kqueue_fd);

	return (0);
}

static int
hwt_pt_mmap(struct trace_context *tc, struct hwt_record_user_entry *rec)
{
	int cpu_id, tid, fd;
	struct pt_dec_ctx *dctx;
	struct pt_config config;
	char filename[32];

	switch (tc->mode) {
	case HWT_MODE_CPU:
		CPU_FOREACH_ISSET (cpu_id, &tc->cpu_map) {
			dctx = &cpus[cpu_id];

			sprintf(filename, "/dev/hwt_%d_%d", tc->ident, cpu_id);
			fd = open(filename, O_RDONLY);
			if (fd < 0) {
				printf("Can't open %s\n", filename);
				return (-1);
			}
			/* thr_fd is used to issue ioctls which control all
			 * cores use fd to the first cpu for this (thread is
			 * always 0) */
			if (tc->thr_fd == 0) {
				tc->thr_fd = fd;
			}
			dctx->tracebuf = mmap(NULL, tc->bufsize, PROT_READ,
			    MAP_SHARED, fd, 0);
			if (dctx->tracebuf == MAP_FAILED) {
				printf(
				    "%s: failed to map tracing buffer for cpu %d: %s\n",
				    __func__, cpu_id, strerror(errno));
				free(dctx);
				return (-1);
			}
			dctx->id = cpu_id;
		}
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
		dctx = calloc(1, sizeof(*dctx));
		if (dctx == NULL)
			return (ENOMEM);
		// TODO: map thread trace buffer
		sprintf(filename, "/dev/hwt_%d_%d", tc->ident, tid);
		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			printf("Can't open %s\n", filename);
			free(dctx);
			return (-1);
		}
		if (tc->thr_fd == 0) {
			tc->thr_fd = fd;
		}
		dctx->tracebuf = mmap(NULL, tc->bufsize, PROT_READ, MAP_SHARED,
		    fd, 0);
		if (dctx->tracebuf == MAP_FAILED) {
			printf(
			    "%s: failed to map tracing buffer for thread %d: %s\n",
			    __func__, tid, strerror(errno));
			free(dctx);
			return (-1);
		}
		dctx->id = tid;
		RB_INSERT(threads, &threads, dctx);
		break;
	default:
		return (EINVAL);
	}

	if (!tc->raw) {
		memset(&config, 0, sizeof(config));
		config.size = sizeof(config);
		config.begin = dctx->tracebuf;
		config.end = (uint8_t *)dctx->tracebuf + tc->bufsize;

		dctx->dec = pt_pkt_alloc_decoder(&config);
		if (dctx->dec == NULL) {
			printf("%s: failed to allocate PT decoder for thread\n",
			    __func__);
			free(dctx);
			return (ENOMEM);
		}
	}

	return (0);
}

static int
hwt_pt_set_config(struct trace_context *tc)
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

static void
hwt_pt_print_tnt(const struct pt_packet_tnt *packet)
{
	uint64_t tnt;
	uint8_t bits;

	bits = packet->bit_size;
	tnt = packet->payload;

	while (--bits)
		putc(tnt & (1ull << (bits - 1)) ? '!' : '.', stdout);
}

static void
hwt_pt_print_mode(const struct pt_packet_mode *pkt)
{
	enum pt_exec_mode mode;

	switch (pkt->leaf) {
	case pt_mol_exec: {
		printf(".exec: ");
		mode = pt_get_exec_mode(&pkt->bits.exec);
		switch (mode) {
		case ptem_64bit:
			printf("64-bit");
			break;
		case ptem_32bit:
			printf("32-bit");
			break;
		case ptem_16bit:
			printf("16-bit");
			break;
		default:
			printf("unknown");
			break;
		}
		break;
	}
	case pt_mol_tsx:
		printf(".tsx");
		break;
	}
}

static int
hwt_pt_print_packet(const struct pt_packet *pkt)
{

	switch (pkt->type) {
	case ppt_unknown:
		printf("<unknown>");
		break;
	case ppt_invalid:
		printf("<invalid>");
		break;
	case ppt_tnt_8:
		printf("tnt.8\n");
		hwt_pt_print_tnt(&pkt->payload.tnt);
		break;
	case ppt_tnt_64:
		printf("tnt.64\n");
		hwt_pt_print_tnt(&pkt->payload.tnt);
		break;
	case ppt_mode:
		printf("mode");
		hwt_pt_print_mode(&pkt->payload.mode);
		break;
	case ppt_pip:
		printf("pip: cr3 %p", (void *)pkt->payload.pip.cr3);
		break;
	case ppt_vmcs:
		printf("vmcs: %p", (void *)pkt->payload.vmcs.base);
		break;
	case ppt_cbr:
		printf("cbr: ratio %u", pkt->payload.cbr.ratio);
		break;
	case ppt_tip_pge:
		printf("pge: TRACE START @%p", (void *)pkt->payload.ip.ip);
		break;
	case ppt_tip_pgd:
		printf("pgd: TRACE STOP @%p", (void *)pkt->payload.ip.ip);
		break;
	case ppt_fup:
		printf("fup: @%p", (void *)pkt->payload.ip.ip);
		break;
	case ppt_pad:
	case ppt_psb:
	case ppt_psbend:
		/* Ignore */
		return (0);
	default:
		printf("%s: unknown packet type encountered: %d\n", __func__,
		    pkt->type);
		return (-1);
	}
	printf("\n");

	return (0);
}

static int
hwt_pt_decode_chunk(struct pt_packet_decoder *dec, uint64_t start, size_t len,
    uint64_t *processed)
{
	int error = 0;
	uint64_t prevoffs, offs;
	int ret;
	struct pt_packet packet;

	printf("%s: start %zu, len %zu\n", __func__, start, len);

	offs = prevoffs = start;
	/* Set decoder to current offset. */
	pt_pkt_sync_set(dec, start);

	do {
		ret = pt_pkt_next(dec, &packet, sizeof(packet));
		if (ret < 0) {
			if (ret == -pte_eos) {
				/* Restore previous offset */
				pt_pkt_sync_set(dec, prevoffs);
				offs = prevoffs;
			} else {
				error = ret;
				printf("%s: error decoding next packet: %s\n",
				    __func__, pt_strerror(error));
			}
			break;
		}
		error = hwt_pt_print_packet(&packet);
		if (error < 0) {
			printf("%s: error while processing packet: %s\n",
			    __func__, pt_strerror(error));
			break;
		}

		prevoffs = offs;
		offs += ret;

		if (offs > (start + len))
			break;
	} while (1);
	*processed = offs - start;

	return (error);
}

/*
 * Dumps raw packet bytes into tc->raw_f.
 */
static int
hwt_pt_dump_chunk(struct pt_dec_ctx *dctx, FILE *raw_f, uint64_t offs,
    size_t len, uint64_t *processed)
{
	void *base;

	base = (void *)((uintptr_t)dctx->tracebuf + (uintptr_t)offs);
	fwrite(base, len, 1, raw_f);
	fflush(raw_f);

	*processed = len;

	return (0);
}

static int
pt_process_chunk(struct trace_context *tc, struct pt_dec_ctx *dctx,
    uint64_t offs, size_t len, uint64_t *processed)
{
	if (tc->raw) {
		return hwt_pt_dump_chunk(dctx, tc->raw_f, offs, len, processed);
	} else {
		return hwt_pt_decode_chunk(dctx->dec, offs, len, processed);
	}
}

static struct pt_dec_ctx *
pt_get_decoder_ctx(struct trace_context *tc, int ctxid)
{
	switch (tc->mode) {
	case HWT_MODE_CPU:
		assert(ctxid < hwt_ncpu());
		return (&cpus[ctxid]);
	case HWT_MODE_THREAD: {
		struct pt_dec_ctx srch;
		srch.id = ctxid;
		return RB_FIND(threads, &threads, &srch);
	}
	default:
		break;
	}

	return (NULL);
}

static int
pt_process_data(struct trace_context *tc, struct kevent *tevent)
{
	int error;
	size_t newoff, curoff, len;
	uint64_t processed;
	int id;
	struct pt_dec_ctx *dctx;

	id = tevent->fflags & HWT_KQ_BUFRDY_ID_MASK;
	newoff = tevent->data;
	printf("%s: new offset %zu for ctx id %d\n", __func__, newoff, id);

	dctx = pt_get_decoder_ctx(tc, id);
	if (dctx == NULL) {
		printf("%s: unable to find decorder context for ID %d\n",
		    __func__, id);
		err(EXIT_FAILURE, "pt_get_decoder_ctx");
	}

	curoff = dctx->curoff;
	if (newoff == curoff) {
		if (tc->terminate)
			return (-1);
	} else if (newoff > curoff) {
		/* New entries in the trace buffer. */
		len = newoff - curoff;
		error = pt_process_chunk(tc, dctx, curoff, len, &processed);
		if (error != 0) {
			return (error);
		}
		dctx->total += processed;
		dctx->curoff += processed;

	} else if (newoff < curoff) {
		/* New entries in the trace buffer. Buffer wrapped. */
		len = tc->bufsize - curoff;
		error = pt_process_chunk(tc, dctx, curoff, len, &processed);
		if (error != 0) {
			return (error);
		}

		dctx->curoff += processed;
		dctx->total += processed;

		curoff = 0;
		len = newoff;
		error = pt_process_chunk(tc, dctx, curoff, len, &processed);
		if (error != 0) {
			return (error);
		}

		dctx->curoff += processed;
		dctx->total += processed;
	}

	return (0);
}

static int
hwt_pt_process(struct trace_context *tc)
{
	int error, nrec, ret;
	struct kevent tevent;
	struct timespec null_timeout = { 0, 5 };

	xo_open_container("trace");
	xo_open_list("entries");

	printf("Decoder started. Press ctrl+c to stop.\n");

	while (1) {
		printf("%s: waiting for new offset\n", __func__);
		ret = kevent(tc->kqueue_fd, NULL, 0, &tevent, 1, NULL);
		if (ret == -1 && errno != EINTR) {
			err(EXIT_FAILURE, "kevent wait");
		}
		// TODO: iterate over all active CTXs and fetch any remaining
		// data
		if (tc->terminate != 0) {
			printf(
			    "%s: tracing terminated - fetching remaining data\n",
			    __func__);
			/* Check if we have any events left over. */
			if (ret > 0) {
				pt_process_data(tc, &tevent);
			}
			while (1) {
				ret = kevent(tc->kqueue_fd, NULL, 0, &tevent, 1,
				    &null_timeout);
				if (ret <= 0) {
					break;
				}
				/* Ignore non-buffer events. */
				if (tevent.ident != HWT_KQ_BUFRDY_EV)
					continue;
				pt_process_data(tc, &tevent);
			}

			return (0);
		}

		printf("EVENT ID: %lu\n", tevent.ident);
		if (tevent.ident == HWT_KQ_BUFRDY_EV) {
			pt_process_data(tc, &tevent);
		} else if (tevent.ident == HWT_KQ_NEW_RECORD_EV) {
			printf("%s: fetching new records\n", __func__);
			error = hwt_record_fetch(tc, &nrec);
			if (error != 0) {
				printf("%s: hwt_get_records error %d\n",
				    __func__, error);
				err(EXIT_FAILURE, "hwt_get_records");
			}
		} else {
			printf("%s: unknown event identifier %lu\n", __func__,
			    tevent.ident);
			err(EXIT_FAILURE, "kevent ident");
		}
	}

	xo_close_list("file");
	xo_close_container("wc");
	if (xo_finish() < 0)
		xo_err(EXIT_FAILURE, "stdout");

	return (0);
}

struct trace_dev_methods pt_methods = {
	.init = hwt_pt_init,
	.mmap = hwt_pt_mmap,
	.process = hwt_pt_process,
	.set_config = hwt_pt_set_config,
};
