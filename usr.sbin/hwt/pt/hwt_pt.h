/*-
 * Copyright (c) 2023 Bojan Novković <bnovkov@freebsd.org>
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

#ifndef _HWT_PT_H_
#define _HWT_PT_H_

#include <stdbool.h>

#include <amd64/pt/pt.h>

#define pt_strerror(errcode) pt_errstr(pt_errcode((errcode)))

/*
 * Trace decoder state.
 */
struct pt_dec_ctx {
	size_t curoff;
	uint64_t ts;
	uint64_t curip;
	void *tracebuf;
	struct pt_insn_decoder *dec;
	int dev_fd;
	bool enabled;
	bool needs_sync;
	bool at_eos;
	uint64_t resume_off;
	int id;
	RB_ENTRY(pt_dec_ctx) entry;

	/* Variables for various decode ops. */
	xo_handle_t *xop;
	FILE *out;
};

struct pt_decode_ops {
	int (*decode_chunk)(struct trace_context *, struct pt_dec_ctx *,
	    uint64_t, size_t, uint64_t *);
	int (*init)(struct trace_context *, struct pt_dec_ctx *);
};
extern struct pt_decode_ops pt_decode_generic_ops;
extern struct pt_decode_ops pt_dump_ops;

extern struct backend_methods pt_methods;
#endif /* !_HWT_PT_H_ */
