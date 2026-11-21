/*-
 * Copyright (c) 2025 Bojan Novković  <bnovkov@freebsd.org>
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

#include <sys/hwt.h>
#include <sys/hwt_record.h>
#include <sys/param.h>

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <libxo/xo.h>

#include "libpmcstat_stubs.h"
#include <libpmcstat.h>

#include "hwt.h"
#include "hwt_fmt.h"

static struct column {
	const char *name;
	enum hwt_fmt_column val;
} columns[] = {
	{ "offset", HWT_FMT_OFFSET },
	{ "id", HWT_FMT_ID },
	{ "image", HWT_FMT_IMAGE_NAME },
	{ "symbol", HWT_FMT_SYM_NAME },
	{ "pc", HWT_FMT_PC },
	{ "event", HWT_FMT_EV_TYPE },
	{ "payload", HWT_FMT_EV_PAYLOAD },
	{ "disas", HWT_FMT_DISAS },
};

void
hwt_fmt_print_generic(struct trace_context *tc, xo_handle_t *xop, int id,
    uint64_t pc, uint64_t offs)
{
	uint64_t newpc;
	unsigned long offset;
	struct pmcstat_symbol *sym;
	struct pmcstat_image *image;
	const char *piname;
	const char *psname;

	if (HWT_FMT_SHOULD_PRINT(tc->fmt, OFFSET))
		xo_emit_h(xop, "{:trace_offset/%#lx}\t", offs);

	if (HWT_FMT_SHOULD_PRINT(tc->fmt, ID))
		xo_emit_h(xop, "{:type/%s} {:id/%d}\t",
		    tc->mode == HWT_MODE_CPU ? "CPU" : "thr", id);

	if (HWT_FMT_SHOULD_PRINT_COLS(tc->fmt,
	    (HWT_FMT_SYM_NAME | HWT_FMT_IMAGE_NAME))){
		sym = hwt_sym_lookup(tc, pc, &image, &newpc);
		if (HWT_FMT_SHOULD_PRINT(tc->fmt, IMAGE_NAME)) {
			if (!image)
				piname = "?";
			else
				piname = pmcstat_string_unintern(image->pi_name);
			xo_emit_h(xop, "{:image_name/%s}{:image_offset/+%#lx}\t",
			    piname, newpc);
		}

		if (HWT_FMT_SHOULD_PRINT(tc->fmt, SYM_NAME))  {
			if (!sym) {
				psname = "?";
				offset = 0;
			} else {
				psname = pmcstat_string_unintern(sym->ps_name);
				offset = newpc - (sym->ps_start +
				    (image != NULL ? image->pi_vaddr : 0));
			}
			xo_emit_h(xop, "{:sym_name/%s}{:sym_offset/+%#lx}\t",
			    psname, offset);
		}
	}

	if (HWT_FMT_SHOULD_PRINT(tc->fmt, PC))
		xo_emit_h(xop, "{:PC/%#lx}\t", pc);
}

enum hwt_fmt_column
hwt_fmt_parse_cols(const char* args)
{
	size_t i;
	char *orig, *tok;
	enum hwt_fmt_column ret;

	ret = 0;
	orig = strdup(args);
	if (orig == NULL)
		err(1, "strdup");
	while ((tok = strsep(&orig, ",")) != NULL) {
		for (i = 0; i < nitems(columns); i++) {
			if (strcmp(columns[i].name, tok) == 0) {
				ret |= columns[i].val;
				break;
			}
		}
		if (i == nitems(columns)) {
			fprintf(stderr, "Unknown output column name '%s'", tok);
			exit(1);
		}
	}

	free(orig);
	return (ret);
}
