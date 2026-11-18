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

#include <sys/errno.h>
#include <sys/hwt.h>
#include <sys/hwt_record.h>
#include <sys/param.h>
#include <sys/tree.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libxo/xo.h>
#include <amd64/pt/pt.h>
#include <libipt/intel-pt.h>

#include "hwt.h"
#include "hwt_pt.h"
#include "hwt_fmt.h"
#include "hwt_pt_fmt.h"

#define PSB_PACKET_SIZE 16

/*
 * A helper method that scans for a PSB packet starting from 'offs' until the buffer's end.
 * This allows us to avoid excessive buffer re-scans due to the fact that 'pt_insn_sync_forward'
 * always starts scanning for a PSB packet from the beginning of a buffer. It is also
 * a massive hack since it messes with the decoder's 'config->begin' field.
 */
static int
pt_sync_forward_from_offs(struct pt_dec_ctx *dctx, struct pt_insn_decoder *dec, struct pt_config *cfg,
    uint64_t offs)
{
    int ret;
    uint8_t *old_begin;

    old_begin = cfg->begin;

    cfg->begin = (uint8_t *)dctx->tracebuf + offs;
    ret = pt_insn_sync_forward(dec);
    cfg->begin = old_begin;

    return (ret);
}

static int
pt_decode_chunk_insn(struct trace_context *tc, struct pt_dec_ctx *dctx,
                     uint64_t start, size_t len, uint64_t *processed)
{
    int ret;
    int error;
    uint64_t offs;
    struct pt_insn insn;
    struct pt_event event;
    struct pt_config *cfg;
    struct pt_insn_decoder *dec;

    printf("%s: id: %d, start: 0x%lx, len: 0x%lx\n", __func__, dctx->id, start, len);

    if (len == 0) {
        *processed = 0;
        return (0);
    }

    error = 0;
    ret = 0;
    offs = start;
    dec = dctx->dec;
    cfg = __DECONST(struct pt_config *, pt_insn_get_config(dec));
    cfg->end = (uint8_t *)dctx->tracebuf + (start + len);

    if (dctx->at_eos) {
        dctx->at_eos = false;
        ret = pt_sync_forward_from_offs(dctx, dec, cfg, dctx->resume_off);
        if (ret < 0) {
            /*
             * No PSB in the current buffer. Don't report an error
             * sync PSB frequency can be configured by the user.
             */
            dctx->enabled = false;
            *processed = 0;
            return (0);
        }
        dctx->enabled = !(ret & pts_ip_suppressed);
    } else if (pt_insn_get_sync_offset(dec, &offs) < 0 ||
               dctx->needs_sync) {
        dctx->needs_sync = false;
        pt_insn_get_offset(dec, &offs);
        ret = pt_sync_forward_from_offs(dctx, dec, cfg, offs);
        if (ret < 0) {
            /*
             * No PSB in the current buffer. Don't report an error
             * sync PSB frequency can be configured by the user.
             */
            dctx->enabled = false;
            *processed = 0;
            return (0);
        }
        dctx->enabled = !(ret & pts_ip_suppressed);
    }

    pt_insn_get_offset(dec, &offs);
    do {
        /* Process any pending events. */
        while (ret >= 0 && (ret & pts_event_pending) != 0) {
            ret = pt_insn_event(dec, &event, sizeof(event));
            if (ret >= 0) {
                if (event.type == ptev_enabled)
                    dctx->enabled = true;
                else if (event.type == ptev_disabled)
                    dctx->enabled = false;
                pt_print_event(tc, dctx, &event, offs);
            }
            pt_insn_get_offset(dec, &offs);
        }
        if (ret >= 0) {
            ret = pt_insn_next(dec, &insn, sizeof(insn));
            pt_insn_get_offset(dec, &offs);
        }
        if (ret < 0) {
            if (ret == -pte_eos || ret == -pte_no_enable) {
                /*
                 * We've hit the end of the current buffer or trace.
                 * Don't report an error and tell the next invocation
                 * to sync to the next PSB.
                 */
                error = 0;
                dctx->at_eos = true;
                dctx->resume_off = offs;
                if (ret == -pte_no_enable && !dctx->enabled)
                    dctx->needs_sync = true;
            } else if (ret == -pte_nomap) {
                fprintf(stdout,
                        "%s: no map at offset 0x%lu; resyncing\n",
                        __func__, offs);
                pt_insn_get_offset(dec, &offs);
                ret = pt_sync_forward_from_offs(dctx, dec, cfg, offs);
                if (ret < 0) {
                    dctx->needs_sync = true;
                    dctx->enabled = false;
                    dctx->at_eos = true;
                    dctx->resume_off = offs;
                    error = 0;
                    break;
                }
                dctx->enabled = true;
                continue;
            } else {
                pt_insn_get_offset(dec, &offs);
                if (offs + PSB_PACKET_SIZE >=
                    (uint64_t)start + len) {
                    /*
                     * The decoding error happened at the very end of the
                     * tracing buffer. Don't report an error since this
                     * could've been caused by a torn PSB packet. Let
                     * the subsequent invocation known that it should re-sync.
                     */
                    dctx->at_eos = true;
                    dctx->resume_off = offs;
                    error = 0;
                    break;
                }
                fprintf(stderr,
                        "%s: error decoding next instruction: %s\n",
                        __func__, pt_strerror(ret));
                error = ret;
            }
            break;
        }

        pt_print_insn(tc, dctx, &insn, offs);
        pt_insn_get_offset(dec, &offs);
    } while (1);

    pt_insn_get_offset(dec, &offs);
    if (offs < start) {
        /*
         * The decoder is lagging behind the current chunk, which
         * can happen after a buffer wrap. Report no progress
         * and resync next chunk.
         */
        *processed = 0;
        dctx->needs_sync = true;
        return (error);
    }
    *processed = offs - start;

    return (error);
}

static int
pt_decode_generic_init(struct trace_context *tc, struct pt_dec_ctx *dctx)
{
	char filename[MAXPATHLEN];

	if (tc->filename) {
		snprintf(filename, MAXPATHLEN, "%s%d", tc->filename,
                 dctx->id);
		dctx->out = fopen(filename, "w");
		if (dctx->out == NULL) {
			printf("Could not open %s\n", filename);
			return (ENXIO);
		}
		dctx->xop = xo_create_to_file(dctx->out, XO_STYLE_TEXT,
                                      XOF_WARN);
	} else {
		dctx->out = stdout;
		dctx->xop = NULL;
	}

	return (0);
}

struct pt_decode_ops pt_decode_generic_ops = {
.init = pt_decode_generic_init,
.decode_chunk = pt_decode_chunk_insn
};
