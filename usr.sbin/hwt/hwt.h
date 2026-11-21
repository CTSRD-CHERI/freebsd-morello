/*-
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

#ifndef	_HWTVAR_H_
#define	_HWTVAR_H_

#include <stdbool.h>
#include "hwt_fmt.h"
#define	TC_MAX_ADDR_RANGES	16

struct trace_context;
struct hwt_record_user_entry;
struct pmcstat_image;

struct backend_methods {
	int (*init)(struct trace_context *tc);
	void (*shutdown)(struct trace_context *tc);

	/*
	 * Called whenever a tracing buffer is mapped into hwt.
	 */
	int (*mmap)(struct trace_context *tc,
	    struct hwt_record_user_entry *entry);
	int (*set_config)(struct trace_context *tc);

	/*
	 * Called whenever the traced process's address space layout changes.
	 */
	int (*as_event_cb)(struct trace_context *tc,
	    struct hwt_record_user_entry *ev);

	/*
	 * Trace data processing methods.
	 *
	 * An hwt backend must specify one of the two processing methods.
	 * If both methods are specified, the 'process_buffer' method will
	 * always take precedence.
	 *
	 * If present, the 'process' method should implement a complete
	 * replacement for hwt's default processing loop. This means that it is
	 * responsible for fetching trace data, fetching records, and processing
	 * the data on its own.
	 *
	 * The 'process_buffer' method gets invoked from hwt's default
	 * processing loop whenever an HWT_BUFFER_RECORD is received and is
	 * tasked with decoding tracing buffer data. This is suitable for
	 * backends whose tracing hardware issues interrupts when the tracing
	 * buffer is ready to be processed.
	 */
	int (*process)(struct trace_context *tc);
	int (*process_buffer)(struct trace_context *tc, int buf_id, int curpage,
	    vm_offset_t offset);
};

struct backend {
	const char *name;
	const char *fullname;
	struct backend_methods *methods;
};

struct trace_context {
	struct backend *backend;
	struct pmcstat_process *pp;
	struct hwt_record_user_entry *records;
	void *base;
	size_t bufsize;
	int attach;
	int pid;
	cpuset_t cpu_map;
	int fd;
	int thr_fd;
	int terminate;
	int kqueue_fd;

	int thread_id;
	int ident;

	/* Address range filtering. */
	int suspend_on_mmap;
	char *image_name;
	char *func_name;
	uintptr_t addr_ranges[TC_MAX_ADDR_RANGES * 2];
	int nranges;

	/* Backend-specific config. */
	void *config;
	int flag_format;

	/* Raw trace. */
	int raw;
	FILE *raw_f;
	uint64_t bytes_written;

	/* Trace file. */
	char *filename;

	bool shutdown;
	int mode;
	const char *fs_root;
	enum hwt_fmt_column fmt;
};

void hwt_procexit(pid_t pid, int status);
void hwt_sleep(int msec);
int hwt_find_sym(struct trace_context *tc);
struct pmcstat_symbol *hwt_sym_lookup(const struct trace_context *tc,
    uint64_t ip, struct pmcstat_image **img, uint64_t *newpc0);
int hwt_start_tracing(struct trace_context *tc);
int hwt_stop_tracing(struct trace_context *tc);
int hwt_mmap_received(struct trace_context *tc,
    struct hwt_record_user_entry *entry);
int hwt_ncpu(void);

#endif /* !_HWTVAR_H_ */
