/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Ruslan Bukin <br@bsdpad.com>
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

/* RISC-V PMU. */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/cpuset.h>
#include <sys/hwc.h>
#include <sys/wait.h>
#include <sys/sysctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <ucl.h>

#include <machine/riscvreg.h>
#include <machine/encoding.h>

#include "hwc.h"
#include "hwc_pmu.h"

#include <libxo/xo.h>

#define	HWC_DEBUG
#undef	HWC_DEBUG

#ifdef	HWC_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

struct counter {
	char *name;
	bool enabled;
};

#define	RISCV_NCOUNTERS	32

static struct counter counters[RISCV_NCOUNTERS];

static uint64_t
csr_read_num(int csr_num)
{
#define switchcase_csr_read(__csr_num, __val)		{\
	case __csr_num:					\
		__val = csr_read(__csr_num);		\
		break; }
#define switchcase_csr_read_2(__csr_num, __val)		{\
	switchcase_csr_read(__csr_num + 0, __val)	\
	switchcase_csr_read(__csr_num + 1, __val)}
#define switchcase_csr_read_4(__csr_num, __val)		{\
	switchcase_csr_read_2(__csr_num + 0, __val)	\
	switchcase_csr_read_2(__csr_num + 2, __val)}
#define switchcase_csr_read_8(__csr_num, __val)		{\
	switchcase_csr_read_4(__csr_num + 0, __val)	\
	switchcase_csr_read_4(__csr_num + 4, __val)}
#define switchcase_csr_read_16(__csr_num, __val)	{\
	switchcase_csr_read_8(__csr_num + 0, __val)	\
	switchcase_csr_read_8(__csr_num + 8, __val)}
#define switchcase_csr_read_32(__csr_num, __val)	{\
	switchcase_csr_read_16(__csr_num + 0, __val)	\
	switchcase_csr_read_16(__csr_num + 16, __val)}

	unsigned long ret = 0;

	switch (csr_num) {
	switchcase_csr_read_32(CSR_CYCLE, ret)
	switchcase_csr_read_32(CSR_CYCLEH, ret)
	default :
		break;
	}

	return ret;
#undef switchcase_csr_read_32
#undef switchcase_csr_read_16
#undef switchcase_csr_read_8
#undef switchcase_csr_read_4
#undef switchcase_csr_read_2
#undef switchcase_csr_read
}

static int
pmu_request(struct hwc_context *tc, int mhpm_id, int event_id)
{
	struct hwc_configure hc;
	int error;

	hc.event_id = event_id;
	hc.counter_id = mhpm_id;
	hc.flags = 0;

	error = ioctl(tc->ctx_fd, HWC_IOC_CONFIGURE, &hc);
	if (error) {
		printf("%s: could not configure event_id %d, error %d\n",
		    __func__, hc.event_id, error);
		return (error);
	}

	return (0);
}

static int
pmu_configure_counter(struct hwc_context *tc, const ucl_object_t *top)
{
	const ucl_object_t *obj;
	ucl_object_iter_t it = NULL;
	const char *k;
	int event_id;
	int mhpm_id;
	const char *name;
	bool enabled __unused;
	int error;

	while ((obj = ucl_iterate_object (top, &it, true))) {
		k = ucl_object_key(obj);
		if (strcmp(k, "id") == 0)
			mhpm_id = ucl_object_toint(obj);
		if (strcmp(k, "event_id") == 0)
			event_id = ucl_object_toint(obj);
		if (strcmp(k, "name") == 0)
			name = ucl_object_tostring(obj);
		if (strcmp(k, "enabled") == 0)
			enabled = ucl_object_toboolean(obj);
	}

	if (enabled == false)
		return (0);

	dprintf("%s: Configuring id %d name %s event_id %d enabled %d\n",
	    __func__, mhpm_id, name, event_id, enabled);

	error = pmu_request(tc, mhpm_id, event_id);
	if (error)
		return (error);

	counters[mhpm_id].name = strdup(name);
	counters[mhpm_id].enabled = true;

	return (0);
}

static int
pmu_configure_counters(struct hwc_context *tc, const ucl_object_t *top)
{
	ucl_object_iter_t it_obj = NULL;
	ucl_object_iter_t it = NULL;
	const ucl_object_t *obj;
	const ucl_object_t *cur;
	const char *k;
	int error;

	while ((obj = ucl_iterate_object (top, &it, true))) {
		k = ucl_object_key(obj);
		if (strcmp(k, "mhpmcounter") != 0)
			continue;
		while ((cur = ucl_iterate_object (obj, &it_obj, false))) {
			error = pmu_configure_counter(tc, cur);
			if (error)
				return (error);
		}
	}

	return (0);
}

static int
pmu_stop(struct hwc_context *tc)
{
	struct hwc_stop hs;
	int error;
	int i;

	hs.counter_mask = 0;

	for (i = 0; i < RISCV_NCOUNTERS; i++)
		if (counters[i].enabled == true)
			hs.counter_mask |= (1 << i);

	error = ioctl(tc->ctx_fd, HWC_IOC_STOP, &hs);
	if (error) {
		printf("%s: could not stop counters (mask) 0x%x, error %d\n",
		    __func__, hs.counter_mask, error);
		return (error);
	}

	return (0);
}

static int
pmu_start(struct hwc_context *tc)
{
	struct hwc_start hs;
	int error;
	int i;

	hs.counter_mask = 0;

	for (i = 0; i < RISCV_NCOUNTERS; i++)
		if (counters[i].enabled == true)
			hs.counter_mask |= (1 << i);

	error = ioctl(tc->ctx_fd, HWC_IOC_START, &hs);
	if (error) {
		printf("%s: could not start counters (mask) 0x%x, error %d\n",
		    __func__, hs.counter_mask, error);
		return (error);
	}

	return (0);
}

static int
pmu_configure(struct hwc_context *tc)
{
	struct ucl_parser *parser;
	const ucl_object_t *obj;
	ucl_object_t *top;
	ucl_object_iter_t it = NULL;
	const char *k;
	int error;
	bool ret;

	parser = ucl_parser_new(0);

	ret = ucl_parser_add_file(parser, tc->config_file);
	if (ret == false) {
		printf("can't read file\n");
		return (-1);
	}

	top = ucl_parser_get_object(parser);

	while ((obj = ucl_iterate_object(top, &it, true))) {
		k = ucl_object_key(obj);
		if (strcmp(k, "mhpmcounters") == 0) {
			error = pmu_configure_counters(tc, obj);
			if (error)
				return (error);
		}
	}

	error = pmu_start(tc);

	return (error);
}

static int
pmu_init(struct hwc_context *tc __unused)
{

	dprintf("%s\n", __func__);

	bzero(counters, sizeof(struct counter) * RISCV_NCOUNTERS);

	return (0);
}

static void
pmu_run_once(struct hwc_context *tc __unused)
{

}

static int
pmu_shutdown(struct hwc_context *tc __unused)
{
	struct counter *c;
	int i;

	pmu_stop(tc);

	/* Print out standard counters. */
	printf(" time == %ld\n", csr_read(time));
	printf(" cycle == %ld\n", csr_read(cycle));
	printf(" instructions == %ld\n", csr_read(instret));

	for (i = 0; i < RISCV_NCOUNTERS; i++) {
		c = &counters[i];
		if (c->enabled == true)
			printf(" %s == %ld\n", c->name,
			    csr_read_num(CSR_HPMCOUNTER3 - 3 + i));
	}

	return (0);
}

struct hwc_methods pmu_methods = {
	.init = pmu_init,
	.shutdown = pmu_shutdown,
	.configure = pmu_configure,
	.run_once = pmu_run_once,
};
