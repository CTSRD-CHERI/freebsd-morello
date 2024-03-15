/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Bojan Novković <bnovkov@freebsd.org>
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
#include <sys/kernel.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/taskqueue.h>

#include <dev/hwt/hwt_context.h>

#include "hwt_event.h"

TASKQUEUE_FAST_DEFINE_THREAD(hwt);

static void
hwt_event_record_handler(void *arg, int pending __unused)
{
	int ret __diagused;
	struct kevent kev;
	struct hwt_context *ctx = (struct hwt_context *)arg;

	EV_SET(&kev, HWT_KQ_NEW_RECORD_EV, EVFILT_USER, EV_ENABLE, NOTE_TRIGGER,
	    0, NULL);
	ret = kqfd_register(ctx->kqueue_fd, &kev, ctx->hwt_td, M_WAITOK);
	KASSERT(ret == 0,
	    ("%s: kqueue fd register failed: %d\n", __func__, ret));
}

int
hwt_event_send(int ev_type, struct task *task, task_fn_t *handler, void *ctx)
{
	int error;
	/* TODO: validate event type - EINVAL */
	if (ev_type == HWT_KQ_NEW_RECORD_EV) {
		handler = hwt_event_record_handler;
	}
	TASK_INIT(task, 0, handler, ctx);
	error = taskqueue_enqueue(taskqueue_hwt, task);

	return (error);
}

void
hwt_event_drain_all(void)
{
	taskqueue_drain_all(taskqueue_hwt);
}
