/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Ruslan Bukin <br@bsdpad.com>
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
#include <sys/eventhandler.h>
#include <sys/ioccom.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/refcount.h>
#include <sys/rwlock.h>
#include <sys/hwt.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vm_pageout.h>
#include <vm/vm_phys.h>

#include <dev/hwt/hwt_hook.h>
#include <dev/hwt/hwt_context.h>
#include <dev/hwt/hwt_contexthash.h>
#include <dev/hwt/hwt_config.h>
#include <dev/hwt/hwt_thread.h>
#include <dev/hwt/hwt_owner.h>
#include <dev/hwt/hwt_ownerhash.h>
#include <dev/hwt/hwt_backend.h>
#include <dev/hwt/hwt_vm.h>
#include <dev/hwt/hwt_record.h>

#define	HWT_THREAD_DEBUG
#undef	HWT_THREAD_DEBUG

#ifdef	HWT_THREAD_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static MALLOC_DEFINE(M_HWT_THREAD, "hwt_thread", "Hardware Trace");

struct hwt_thread *
hwt_thread_first(struct hwt_context *ctx)
{
	struct hwt_thread *thr;

	HWT_CTX_ASSERT_LOCKED(ctx);

	thr = TAILQ_FIRST(&ctx->threads);

	KASSERT(thr != NULL, ("thr is NULL"));

	return (thr);
}

/*
 * To use by hwt_switch_in/out() only.
 */
struct hwt_thread *
hwt_thread_lookup(struct hwt_context *ctx, struct thread *td)
{
	struct hwt_thread *thr;

	/* Caller of this func holds ctx refcnt right here. */

	HWT_CTX_LOCK(ctx);
	TAILQ_FOREACH(thr, &ctx->threads, next) {
		if (thr->td == td) {
			HWT_CTX_UNLOCK(ctx);
			return (thr);
		}
	}
	HWT_CTX_UNLOCK(ctx);

	/*
	 * We are here because the hook on thread creation failed to allocate
	 * a thread.
	 */

	return (NULL);
}

int
hwt_thread_alloc(struct hwt_context *ctx, struct hwt_thread **thr0, char *path, size_t bufsize,
    int kva_req)
{
	struct hwt_thread *thr;
	struct hwt_vm *vm;
	int error;

	error = hwt_vm_alloc(bufsize, kva_req, path, &vm);
	if (error)
		return (error);

	thr = malloc(sizeof(struct hwt_thread), M_HWT_THREAD,
	    M_WAITOK | M_ZERO);
	thr->vm = vm;
	/* Check if we need to store backend-specific data. */
  	if(ctx->hwt_backend->ops->hwt_backend_alloc_thread_priv != NULL) {
		ctx->hwt_backend->ops->hwt_backend_alloc_thread_priv(thr);
		if (thr->cookie == NULL){
			dprintf("%s: failed to allocate thread cookie\n", __func__);
			return (ENOMEM);
		}
	}

	mtx_init(&thr->mtx, "thr", NULL, MTX_DEF);

	refcount_init(&thr->refcnt, 1);

	vm->thr = thr;

	*thr0 = thr;

	return (0);
}

void
hwt_thread_free(struct hwt_thread *thr)
{

	hwt_vm_free(thr->vm);
	/* Free private backend data, if any. */
	if(thr->ctx->hwt_backend->ops->hwt_backend_free_thread_priv != NULL) {
		KASSERT(thr->cookie != NULL, ("%s: thread cookie is NULL\n", __func__));
		thr->ctx->hwt_backend->ops->hwt_backend_free_thread_priv(thr);
	}
	free(thr, M_HWT_THREAD);
}

/*
 * Inserts a new thread and a thread creation record into the
 * context notifies userspace about the newly created thread.
 */
void
hwt_thread_insert(struct hwt_context *ctx, struct hwt_thread *thr, struct hwt_record_entry *entry)
{

	HWT_CTX_ASSERT_LOCKED(ctx);
	TAILQ_INSERT_TAIL(&ctx->threads, thr, next);
	LIST_INSERT_HEAD(&ctx->records, entry, next);
}
