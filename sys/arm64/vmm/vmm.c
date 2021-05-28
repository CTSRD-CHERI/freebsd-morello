/*
 * Copyright (C) 2015 Mihai Carabas <mihai.carabas@gmail.com>
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/cpuset.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>
#include <vm/vm_param.h>

#include <machine/cpu.h>
#include <machine/machdep.h>
#include <machine/vm.h>
#include <machine/pcb.h>
#include <machine/param.h>
#include <machine/smp.h>
#include <machine/vmparam.h>
#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <machine/armreg.h>

#include <dev/pci/pcireg.h>

#include "vmm_stat.h"
#include "vmm_mem.h"
#include "arm64.h"
#include "mmu.h"
#include "psci.h"

#include "io/vgic_v3.h"
#include "io/vtimer.h"

#define	BSP	0			/* the boostrap processor */

struct vcpu {
	int		flags;
	enum vcpu_state	state;
	struct mtx	mtx;
	int		hostcpu;	/* host cpuid this vcpu last ran on */
	int		vcpuid;
	void		*stats;
	struct vm_exit	exitinfo;
	uint64_t	nextpc;		/* (x) next instruction to execute */
};

#define	vcpu_lock_initialized(v) mtx_initialized(&((v)->mtx))
#define	vcpu_lock_init(v)	mtx_init(&((v)->mtx), "vcpu lock", 0, MTX_SPIN)
#define	vcpu_lock(v)		mtx_lock_spin(&((v)->mtx))
#define	vcpu_unlock(v)		mtx_unlock_spin(&((v)->mtx))
#define	vcpu_assert_locked(v)	mtx_assert(&((v)->mtx), MA_OWNED)

struct mem_seg {
	uint64_t	gpa;
	size_t		len;
	bool		wired;
	bool		sysmem;
	vm_object_t	object;
};
#define	VM_MAX_MEMSEGS	3

struct mem_map {
	vm_paddr_t	gpa;
	size_t		len;
	vm_ooffset_t	segoff;
	int		segid;
	int		prot;
	int		flags;
};
#define	VM_MAX_MEMMAPS	4

struct vmm_mmio_region {
	uint64_t start;
	uint64_t end;
	mem_region_read_t read;
	mem_region_write_t write;
};
#define	VM_MAX_MMIO_REGIONS	4

/*
 * Initialization:
 * (o) initialized the first time the VM is created
 * (i) initialized when VM is created and when it is reinitialized
 * (x) initialized before use
 */
struct vm {
	void		*cookie;		/* (i) cpu-specific data */
	volatile cpuset_t active_cpus;		/* (i) active vcpus */
	volatile cpuset_t debug_cpus;		/* (i) vcpus stopped for debug */
	int		suspend;		/* (i) stop VM execution */
	volatile cpuset_t suspended_cpus; 	/* (i) suspended vcpus */
	volatile cpuset_t halted_cpus;		/* (x) cpus in a hard halt */
	struct mem_map	mem_maps[VM_MAX_MEMMAPS]; /* (i) guest address space */
	struct mem_seg	mem_segs[VM_MAX_MEMSEGS]; /* (o) guest memory regions */
	struct vmspace	*vmspace;		/* (o) guest's address space */
	char		name[VM_MAX_NAMELEN];	/* (o) virtual machine name */
	struct vcpu	vcpu[VM_MAXCPU];	/* (i) guest vcpus */
	uint16_t	maxcpus;		/* (o) max pluggable cpus */
	struct vmm_mmio_region mmio_region[VM_MAX_MMIO_REGIONS];
						/* (o) guest MMIO regions */
};

static bool vmm_initialized = false;

static struct vmm_ops *ops = NULL;

#define	VMM_INIT(num)	(ops != NULL ? (*ops->init)(num) : 0)
#define	VMM_CLEANUP()	(ops != NULL ? (*ops->cleanup)() : 0)

#define	VMINIT(vm, pmap) (ops != NULL ? (*ops->vminit)(vm, pmap): NULL)
#define	VMRUN(vmi, vcpu, pc, pmap, rvc, sc) \
	(ops != NULL ? (*ops->vmrun)(vmi, vcpu, pc, pmap, rvc, sc) : ENXIO)
#define	VMCLEANUP(vmi)	(ops != NULL ? (*ops->vmcleanup)(vmi) : NULL)
#define	VMSPACE_ALLOC(min, max) \
	(ops != NULL ? (*ops->vmspace_alloc)(min, max) : NULL)
#define	VMSPACE_FREE(vmspace) \
	(ops != NULL ? (*ops->vmspace_free)(vmspace) : ENXIO)
#define	VMGETREG(vmi, vcpu, num, retval)		\
	(ops != NULL ? (*ops->vmgetreg)(vmi, vcpu, num, retval) : ENXIO)
#define	VMSETREG(vmi, vcpu, num, val)		\
	(ops != NULL ? (*ops->vmsetreg)(vmi, vcpu, num, val) : ENXIO)
#define	VMGETCAP(vmi, vcpu, num, retval)	\
	(ops != NULL ? (*ops->vmgetcap)(vmi, vcpu, num, retval) : ENXIO)
#define	VMSETCAP(vmi, vcpu, num, val)		\
	(ops != NULL ? (*ops->vmsetcap)(vmi, vcpu, num, val) : ENXIO)

#define	fpu_start_emulating()	load_cr0(rcr0() | CR0_TS)
#define	fpu_stop_emulating()	clts()

static int vm_handle_wfi(struct vm *vm, int vcpuid,
			 struct vm_exit *vme, bool *retu);

static MALLOC_DEFINE(M_VMM, "vmm", "vmm");

/* statistics */
static VMM_STAT(VCPU_TOTAL_RUNTIME, "vcpu total runtime");

SYSCTL_NODE(_hw, OID_AUTO, vmm, CTLFLAG_RW, NULL, NULL);

/*
 * Halt the guest if all vcpus are executing a HLT instruction with
 * interrupts disabled.
 */
static int halt_detection_enabled = 1;
SYSCTL_INT(_hw_vmm, OID_AUTO, halt_detection, CTLFLAG_RDTUN,
    &halt_detection_enabled, 0,
    "Halt VM if all vcpus execute HLT with interrupts disabled");

static int vmm_ipinum;
SYSCTL_INT(_hw_vmm, OID_AUTO, ipinum, CTLFLAG_RD, &vmm_ipinum, 0,
    "IPI vector used for vcpu notifications");

static int trace_guest_exceptions;
SYSCTL_INT(_hw_vmm, OID_AUTO, trace_guest_exceptions, CTLFLAG_RDTUN,
    &trace_guest_exceptions, 0,
    "Trap into hypervisor on all guest exceptions and reflect them back");

static void vm_free_memmap(struct vm *vm, int ident);
static bool sysmem_mapping(struct vm *vm, struct mem_map *mm);
static void vcpu_notify_event_locked(struct vcpu *vcpu, bool lapic_intr);

static void
vcpu_cleanup(struct vm *vm, int i, bool destroy)
{
//	struct vcpu *vcpu = &vm->vcpu[i];
}

static void
vcpu_init(struct vm *vm, uint32_t vcpu_id, bool create)
{
	struct vcpu *vcpu;

	vcpu = &vm->vcpu[vcpu_id];

	if (create) {
		KASSERT(!vcpu_lock_initialized(vcpu), ("vcpu %d already "
		    "initialized", vcpu_id));
		vcpu_lock_init(vcpu);
		vcpu->hostcpu = NOCPU;
		vcpu->vcpuid = vcpu_id;
	}
}

struct vm_exit *
vm_exitinfo(struct vm *vm, int cpuid)
{
	struct vcpu *vcpu;

	if (cpuid < 0 || cpuid >= vm->maxcpus)
		panic("vm_exitinfo: invalid cpuid %d", cpuid);

	vcpu = &vm->vcpu[cpuid];

	return (&vcpu->exitinfo);
}

static int
vmm_init(void)
{
	ops = &vmm_ops_arm;

	return (VMM_INIT(0));
}

static int
vmm_handler(module_t mod, int what, void *arg)
{
	int error;

	switch (what) {
	case MOD_LOAD:
		vmmdev_init();
		error = vmm_init();
		if (error == 0)
			vmm_initialized = true;
		break;
	case MOD_UNLOAD:
		error = vmmdev_cleanup();
		if (error == 0 && vmm_initialized) {
			error = VMM_CLEANUP();
			if (error)
				vmm_initialized = false;
		}
		break;
	default:
		error = 0;
		break;
	}
	return (error);
}

static moduledata_t vmm_kmod = {
	"vmm",
	vmm_handler,
	NULL
};

/*
 * vmm initialization has the following dependencies:
 *
 * - HYP initialization requires smp_rendezvous() and therefore must happen
 *   after SMP is fully functional (after SI_SUB_SMP).
 */
DECLARE_MODULE(vmm, vmm_kmod, SI_SUB_SMP + 1, SI_ORDER_ANY);
MODULE_VERSION(vmm, 1);

static void
vm_init(struct vm *vm, bool create)
{
	int i;

	vm->cookie = VMINIT(vm, vmspace_pmap(vm->vmspace));

	CPU_ZERO(&vm->active_cpus);
	CPU_ZERO(&vm->debug_cpus);

	vm->suspend = 0;
	CPU_ZERO(&vm->suspended_cpus);

	memset(vm->mmio_region, 0, sizeof(vm->mmio_region));

	for (i = 0; i < vm->maxcpus; i++)
		vcpu_init(vm, i, create);
}

int
vm_create(const char *name, struct vm **retvm)
{
	struct vm *vm;
	struct vmspace *vmspace;

	/*
	 * If vmm.ko could not be successfully initialized then don't attempt
	 * to create the virtual machine.
	 */
	if (!vmm_initialized)
		return (ENXIO);

	if (name == NULL || strlen(name) >= VM_MAX_NAMELEN)
		return (EINVAL);

	vmspace = VMSPACE_ALLOC(0, 1ul << 39);
	if (vmspace == NULL)
		return (ENOMEM);

	vm = malloc(sizeof(struct vm), M_VMM, M_WAITOK | M_ZERO);
	strcpy(vm->name, name);
	vm->vmspace = vmspace;

	vm->maxcpus = VM_MAXCPU;	/* XXX temp to keep code working */

	vm_init(vm, true);

	*retvm = vm;
	return (0);
}

uint16_t
vm_get_maxcpus(struct vm *vm)
{
	return (vm->maxcpus);
}


static void
vm_cleanup(struct vm *vm, bool destroy)
{
	struct mem_map *mm;
	int i;

	vtimer_vmcleanup(vm);
	vgic_v3_detach_from_vm(vm);

	for (i = 0; i < vm->maxcpus; i++)
		vcpu_cleanup(vm, i, destroy);

	VMCLEANUP(vm->cookie);

	/*
	 * System memory is removed from the guest address space only when
	 * the VM is destroyed. This is because the mapping remains the same
	 * across VM reset.
	 *
	 * Device memory can be relocated by the guest (e.g. using PCI BARs)
	 * so those mappings are removed on a VM reset.
	 */
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm->mem_maps[i];
		if (destroy || !sysmem_mapping(vm, mm))
			vm_free_memmap(vm, i);
	}

	if (destroy) {
		for (i = 0; i < VM_MAX_MEMSEGS; i++)
			vm_free_memseg(vm, i);

		VMSPACE_FREE(vm->vmspace);
		vm->vmspace = NULL;
	}
}

void
vm_destroy(struct vm *vm)
{
	vm_cleanup(vm, true);
	free(vm, M_VMM);
}

int
vm_reinit(struct vm *vm)
{
	int error;

	/*
	 * A virtual machine can be reset only if all vcpus are suspended.
	 */
	if (CPU_CMP(&vm->suspended_cpus, &vm->active_cpus) == 0) {
		vm_cleanup(vm, false);
		vm_init(vm, false);
		error = 0;
	} else {
		error = EBUSY;
	}

	return (error);
}

const char *
vm_name(struct vm *vm)
{
	return (vm->name);
}

int
vm_map_mmio(struct vm *vm, vm_paddr_t gpa, size_t len, vm_paddr_t hpa)
{
	vm_object_t obj;

	if ((obj = vmm_mmio_alloc(vm->vmspace, gpa, len, hpa)) == NULL)
		return (ENOMEM);
	else
		return (0);
}

int
vm_unmap_mmio(struct vm *vm, vm_paddr_t gpa, size_t len)
{

	vmm_mmio_free(vm->vmspace, gpa, len);
	return (0);
}

int
vmm_map_gpa(struct vm *vm, vm_offset_t va, vm_paddr_t gpa, int pages,
    vm_page_t *ma)
{
	size_t len;
	int cnt;

	KASSERT((gpa & PAGE_MASK) == 0, ("%s: Misaligned guest address %lx",
	    __func__, gpa));
	KASSERT((va & PAGE_MASK) == 0, ("%s: Misaligned address %lx", __func__,
	    va));

	len = pages * PAGE_SIZE;
	cnt = vm_fault_quick_hold_pages(&vm->vmspace->vm_map, gpa, len,
	    VM_PROT_READ, ma, pages);
	if (cnt == -1)
		return (-1);

	KASSERT(cnt == pages, ("%s: Invalid page count %d != %d", __func__,
	   cnt, pages));
	pmap_qenter(va, ma, pages);
	return (cnt);
}

void
vmm_unmap_gpa(struct vm *vm, vm_offset_t va, size_t pages, vm_page_t *ma)
{

	KASSERT((va & PAGE_MASK) == 0, ("%s: Misaligned address %lx", __func__,
	    va));
	pmap_qremove(va, pages);
	vm_page_unhold_pages(ma, pages);
}


/*
 * Return 'true' if 'gpa' is allocated in the guest address space.
 *
 * This function is called in the context of a running vcpu which acts as
 * an implicit lock on 'vm->mem_maps[]'.
 */
bool
vm_mem_allocated(struct vm *vm, int vcpuid, vm_paddr_t gpa)
{
	struct mem_map *mm;
	int i;

#ifdef INVARIANTS
	int hostcpu, state;
	state = vcpu_get_state(vm, vcpuid, &hostcpu);
	KASSERT(state == VCPU_RUNNING && hostcpu == curcpu,
	    ("%s: invalid vcpu state %d/%d", __func__, state, hostcpu));
#endif

	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm->mem_maps[i];
		if (mm->len != 0 && gpa >= mm->gpa && gpa < mm->gpa + mm->len)
			return (true);		/* 'gpa' is sysmem or devmem */
	}

#if 0
	if (ppt_is_mmio(vm, gpa))
		return (true);			/* 'gpa' is pci passthru mmio */
#endif

	return (false);
}

int
vm_alloc_memseg(struct vm *vm, int ident, size_t len, bool sysmem)
{
	struct mem_seg *seg;
	vm_object_t obj;

	if (ident < 0 || ident >= VM_MAX_MEMSEGS)
		return (EINVAL);

	if (len == 0 || (len & PAGE_MASK))
		return (EINVAL);

	seg = &vm->mem_segs[ident];
	if (seg->object != NULL) {
		if (seg->len == len && seg->sysmem == sysmem)
			return (EEXIST);
		else
			return (EINVAL);
	}

	obj = vm_object_allocate(OBJT_DEFAULT, len >> PAGE_SHIFT);
	if (obj == NULL)
		return (ENOMEM);

	seg->len = len;
	seg->object = obj;
	seg->sysmem = sysmem;
	return (0);
}

int
vm_get_memseg(struct vm *vm, int ident, size_t *len, bool *sysmem,
    vm_object_t *objptr)
{
	struct mem_seg *seg;

	if (ident < 0 || ident >= VM_MAX_MEMSEGS)
		return (EINVAL);

	seg = &vm->mem_segs[ident];
	if (len)
		*len = seg->len;
	if (sysmem)
		*sysmem = seg->sysmem;
	if (objptr)
		*objptr = seg->object;
	return (0);
}

void
vm_free_memseg(struct vm *vm, int ident)
{
	struct mem_seg *seg;

	KASSERT(ident >= 0 && ident < VM_MAX_MEMSEGS,
	    ("%s: invalid memseg ident %d", __func__, ident));

	seg = &vm->mem_segs[ident];
	if (seg->object != NULL) {
		vm_object_deallocate(seg->object);
		bzero(seg, sizeof(struct mem_seg));
	}
}

int
vm_mmap_memseg(struct vm *vm, vm_paddr_t gpa, int segid, vm_ooffset_t first,
    size_t len, int prot, int flags)
{
	struct mem_seg *seg;
	struct mem_map *m, *map;
	vm_ooffset_t last;
	int i, error;

	if (prot == 0 || (prot & ~(VM_PROT_ALL)) != 0)
		return (EINVAL);

	if (flags & ~VM_MEMMAP_F_WIRED)
		return (EINVAL);

	if (segid < 0 || segid >= VM_MAX_MEMSEGS)
		return (EINVAL);

	seg = &vm->mem_segs[segid];
	if (seg->object == NULL)
		return (EINVAL);

	last = first + len;
	if (first < 0 || first >= last || last > seg->len)
		return (EINVAL);

	if ((gpa | first | last) & PAGE_MASK)
		return (EINVAL);

	map = NULL;
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		m = &vm->mem_maps[i];
		if (m->len == 0) {
			map = m;
			break;
		}
	}

	if (map == NULL)
		return (ENOSPC);

	error = vm_map_find(&vm->vmspace->vm_map, seg->object, first, &gpa,
	    len, 0, VMFS_NO_SPACE, prot, prot, 0);
	if (error != KERN_SUCCESS)
		return (EFAULT);

	vm_object_reference(seg->object);

	if (flags & VM_MEMMAP_F_WIRED) {
		error = vm_map_wire(&vm->vmspace->vm_map, gpa, gpa + len,
		    VM_MAP_WIRE_USER | VM_MAP_WIRE_NOHOLES);
		if (error != KERN_SUCCESS) {
			vm_map_remove(&vm->vmspace->vm_map, gpa, gpa + len);
			return (error == KERN_RESOURCE_SHORTAGE ? ENOMEM :
			    EFAULT);
		}
	}

	map->gpa = gpa;
	map->len = len;
	map->segoff = first;
	map->segid = segid;
	map->prot = prot;
	map->flags = flags;
	return (0);
}

int
vm_mmap_getnext(struct vm *vm, vm_paddr_t *gpa, int *segid,
    vm_ooffset_t *segoff, size_t *len, int *prot, int *flags)
{
	struct mem_map *mm, *mmnext;
	int i;

	mmnext = NULL;
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm->mem_maps[i];
		if (mm->len == 0 || mm->gpa < *gpa)
			continue;
		if (mmnext == NULL || mm->gpa < mmnext->gpa)
			mmnext = mm;
	}

	if (mmnext != NULL) {
		*gpa = mmnext->gpa;
		if (segid)
			*segid = mmnext->segid;
		if (segoff)
			*segoff = mmnext->segoff;
		if (len)
			*len = mmnext->len;
		if (prot)
			*prot = mmnext->prot;
		if (flags)
			*flags = mmnext->flags;
		return (0);
	} else {
		return (ENOENT);
	}
}

static void
vm_free_memmap(struct vm *vm, int ident)
{
	struct mem_map *mm;
	int error;

	mm = &vm->mem_maps[ident];
	if (mm->len) {
		error = vm_map_remove(&vm->vmspace->vm_map, mm->gpa,
		    mm->gpa + mm->len);
		KASSERT(error == KERN_SUCCESS, ("%s: vm_map_remove error %d",
		    __func__, error));
		bzero(mm, sizeof(struct mem_map));
	}
}

static __inline bool
sysmem_mapping(struct vm *vm, struct mem_map *mm)
{

	if (mm->len != 0 && vm->mem_segs[mm->segid].sysmem)
		return (true);
	else
		return (false);
}

vm_paddr_t
vmm_sysmem_maxaddr(struct vm *vm)
{
	struct mem_map *mm;
	vm_paddr_t maxaddr;
	int i;

	maxaddr = 0;
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm->mem_maps[i];
		if (sysmem_mapping(vm, mm)) {
			if (maxaddr < mm->gpa + mm->len)
				maxaddr = mm->gpa + mm->len;
		}
	}
	return (maxaddr);
}


#include <sys/queue.h>
#include <sys/linker.h>

static int
vm_handle_reg_emul(struct vm *vm, int vcpuid, bool *retu)
{
	struct hyp *hyp;
	struct vm_exit *vme;
	struct vre *vre;
	reg_read_t rread;
	reg_write_t rwrite;

	hyp = (struct hyp *)vm->cookie;
	vme = vm_exitinfo(vm, vcpuid);
	vre = &vme->u.reg_emul.vre;

	switch(vre->inst_syndrome & ISS_MSR_REG_MASK) {
	/* Counter registers */
	case ISS_CNTP_CTL_EL0:
		rread = vtimer_phys_ctl_read;
		rwrite = vtimer_phys_ctl_write;
		break;
	case ISS_CNTP_CT_EL0:
		rread = vtimer_phys_cnt_read;
		rwrite = vtimer_phys_cnt_write;
		break;
	case ISS_CNTP_CVAL_EL0:
		rread = vtimer_phys_cval_read;
		rwrite = vtimer_phys_cval_write;
		break;
	case ISS_CNTP_TVAL_EL0:
		rread = vtimer_phys_tval_read;
		rwrite = vtimer_phys_tval_write;
		break;

	/* Interrupt controller registers */
	case ISS_ICC_SGI1R_EL1:
		rread = vgic_v3_icc_sgi1r_read;
		rwrite = vgic_v3_icc_sgi1r_write;
		break;

	default:
		*retu = true;
		return (0);
	}

	return (vmm_emulate_register(vm, vcpuid, vre, rread, rwrite, retu));
}

void
vm_register_inst_handler(struct vm *vm, uint64_t start, uint64_t size,
    mem_region_read_t mmio_read, mem_region_write_t mmio_write)
{
	int i;

	for (i = 0; i < nitems(vm->mmio_region); i++) {
		if (vm->mmio_region[i].start == 0 &&
		    vm->mmio_region[i].end == 0) {
			vm->mmio_region[i].start = start;
			vm->mmio_region[i].end = start + size;
			vm->mmio_region[i].read = mmio_read;
			vm->mmio_region[i].write = mmio_write;
			return;
		}
	}

	panic("%s: No free MMIO region", __func__);
}

void
vm_deregister_inst_handler(struct vm *vm, uint64_t start, uint64_t size)
{
	int i;

	for (i = 0; i < nitems(vm->mmio_region); i++) {
		if (vm->mmio_region[i].start == start &&
		    vm->mmio_region[i].end == start + size) {
			memset(&vm->mmio_region[i], 0,
			    sizeof(vm->mmio_region[i]));
			return;
		}
	}

	panic("%s: Invalid MMIO region: %lx - %lx", __func__, start,
	    start + size);
}

static int
vm_mmio_region_match(const void *key, const void *memb)
{
	const uint64_t *addr = key;
	const struct vgic_mmio_region *vmr = memb;

	if (*addr < vmr->start)
		return (-1);
	else if (*addr >= vmr->start && *addr < vmr->end)
		return (0);
	else
		return (1);
}

static int
vm_handle_inst_emul(struct vm *vm, int vcpuid, bool *retu)
{
	struct vm_exit *vme;
	struct vie *vie;
	struct hyp *hyp = vm->cookie;
	uint64_t fault_ipa;
	struct vm_guest_paging *paging;
	struct vmm_mmio_region *vmr;
	int error, i;

	if (!hyp->vgic_attached)
		goto out_user;

	vme = vm_exitinfo(vm, vcpuid);
	vie = &vme->u.inst_emul.vie;
	paging = &vme->u.inst_emul.paging;

	fault_ipa = vme->u.inst_emul.gpa;

	vmr = NULL;
	for (i = 0; i < nitems(vm->mmio_region); i++) {
		if (vm->mmio_region[i].start <= fault_ipa &&
		    vm->mmio_region[i].end > fault_ipa) {
			vmr = &vm->mmio_region[i];
			break;
		}
	}
	if (vmr == NULL)
		goto out_user;

	error = vmm_emulate_instruction(vm, vcpuid, fault_ipa, vie,
	    paging, vmr->read, vmr->write, retu);
	return (error);

out_user:
	*retu = true;
	return (0);
}

static int
vm_handle_poweroff(struct vm *vm, int vcpuid)
{
	return (0);
}

static int
vm_handle_psci_call(struct vm *vm, int vcpuid, bool *retu)
{
	struct vm_exit *vme;
	enum vm_suspend_how how;
	int error;

	vme = vm_exitinfo(vm, vcpuid);

	error = psci_handle_call(vm, vcpuid, vme, retu);
	if (error)
		goto out;

	if (vme->exitcode == VM_EXITCODE_SUSPENDED) {
		how = vme->u.suspended.how;
		switch (how) {
		case VM_SUSPEND_POWEROFF:
			vm_handle_poweroff(vm, vcpuid);
			break;
		default:
			/* Nothing to do */
			;
		}
	}

out:
	return (error);
}

int
vm_suspend(struct vm *vm, enum vm_suspend_how how)
{
	int i;

	if (how <= VM_SUSPEND_NONE || how >= VM_SUSPEND_LAST)
		return (EINVAL);

	if (atomic_cmpset_int(&vm->suspend, 0, how) == 0) {
#if 0
		VM_CTR2(vm, "virtual machine already suspended %d/%d",
		    vm->suspend, how);
#endif
		return (EALREADY);
	}

#if 0
	VM_CTR1(vm, "virtual machine successfully suspended %d", how);
#endif

	/*
	 * Notify all active vcpus that they are now suspended.
	 */
	for (i = 0; i < vm->maxcpus; i++) {
		if (CPU_ISSET(i, &vm->active_cpus))
			vcpu_notify_event(vm, i, false);
	}

	return (0);
}

int
vm_activate_cpu(struct vm *vm, int vcpuid)
{

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	if (CPU_ISSET(vcpuid, &vm->active_cpus))
		return (EBUSY);

	CPU_SET_ATOMIC(vcpuid, &vm->active_cpus);
	return (0);

}

int
vm_suspend_cpu(struct vm *vm, int vcpuid)
{
	int i;

	if (vcpuid < -1 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	if (vcpuid == -1) {
		vm->debug_cpus = vm->active_cpus;
		for (i = 0; i < vm->maxcpus; i++) {
			if (CPU_ISSET(i, &vm->active_cpus))
				vcpu_notify_event(vm, i, false);
		}
	} else {
		if (!CPU_ISSET(vcpuid, &vm->active_cpus))
			return (EINVAL);

		CPU_SET_ATOMIC(vcpuid, &vm->debug_cpus);
		vcpu_notify_event(vm, vcpuid, false);
	}
	return (0);
}

int
vm_resume_cpu(struct vm *vm, int vcpuid)
{

	if (vcpuid < -1 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	if (vcpuid == -1) {
		CPU_ZERO(&vm->debug_cpus);
	} else {
		if (!CPU_ISSET(vcpuid, &vm->debug_cpus))
			return (EINVAL);

		CPU_CLR_ATOMIC(vcpuid, &vm->debug_cpus);
	}
	return (0);
}


cpuset_t
vm_active_cpus(struct vm *vm)
{

	return (vm->active_cpus);
}

cpuset_t
vm_debug_cpus(struct vm *vm)
{

	return (vm->debug_cpus);
}

cpuset_t
vm_suspended_cpus(struct vm *vm)
{

	return (vm->suspended_cpus);
}


void *
vcpu_stats(struct vm *vm, int vcpuid)
{

	return (vm->vcpu[vcpuid].stats);
}

/*
 * This function is called to ensure that a vcpu "sees" a pending event
 * as soon as possible:
 * - If the vcpu thread is sleeping then it is woken up.
 * - If the vcpu is running on a different host_cpu then an IPI will be directed
 *   to the host_cpu to cause the vcpu to trap into the hypervisor.
 */
static void
vcpu_notify_event_locked(struct vcpu *vcpu, bool lapic_intr)
{
	int hostcpu;

	KASSERT(lapic_intr == false, ("%s: lapic_intr != false", __func__));
	hostcpu = vcpu->hostcpu;
	if (vcpu->state == VCPU_RUNNING) {
		KASSERT(hostcpu != NOCPU, ("vcpu running on invalid hostcpu"));
		if (hostcpu != curcpu) {
#if 0
			if (lapic_intr) {
				vlapic_post_intr(vcpu->vlapic, hostcpu,
				    vmm_ipinum);
			} else
#endif
			{
				ipi_cpu(hostcpu, vmm_ipinum);
			}
		} else {
			/*
			 * If the 'vcpu' is running on 'curcpu' then it must
			 * be sending a notification to itself (e.g. SELF_IPI).
			 * The pending event will be picked up when the vcpu
			 * transitions back to guest context.
			 */
		}
	} else {
		KASSERT(hostcpu == NOCPU, ("vcpu state %d not consistent "
		    "with hostcpu %d", vcpu->state, hostcpu));
		if (vcpu->state == VCPU_SLEEPING)
			wakeup_one(vcpu);
	}
}

void
vcpu_notify_event(struct vm *vm, int vcpuid, bool lapic_intr)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];

	vcpu_lock(vcpu);
	vcpu_notify_event_locked(vcpu, lapic_intr);
	vcpu_unlock(vcpu);
}

static int
vcpu_set_state_locked(struct vm *vm, int vcpuid, enum vcpu_state newstate,
    bool from_idle)
{
	struct vcpu *vcpu;
	int error;

	vcpu = &vm->vcpu[vcpuid];
	vcpu_assert_locked(vcpu);

	/*
	 * State transitions from the vmmdev_ioctl() must always begin from
	 * the VCPU_IDLE state. This guarantees that there is only a single
	 * ioctl() operating on a vcpu at any point.
	 */
	if (from_idle) {
		while (vcpu->state != VCPU_IDLE) {
			vcpu_notify_event_locked(vcpu, false);
			msleep_spin(&vcpu->state, &vcpu->mtx, "vmstat", hz);
		}
	} else {
		KASSERT(vcpu->state != VCPU_IDLE, ("invalid transition from "
		    "vcpu idle state"));
	}

	if (vcpu->state == VCPU_RUNNING) {
		KASSERT(vcpu->hostcpu == curcpu, ("curcpu %d and hostcpu %d "
		    "mismatch for running vcpu", curcpu, vcpu->hostcpu));
	} else {
		KASSERT(vcpu->hostcpu == NOCPU, ("Invalid hostcpu %d for a "
		    "vcpu that is not running", vcpu->hostcpu));
	}

	/*
	 * The following state transitions are allowed:
	 * IDLE -> FROZEN -> IDLE
	 * FROZEN -> RUNNING -> FROZEN
	 * FROZEN -> SLEEPING -> FROZEN
	 */
	switch (vcpu->state) {
	case VCPU_IDLE:
	case VCPU_RUNNING:
	case VCPU_SLEEPING:
		error = (newstate != VCPU_FROZEN);
		break;
	case VCPU_FROZEN:
		error = (newstate == VCPU_FROZEN);
		break;
	default:
		error = 1;
		break;
	}

	if (error)
		return (EBUSY);

	vcpu->state = newstate;
	if (newstate == VCPU_RUNNING)
		vcpu->hostcpu = curcpu;
	else
		vcpu->hostcpu = NOCPU;

	if (newstate == VCPU_IDLE)
		wakeup(&vcpu->state);

	return (0);
}

static void
vcpu_require_state(struct vm *vm, int vcpuid, enum vcpu_state newstate)
{
	int error;

	if ((error = vcpu_set_state(vm, vcpuid, newstate, false)) != 0)
		panic("Error %d setting state to %d\n", error, newstate);
}

static void
vcpu_require_state_locked(struct vm *vm, int vcpuid, enum vcpu_state newstate)
{
	int error;

	if ((error = vcpu_set_state_locked(vm, vcpuid, newstate, false)) != 0)
		panic("Error %d setting state to %d", error, newstate);
}

int
vm_get_capability(struct vm *vm, int vcpu, int type, int *retval)
{
	if (vcpu < 0 || vcpu >= vm->maxcpus)
		return (EINVAL);

	if (type < 0 || type >= VM_CAP_MAX)
		return (EINVAL);

	return (VMGETCAP(vm->cookie, vcpu, type, retval));
}

int
vm_set_capability(struct vm *vm, int vcpu, int type, int val)
{
	if (vcpu < 0 || vcpu >= vm->maxcpus)
		return (EINVAL);

	if (type < 0 || type >= VM_CAP_MAX)
		return (EINVAL);

	return (VMSETCAP(vm->cookie, vcpu, type, val));
}

int
vcpu_set_state(struct vm *vm, int vcpuid, enum vcpu_state newstate,
		bool from_idle)
{
	int error;
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		panic("vm_set_run_state: invalid vcpuid %d", vcpuid);

	vcpu = &vm->vcpu[vcpuid];

	vcpu_lock(vcpu);
	error = vcpu_set_state_locked(vm, vcpuid, newstate, from_idle);
	vcpu_unlock(vcpu);

	return (error);
}

enum vcpu_state
vcpu_get_state(struct vm *vm, int vcpuid, int *hostcpu)
{
	struct vcpu *vcpu;
	enum vcpu_state state;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		panic("vm_get_run_state: invalid vcpuid %d", vcpuid);

	vcpu = &vm->vcpu[vcpuid];

	vcpu_lock(vcpu);
	state = vcpu->state;
	if (hostcpu != NULL)
		*hostcpu = vcpu->hostcpu;
	vcpu_unlock(vcpu);

	return (state);
}

void *
vm_gpa_hold(struct vm *vm, int vcpuid, vm_paddr_t gpa, size_t len, int reqprot,
	    void **cookie)
{
	int i, count, pageoff;
	struct mem_map *mm;
	vm_page_t m;
#ifdef INVARIANTS
	/*
	 * All vcpus are frozen by ioctls that modify the memory map
	 * (e.g. VM_MMAP_MEMSEG). Therefore 'vm->memmap[]' stability is
	 * guaranteed if at least one vcpu is in the VCPU_FROZEN state.
	 */
	int state;
	KASSERT(vcpuid >= -1 && vcpuid < vm->maxcpus, ("%s: invalid vcpuid %d",
	    __func__, vcpuid));
	for (i = 0; i < vm->maxcpus; i++) {
		if (vcpuid != -1 && vcpuid != i)
			continue;
		state = vcpu_get_state(vm, i, NULL);
		KASSERT(state == VCPU_FROZEN, ("%s: invalid vcpu state %d",
		    __func__, state));
	}
#endif
	pageoff = gpa & PAGE_MASK;
	if (len > PAGE_SIZE - pageoff)
		panic("vm_gpa_hold: invalid gpa/len: 0x%016lx/%lu", gpa, len);

	count = 0;
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm->mem_maps[i];
		if (sysmem_mapping(vm, mm) && gpa >= mm->gpa &&
		    gpa < mm->gpa + mm->len) {
			count = vm_fault_quick_hold_pages(&vm->vmspace->vm_map,
			    trunc_page(gpa), PAGE_SIZE, reqprot, &m, 1);
			break;
		}
	}

	if (count == 1) {
		*cookie = m;
		return ((void *)(PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m)) + pageoff));
	} else {
		*cookie = NULL;
		return (NULL);
	}
}

void
vm_gpa_release(void *cookie)
{
	vm_page_t m = cookie;

	vm_page_unwire(m, PQ_ACTIVE);
}

int
vm_get_register(struct vm *vm, int vcpu, int reg, uint64_t *retval)
{

	if (vcpu < 0 || vcpu >= vm->maxcpus)
		return (EINVAL);

	if (reg >= VM_REG_LAST)
		return (EINVAL);

	return (VMGETREG(vm->cookie, vcpu, reg, retval));
}

int
vm_set_register(struct vm *vm, int vcpuid, int reg, uint64_t val)
{
	struct vcpu *vcpu;
	int error;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	if (reg >= VM_REG_LAST)
		return (EINVAL);
	error = VMSETREG(vm->cookie, vcpuid, reg, val);
	if (error || reg != VM_REG_ELR_EL2)
		return (error);

	vcpu = &vm->vcpu[vcpuid];
	vcpu->nextpc = val;

	return(0);
}

void *
vm_get_cookie(struct vm *vm)
{
	return vm->cookie;
}

int
vm_attach_vgic(struct vm *vm, uint64_t dist_start, size_t dist_size,
    uint64_t redist_start, size_t redist_size)
{
	int error;

	error = vgic_v3_attach_to_vm(vm, dist_start, dist_size, redist_start,
	    redist_size);

	return (error);
}

int
vm_assert_irq(struct vm *vm, uint32_t irq)
{
	struct hyp *hyp = (struct hyp *)vm->cookie;
	int error;

	error = vgic_v3_inject_irq(hyp, -1, irq, true, VGIC_IRQ_MISC);

	return (error);
}

int
vm_deassert_irq(struct vm *vm, uint32_t irq)
{
	struct hyp *hyp = (struct hyp *)vm->cookie;
	int error;

	error = vgic_v3_inject_irq(hyp, -1, irq, false, VGIC_IRQ_MISC);

	return (error);
}

int
vm_raise_msi(struct vm *vm, uint64_t msg, uint64_t addr, int bus, int slot,
    int func)
{
	struct hyp *hyp = (struct hyp *)vm->cookie;
	int error;

	if (addr >= hyp->vgic_dist.start && addr < hyp->vgic_dist.end) {
		error = vgic_v3_inject_msi(hyp, msg, addr);
		if (error == 0)
			return (0);
	}

	/* TODO: Should we raise an SError? */
	return (EINVAL);
}

static int
vm_handle_wfi(struct vm *vm, int vcpuid, struct vm_exit *vme, bool *retu)
{
	struct vcpu *vcpu;
	struct hypctx *hypctx;
	bool intr_disabled;

	vcpu = &vm->vcpu[vcpuid];
	hypctx = vme->u.wfi.hypctx;
	intr_disabled = !(hypctx->regs.spsr & PSR_I);

	vcpu_lock(vcpu);
	while (1) {
		if (!intr_disabled && vgic_v3_vcpu_pending_irq(hypctx))
			break;

		if (vcpu_should_yield(vm, vcpuid))
			break;

		vcpu_require_state_locked(vm, vcpuid, VCPU_SLEEPING);
		msleep_spin(vcpu, &vcpu->mtx, "vmidle", hz);
		vcpu_require_state_locked(vm, vcpuid, VCPU_FROZEN);
	}
	vcpu_unlock(vcpu);

	*retu = false;
	return (0);
}

static int
vm_handle_paging(struct vm *vm, int vcpuid, bool *retu)
{
	struct vm_exit *vme;
	struct vm_map *map;
	struct vcpu *vcpu;
	uint64_t addr, esr;
	pmap_t pmap;
	int ftype, rv;

	vme = vm_exitinfo(vm, vcpuid);
	pmap = vmspace_pmap(vm->vmspace);
	vcpu = &vm->vcpu[vcpuid];
	addr = vme->u.paging.gpa;
	esr = vme->u.paging.esr;

	/* The page exists, but the page table needs to be upddated */
	if (pmap_fault(pmap, vme->u.paging.esr, addr) == KERN_SUCCESS)
		return (0);

	switch (ESR_ELx_EXCEPTION(vme->u.paging.esr)) {
	case EXCP_INSN_ABORT_L:
		ftype = VM_PROT_EXECUTE;
		break;
	case EXCP_DATA_ABORT_L:
		ftype = (esr & ISS_DATA_WnR) == 0 ? VM_PROT_READ :
		    VM_PROT_READ | VM_PROT_WRITE;
		break;
	default:
		panic("%s: Invalid exception (esr = %lx)", __func__,
		    vme->u.paging.esr);
	}

	map = &vm->vmspace->vm_map;
	rv = vm_fault(map, vme->u.paging.gpa, ftype, VM_FAULT_NORMAL, NULL);
	if (rv != KERN_SUCCESS)
		return (EFAULT);

	return (0);
}

int
vm_run(struct vm *vm, struct vm_run *vmrun)
{
	int error, vcpuid;
	struct vcpu *vcpu;
	struct vm_exit *vme;
	bool retu;
	void *rvc, *sc;
	pmap_t pmap;

	vcpuid = vmrun->cpuid;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	if (!CPU_ISSET(vcpuid, &vm->active_cpus))
		return (EINVAL);

	if (CPU_ISSET(vcpuid, &vm->suspended_cpus))
		return (EINVAL);

	pmap = vmspace_pmap(vm->vmspace);
	vcpu = &vm->vcpu[vcpuid];
	rvc = sc = NULL;
restart:
	critical_enter();
	vcpu_require_state(vm, vcpuid, VCPU_RUNNING);
	error = VMRUN(vm->cookie, vcpuid, vcpu->nextpc, pmap, rvc, sc);
	vcpu_require_state(vm, vcpuid, VCPU_FROZEN);
	critical_exit();

	vme = vm_exitinfo(vm, vcpuid);
	if (error == 0) {
		retu = false;
		switch (vme->exitcode) {
		case VM_EXITCODE_INST_EMUL:
			vcpu->nextpc = vme->pc + vme->inst_length;
			error = vm_handle_inst_emul(vm, vcpuid, &retu);
			break;

		case VM_EXITCODE_REG_EMUL:
			vcpu->nextpc = vme->pc + vme->inst_length;
			error = vm_handle_reg_emul(vm, vcpuid, &retu);
			break;

		case VM_EXITCODE_HVC:
			/*
			 * The HVC instruction saves the address for the
			 * next instruction as the return address.
			 */
			vcpu->nextpc = vme->pc;
			/*
			 * The PSCI call can change the exit information in the
			 * case of suspend/reset/poweroff/cpu off/cpu on.
			 */
			error = psci_handle_call(vm, vcpuid, vme, &retu);
			break;

		case VM_EXITCODE_WFI:
			vcpu->nextpc = vme->pc + vme->inst_length;
			error = vm_handle_wfi(vm, vcpuid, vme, &retu);
			break;

		case VM_EXITCODE_PAGING:
			vcpu->nextpc = vme->pc;
			error = vm_handle_paging(vm, vcpuid, &retu);
			break;

		default:
			/* Handle in userland */
			vcpu->nextpc = vme->pc;
			retu = true;
			break;
		}
	}

	if (error == 0 && retu == false)
		goto restart;

	/* Copy the exit information */
	bcopy(vme, &vmrun->vm_exit, sizeof(struct vm_exit));

	return (error);
}
