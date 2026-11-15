#include <sys/param.h>
#include <sys/types.h>
#include <sys/cpuset.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/hwt.h>
#include <sys/hwt_record.h>
#include <sys/stat.h>

#include <assert.h>
#include <fcntl.h>
#include <gelf.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#include "hwt.h"
#include "hwt_elf.h"
#include "hwt_record.h"

#include "libpmcstat_stubs.h"
#include <libpmcstat.h>

static int
hwt_elf_find_exec_seg(const char *fullpath, uint64_t *vaddr, uint64_t *foffset,
    size_t *size, char **dynlinker_path)
{
	int error;
	GElf_Phdr ph;
	GElf_Ehdr eh;
	GElf_Shdr sh;
	Elf *elf;
	Elf_Scn *scn;
	int fd;
	size_t i;
	uint64_t start, end;
	const char *elfbase;
	bool found;

	fd = open(fullpath, O_RDONLY, 0);

	assert(fd >= 0);

	elf = elf_begin(fd, ELF_C_READ, NULL);

	assert(elf != NULL);
	assert(elf_kind(elf) == ELF_K_ELF);

	error = 0;
	if (dynlinker_path != NULL)
		*dynlinker_path = NULL;
	if (gelf_getehdr(elf, &eh) != &eh) {
		fprintf(stderr, "%s: Could not find elf header\n",
		    __func__);
		error = -1;
		goto done;
	}

	if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN) {
		fprintf(stderr, "%s: Unsupported image type\n", __func__);
		error = -1;
		goto done;
	}

	if (eh.e_ident[EI_CLASS] != ELFCLASS32 &&
	    eh.e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "%s: Unsupported ELF class\n", __func__);
		error = -1;
		goto done;
	}

	found = false;
	for (i = 0; i < eh.e_phnum; i++) {
		if (gelf_getphdr(elf, i, &ph) != &ph) {
			warnx("WARNING: Cannot read program header for \"%s\": %s.",
			    fullpath, elf_errmsg(-1));
			error = -1;
			goto done;
		}

		if (ph.p_type == PT_INTERP && dynlinker_path != NULL) {
			if ((elfbase = elf_rawfile(elf, NULL)) == NULL) {
				warnx(
					"WARNING: Cannot retrieve the interpreter for \"%s\": %s.",
					fullpath, elf_errmsg(-1));
				goto done;
			}
			*dynlinker_path = strdup(elfbase + ph.p_offset);
			continue;
		}

		if (ph.p_type == PT_LOAD) {
			if ((ph.p_flags & PF_X) != 0 && !found) {
				*vaddr = ph.p_vaddr;
				*foffset = ph.p_offset;
				found = true;
			}
		}
	}

	if (!found) {
		warnx("Skipping empty image \"%s\"", fullpath);
		error = -1;
		goto done;
	}

	size_t nsh;
	if (elf_getshnum(elf, &nsh) == 0) {
			error = -1;
		goto done;
	}
	for (i = 0; i < nsh; i++) {
		if ((scn = elf_getscn(elf, i)) == NULL ||
			gelf_getshdr(scn, &sh) != &sh) {
			warnx(
				"WARNING: Could not retrieve section header #%ju in \"%s\": %s.",
				(uintmax_t) i, fullpath, elf_errmsg(-1));
			error = -1;
			goto done;
		}
		if (sh.sh_flags & SHF_EXECINSTR) {
			start = MIN(start, sh.sh_addr);
			end = MAX(end, sh.sh_addr + sh.sh_size);
		}
	}
	*size = end - start;

done:
	assert(elf_end(elf) == 0);
	assert(close(fd) == 0);

	return (error);
}

int
hwt_elf_process_exec(struct trace_context *tc,
    struct hwt_record_user_entry *rec)
{
	int error;
	uint64_t seg_vaddr, foffset;
	struct hwt_record_user_entry mmap_rec;
	struct hwt_wakeup wakeup;
	char* dynlinker_path;

	assert(rec->record_type == HWT_RECORD_EXECUTABLE);
	assert(elf_version(EV_CURRENT) != EV_NONE);

	if (hwt_elf_find_exec_seg(rec->fullpath, &seg_vaddr,
	    &foffset, &mmap_rec.size, &dynlinker_path) != 0)
		return (0);
	strlcpy(mmap_rec.fullpath, rec->fullpath, PATH_MAX);
	mmap_rec.addr = rec->addr + seg_vaddr;
	mmap_rec.foffset = foffset;
	mmap_rec.record_type = HWT_RECORD_MMAP;

	if (tc->backend->methods->as_event_cb != NULL &&
	    (error = tc->backend->methods->as_event_cb(tc, &mmap_rec))) {
		ioctl(tc->thr_fd, HWT_IOC_WAKEUP, &wakeup);
		return (error);
	}
	hwt_elf_link_pmcstat_img(tc, &mmap_rec);

	if (dynlinker_path == NULL)
		return (0);

	/* Fetch and register RTLD. */
	if (hwt_elf_find_exec_seg(dynlinker_path,
	    &seg_vaddr, &foffset, &mmap_rec.size, NULL) != 0) {
		free(dynlinker_path);
		return (-1);
	}
	strlcpy(mmap_rec.fullpath, dynlinker_path,
	    PATH_MAX);
	mmap_rec.addr = rec->baseaddr + seg_vaddr;
	mmap_rec.foffset = foffset;
	mmap_rec.record_type = HWT_RECORD_MMAP;
	free(dynlinker_path);

	if (tc->backend->methods->as_event_cb != NULL &&
	    (error = tc->backend->methods->as_event_cb(tc, &mmap_rec))) {
		ioctl(tc->thr_fd, HWT_IOC_WAKEUP, &wakeup);
		return (error);
	}

	hwt_elf_link_pmcstat_img(tc, &mmap_rec);
	return (0);
}

int
hwt_elf_link_pmcstat_img(struct trace_context *tc,
    struct hwt_record_user_entry *entry)
{
	pmcstat_interned_string path;
	struct pmcstat_image *image;
	struct pmc_plugins plugins;
	struct pmcstat_args args;
	unsigned long addr;
	char imagepath[PATH_MAX];

	memset(&plugins, 0, sizeof(struct pmc_plugins));
	memset(&args, 0, sizeof(struct pmcstat_args));
	args.pa_fsroot = "/";
	snprintf(imagepath, sizeof(imagepath), "%s/%s", tc->fs_root,
	    entry->fullpath);
	path = pmcstat_string_intern(imagepath);

	image = pmcstat_image_from_path(path,
	    !!(entry->record_type == HWT_RECORD_KERNEL), &args, &plugins);
	if (image == NULL)
		return (-1);

	if (image->pi_type == PMCSTAT_IMAGE_UNKNOWN)
		pmcstat_image_determine_type(image, &args);

	if (image->pi_end == 0) {
		printf("  image '%s' has no executable sections, skipping\n",
		    imagepath);
		free(image);
		image = NULL;
		return (0);
	}
	addr = (unsigned long)entry->addr & ~1;
	if (tc->mode == HWT_MODE_THREAD)
		addr += image->pi_vaddr;

	pmcstat_image_link(tc->pp, image, addr);
	return (0);
}
