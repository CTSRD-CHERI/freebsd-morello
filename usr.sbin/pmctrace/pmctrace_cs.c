/*-
 * Copyright (c) 2018 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
 
#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/ttycom.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <assert.h>
#include <curses.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <kvm.h>
#include <libgen.h>
#include <limits.h>
#include <math.h>
#include <pmc.h>
#include <pmclog.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <gelf.h>
#include <inttypes.h>

#include <libpmcstat.h>

#include "pmctrace.h"
#include "pmctrace_cs.h"

#include <opencsd/c_api/ocsd_c_api_types.h>
#include <opencsd/c_api/opencsd_c_api.h>

#define	PMCTRACE_CS_DEBUG
#undef	PMCTRACE_CS_DEBUG

#ifdef	PMCTRACE_CS_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#define	PACKET_STR_LEN	1024
static char packet_str[PACKET_STR_LEN];

static dcd_tree_handle_t dcdtree_handle;

static int cs_init(struct trace_cpu *tc);
static int cs_flags;
#define	FLAG_FORMAT			(1 << 0)
#define	FLAG_FRAME_RAW_UNPACKED		(1 << 1)
#define	FLAG_FRAME_RAW_PACKED		(1 << 2)
#define	FLAG_CALLBACK_MEM_ACC		(1 << 3)

static struct pmcstat_symbol *
symbol_lookup(const struct mtrace_data *mdata, uint64_t ip,
    struct pmcstat_image **img)
{
	struct pmcstat_image *image;
	struct pmcstat_symbol *sym;
	struct pmcstat_pcmap *map;
	uint64_t newpc;

	map = pmcstat_process_find_map(mdata->pp, ip);
	if (map != NULL) {
		image = map->ppm_image;
		newpc = ip - (map->ppm_lowpc +
		    (image->pi_vaddr - image->pi_start));

		sym = pmcstat_symbol_search(image, newpc);
		*img = image;

		if (sym == NULL)
			dprintf("cpu%d: symbol 0x%lx not found\n",
			    mdata->cpu, newpc);

		return (sym);
	} else {
		dprintf("cpu%d: 0x%lx map not found\n", mdata->cpu, ip);
	}

	return (NULL);
}

static ocsd_err_t
attach_raw_printers(dcd_tree_handle_t dcd_tree_h)
{
	ocsd_err_t err;
	int flags;

	flags = 0;
	err = OCSD_OK;

	if (cs_flags & FLAG_FRAME_RAW_UNPACKED)
		flags |= OCSD_DFRMTR_UNPACKED_RAW_OUT;

	if (cs_flags & FLAG_FRAME_RAW_PACKED)
		flags |= OCSD_DFRMTR_PACKED_RAW_OUT;

	if (flags)
		err = ocsd_dt_set_raw_frame_printer(dcd_tree_h, flags);

	return err;
}

static int
print_data_array(const uint8_t *p_array, const int array_size,
    char *p_buffer, int buf_size)
{
	int bytes_processed;
	int chars_printed;

	chars_printed = 0;
	p_buffer[0] = 0;

	if (buf_size > 9) {
		strcat(p_buffer, "[ ");
		chars_printed += 2;
 
		for (bytes_processed = 0; bytes_processed < array_size;
		    bytes_processed++) {
			sprintf(p_buffer + chars_printed, "0x%02X ",
			    p_array[bytes_processed]);
			chars_printed += 5;
			if ((chars_printed + 5) > buf_size)
				break;
		}

		strcat(p_buffer, "];");
		chars_printed += 2;
	} else if (buf_size >= 4) {
		sprintf(p_buffer, "[];");
		chars_printed += 3;
	}

	return (chars_printed);
}

static void
packet_monitor(void *context __unused,
    const ocsd_datapath_op_t op,
    const ocsd_trc_index_t index_sop,
    const void *p_packet_in,
    const uint32_t size,
    const uint8_t *p_data)
{
	int offset;

	offset = 0;
 
	switch(op) {
	case OCSD_OP_DATA:
		sprintf(packet_str, "Idx:%"  OCSD_TRC_IDX_STR ";", index_sop);
		offset = strlen(packet_str);
		offset += print_data_array(p_data, size, packet_str + offset,
		    PACKET_STR_LEN - offset);

		/*
		 * Got a packet -- convert to string and use the libraries'
		 * message output to print to file and stdoout
		 */

		if (ocsd_pkt_str(OCSD_PROTOCOL_ETMV4I, p_packet_in,
		    packet_str + offset, PACKET_STR_LEN - offset) == OCSD_OK) {
			/* add in <CR> */
			if (strlen(packet_str) == PACKET_STR_LEN - 1)/*maxlen*/
				packet_str[PACKET_STR_LEN - 2] = '\n';
			else
				strcat(packet_str,"\n");

			/* print it using the library output logger. */
			ocsd_def_errlog_msgout(packet_str);
		}
		break;

	case OCSD_OP_EOT:
		sprintf(packet_str,"**** END OF TRACE ****\n");
		ocsd_def_errlog_msgout(packet_str);
		break;
	default:
		printf("%s: unknown op %d\n", __func__, op);
		break;
	}
}

static uint32_t
cs_cs_decoder__mem_access(const void *context __unused,
    const ocsd_vaddr_t address __unused,
    const ocsd_mem_space_acc_t mem_space __unused,
    const uint32_t req_size __unused, uint8_t *buffer __unused)
{

	/* TODO */

	return (0);
}

static ocsd_err_t
create_test_memory_acc(dcd_tree_handle_t handle, uint64_t base,
    uint64_t start, uint64_t end)
{
	ocsd_vaddr_t address;
	uint8_t *p_mem_buffer;
	uint32_t mem_length;
	int ret;

	dprintf("%s: base %lx start %lx end %lx\n",
	    __func__, base, start, end);

	address = (ocsd_vaddr_t)base;
	p_mem_buffer = (uint8_t *)(base + start);
	mem_length = (end-start);

	if (cs_flags & FLAG_CALLBACK_MEM_ACC)
		ret = ocsd_dt_add_callback_mem_acc(handle, base + start,
			base + end - 1, OCSD_MEM_SPACE_ANY,
			cs_cs_decoder__mem_access, NULL);
	else
		ret = ocsd_dt_add_buffer_mem_acc(handle, address,
		    OCSD_MEM_SPACE_ANY, p_mem_buffer, mem_length);

	if (ret != OCSD_OK)
		printf("%s: can't create memory accessor: ret %d\n",
		    __func__, ret);

	return (ret);
}

static ocsd_err_t
create_generic_decoder(dcd_tree_handle_t handle, const char *p_name,
    const void *p_cfg, const void *p_context __unused, uint64_t base,
    uint64_t start, uint64_t end)
{ 
	ocsd_err_t ret;
	uint8_t CSID;

	CSID = 0;

	dprintf("%s\n", __func__);

	ret = ocsd_dt_create_decoder(handle, p_name,
	    OCSD_CREATE_FLG_FULL_DECODER, p_cfg, &CSID);
	if(ret != OCSD_OK)
		return (-1);

	if (cs_flags & FLAG_FORMAT) {
		ret = ocsd_dt_attach_packet_callback(handle, CSID,
		    OCSD_C_API_CB_PKT_MON, packet_monitor, p_context);
		if (ret != OCSD_OK)
			return (-1);
	}

	/* attach a memory accessor */
	ret = create_test_memory_acc(handle, base, start, end);
	if(ret != OCSD_OK)
		ocsd_dt_remove_decoder(handle,CSID);

	return (ret);
}

static ocsd_err_t
create_decoder_etmv4(dcd_tree_handle_t dcd_tree_h, uint64_t base,
    uint64_t start, uint64_t end)
{
	ocsd_etmv4_cfg trace_config;
	ocsd_err_t ret;

	trace_config.arch_ver = ARCH_V8;
	trace_config.core_prof = profile_CortexA;

	trace_config.reg_configr = 0x000000C1;
	trace_config.reg_traceidr = 0x00000010;   /* Trace ID */

	trace_config.reg_idr0   = 0x28000EA1;
	trace_config.reg_idr1   = 0x4100F403;
	trace_config.reg_idr2   = 0x00000488;
	trace_config.reg_idr8   = 0x0;
	trace_config.reg_idr9   = 0x0;
	trace_config.reg_idr10  = 0x0;
	trace_config.reg_idr11  = 0x0;
	trace_config.reg_idr12  = 0x0;
	trace_config.reg_idr13  = 0x0;

	ret = create_generic_decoder(dcd_tree_h, OCSD_BUILTIN_DCD_ETMV4I,
	    (void *)&trace_config, 0, base, start, end);
	return (ret);
}

static ocsd_datapath_resp_t
gen_trace_elem_print_lookup(const void *p_context,
    const ocsd_trc_index_t index_sop __unused,
    const uint8_t trc_chan_id __unused,
    const ocsd_generic_trace_elem *elem __unused)
{ 
	const struct mtrace_data *mdata;
	ocsd_datapath_resp_t resp;
	struct pmcstat_symbol *sym;
	struct pmcstat_image *image;

	mdata = (const struct mtrace_data *)p_context;

	resp = OCSD_RESP_CONT;

#if 0
	dprintf("%s: Idx:%d ELEM TYPE %d, st_addr %lx, en_addr %lx\n",
	    __func__, index_sop, elem->elem_type,
	    elem->st_addr, elem->en_addr);
#endif

	if (elem->st_addr == 0)
		return (0);
	sym = symbol_lookup(mdata, elem->st_addr, &image);
	if (sym)
		printf("cpu%d:  IP 0x%lx %s %s\n", mdata->cpu, elem->st_addr,
		    pmcstat_string_unintern(image->pi_name),
		    pmcstat_string_unintern(sym->ps_name));

	switch (elem->elem_type) {
	case OCSD_GEN_TRC_ELEM_UNKNOWN:
		break;
	case OCSD_GEN_TRC_ELEM_NO_SYNC:
		/* Trace off */
		break;
	case OCSD_GEN_TRC_ELEM_TRACE_ON:
		break;
	case OCSD_GEN_TRC_ELEM_INSTR_RANGE:
		printf("range\n");
		break;
	case OCSD_GEN_TRC_ELEM_EXCEPTION:
	case OCSD_GEN_TRC_ELEM_EXCEPTION_RET:
	case OCSD_GEN_TRC_ELEM_PE_CONTEXT:
	case OCSD_GEN_TRC_ELEM_EO_TRACE:
	case OCSD_GEN_TRC_ELEM_ADDR_NACC:
	case OCSD_GEN_TRC_ELEM_TIMESTAMP:
	case OCSD_GEN_TRC_ELEM_CYCLE_COUNT:
	case OCSD_GEN_TRC_ELEM_ADDR_UNKNOWN:
	case OCSD_GEN_TRC_ELEM_EVENT:
	case OCSD_GEN_TRC_ELEM_SWTRACE:
	case OCSD_GEN_TRC_ELEM_CUSTOM:
	default:
		break;
	};

	return (resp);
}

static int
cs_process_chunk(struct mtrace_data *mdata __unused, uint64_t base,
    uint64_t start, uint64_t end)
{
	uint32_t bytes_done;
	uint32_t block_size;
	uint8_t *p_block;
	int bytes_this_time;
	int block_index;
	int dp_ret;
	int ret;

	dprintf("%s: base %lx start %lx end %lx\n",
	    __func__, base, start, end);

	bytes_this_time = 0;
	block_index = 0;
	bytes_done = 0;
	block_size = (end - start);
	p_block = (uint8_t *)(base + start);

	ret = OCSD_OK;
	dp_ret = OCSD_RESP_CONT;

	while (bytes_done < (uint32_t)block_size && (ret == OCSD_OK)) {

		if (OCSD_DATA_RESP_IS_CONT(dp_ret)) {
			dprintf("process data, block_size %d, bytes_done %d\n",
			    block_size, bytes_done);
			dp_ret = ocsd_dt_process_data(dcdtree_handle,
			    OCSD_OP_DATA,
			    block_index + bytes_done,
			    block_size - bytes_done,
			    ((uint8_t *)p_block) + bytes_done,
			    &bytes_this_time);
			bytes_done += bytes_this_time;
			dprintf("BYTES DONE %d\n", bytes_done);
		} else if (OCSD_DATA_RESP_IS_WAIT(dp_ret)) {
			dp_ret = ocsd_dt_process_data(dcdtree_handle,
			    OCSD_OP_FLUSH, 0, 0, NULL, NULL);
		} else {
			ret = OCSD_ERR_DATA_DECODE_FATAL;
		}
	}

	ocsd_dt_process_data(dcdtree_handle, OCSD_OP_EOT, 0, 0, NULL, NULL);

	return (0);
}

static int
cs_process(struct trace_cpu *tc, struct pmcstat_process *pp,
    uint32_t cpu, uint32_t cycle, uint64_t offset)
{
	struct mtrace_data *mdata;

	mdata = &tc->mdata;
	mdata->pp = pp;

	cs_init(tc);

	dprintf("%s: cpu %d, cycle %d, tc->base %lx, tc->offset %lx,"
	    "offset %lx, *tc->base %lx\n",
	    __func__, cpu, cycle, (uint64_t)tc->base,
	    (uint64_t)tc->offset, offset, *(uint64_t *)tc->base);

	if (offset == tc->offset)
		return (0);

	if (cycle == tc->cycle) {
		if (offset > tc->offset) {
			cs_process_chunk(mdata, (uint64_t)tc->base,
			    tc->offset, offset);
			tc->offset = offset;
		} else if (offset < tc->offset) {
			err(EXIT_FAILURE,
			    "cpu%d: offset already processed %lx %lx",
			    cpu, offset, tc->offset);
		}
	} else if (cycle > tc->cycle) {
		if ((cycle - tc->cycle) > 1)
			err(EXIT_FAILURE,
			    "cpu%d: trace buffers fills up faster than"
			    " we can process it (%d/%d). Consider setting"
			    " trace filters",
			    cpu, cycle, tc->cycle);
		cs_process_chunk(mdata, (uint64_t)tc->base,
		    tc->offset, tc->bufsize);
		tc->offset = 0;
		tc->cycle += 1;
	}

	return (0);
}

static int
cs_init(struct trace_cpu *tc)
{
	uint64_t start;
	uint64_t end;
	int ret;

	ocsd_def_errlog_init(OCSD_ERR_SEV_INFO, 1);
	ocsd_def_errlog_init(0, 0);

#if 0
	ret = ocsd_def_errlog_config_output(C_API_MSGLOGOUT_FLG_FILE |
	    C_API_MSGLOGOUT_FLG_STDOUT, "c_api_test.log");
	if (ret != OCSD_OK)
		return (-1);
#endif

	dcdtree_handle = ocsd_create_dcd_tree(OCSD_TRC_SRC_FRAME_FORMATTED,
	    OCSD_DFRMTR_FRAME_MEM_ALIGN);
	if(dcdtree_handle == C_API_INVALID_TREE_HANDLE) {
		printf("can't find dcd tree\n");
		return (-1);
	}

	start = (uint64_t)tc->base;
	end = (uint64_t)tc->base + tc->bufsize;

	ret = create_decoder_etmv4(dcdtree_handle,
	    (uint64_t)tc->base, start, end);
	if (ret != OCSD_OK) {
		printf("can't create decoder: base %lx start %lx end %lx\n",
		    (uint64_t)tc->base, start, end);
		return (-2);
	}

#ifdef PMCTRACE_CS_DEBUG
	ocsd_tl_log_mapped_mem_ranges(dcdtree_handle);
#endif

	if (cs_flags & FLAG_FORMAT)
		ocsd_dt_set_gen_elem_printer(dcdtree_handle);
	else
		ocsd_dt_set_gen_elem_outfn(dcdtree_handle,
		    gen_trace_elem_print_lookup,
		    (const struct mtrace_data *)&tc->mdata);

	attach_raw_printers(dcdtree_handle);

	return (0);
}

static int
cs_option(int option)
{

	switch (option) {
	case 't':
		cs_flags |= FLAG_FORMAT;
		break;
	default:
		break;
	}

	return (0);
}

struct trace_dev_methods cs_methods = {
	.init = cs_init,
	.process = cs_process,
	.option = cs_option,
};
