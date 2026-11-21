#include <stdbool.h>

int
hwt_elf_process_exec(struct trace_context *tc,
    struct hwt_record_user_entry *rec);

int
hwt_elf_link_pmcstat_img(struct trace_context *tc,
    struct hwt_record_user_entry *entry, bool);
