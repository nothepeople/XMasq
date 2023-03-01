#include "bpf/bpf.h"
#include "common_defines.h"

#ifndef __COMMON_USER_H
#define __COMMON_USER_H

bool locate_kern_object(char *execname, char *filename, size_t size);

#define BPF_DIR_MNT "/sys/fs/bpf"
int bpf_fs_check_and_fix();

int tc_new_qdisc(const char* dev);
int tc_attach_bpf(const char* dev, const char* bpf_obj,
    const char* sec_name, bool egress);
int tc_list_filter(const char* dev, bool egress);
int tc_remove_filter(const char* dev, bool egress);

#ifdef __cplusplus
extern "C" {
#endif
int open_bpf_map_file(const char *pin_dir,
        const char *mapname,
        struct bpf_map_info *info);
#ifdef __cplusplus
}
#endif

#endif
