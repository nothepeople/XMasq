#include "common_defines.h"
#include "common_user.h"

// Unit = 4.294s
#define CHECK_TIME 1
#define SENDER_EXPIRE_TIME 5
#define RECEIVER_EXPIRE_TIME 10

int update_map_element(const char* pin_dir, const char * map_name, const void* key, const void* value) {
    int map_fd = open_bpf_map_file(pin_dir, map_name, NULL);
    if (map_fd < 0) {
        return EXIT_FAIL_BPF;
    }
    int err = bpf_map_update_elem(map_fd, key, value, 0);
    if (err < 0) {
        fprintf(stderr, "ERR: bpf_map_update_elem\n");
        return EXIT_FAIL_BPF;
    }
    return 0;
}

int check_send_cache_valid(int map_fd, int expire_time) {
    struct podip prev_podip_;
    struct podip podip_;
    struct podip del_key = {0};
    struct pathinfo pathinfo_;
    struct timespec timestamp = { 0, 0 };
    clock_gettime(CLOCK_MONOTONIC, &timestamp);
    uint32_t time =
        (timestamp.tv_sec * 1000000000 + timestamp.tv_nsec) >> 32;
    fprintf(stdout, "Current time: %d\n", time);
    while(bpf_map_get_next_key(map_fd, &prev_podip_, &podip_) == 0) {
        // fprintf(stdout, "Start iteration\n");
        if (del_key.local_ip != 0) {
            // Delete the previous key if it exist
            if (bpf_map_delete_elem(map_fd, &del_key) < 0)
                return EXIT_FAIL_BPF;
            del_key.local_ip = 0;
            fprintf(stdout, "Delete a cache!\n");
        }
        bpf_map_lookup_elem(map_fd, &podip_, &pathinfo_);

        uint32_t cache_time = pathinfo_.last_refresh_time;
        fprintf(stdout, "Cache time: %d\n", cache_time);
        if (time > cache_time + expire_time) {
            fprintf(stdout, "A expired cache found\n");
            del_key = podip_;
        } else {
            del_key.local_ip = 0;
        }
        prev_podip_ = podip_;
    }
    if (del_key.local_ip != 0) {
        // Delete the last key if it matched
        if (bpf_map_delete_elem(map_fd, &del_key) < 0)
            return EXIT_FAIL_BPF;
        fprintf(stdout, "Delete a cache!\n");
    }
    return EXIT_SUCCESS;
}

int check_receive_cache_valid(int map_fd, int expire_time) {
    struct pathkey prev_pathkey_;
    struct pathkey pathkey_;
    struct pathkey del_key = {0};
    struct pathinfo pathinfo_;
    struct timespec timestamp = { 0, 0 };
    clock_gettime(CLOCK_MONOTONIC, &timestamp);
    uint32_t time =
        (timestamp.tv_sec * 1000000000 + timestamp.tv_nsec) >> 32;
    fprintf(stdout, "Current time: %d\n", time);
    while(bpf_map_get_next_key(map_fd, &prev_pathkey_, &pathkey_) == 0) {
        // fprintf(stdout, "Start iteration\n");
        if (del_key.ip != 0) {
            // Delete the previous key if it exist
            if (bpf_map_delete_elem(map_fd, &del_key) < 0)
                return EXIT_FAIL_BPF;
            del_key.ip = 0;
            fprintf(stdout, "Delete a cache!\n");
        }
        bpf_map_lookup_elem(map_fd, &pathkey_, &pathinfo_);

        uint32_t cache_time = pathinfo_.last_refresh_time;
        fprintf(stdout, "Cache time: %d\n", cache_time);
        if (time > cache_time + expire_time) {
            fprintf(stdout, "A expired cache found\n");
            del_key = pathkey_;
        } else {
            del_key.ip = 0;
        }
        prev_pathkey_ = pathkey_;
    }
    if (del_key.ip != 0) {
        // Delete the last key if it matched
        if (bpf_map_delete_elem(map_fd, &del_key) < 0)
            return EXIT_FAIL_BPF;
        fprintf(stdout, "Delete a cache!\n");
    }
    return EXIT_SUCCESS;
}

const char *pin_dir =  "/sys/fs/bpf/tc/globals/";

int main(int argc, char **argv) {
    fprintf(stdout, "Start check info\n");

    while (1) {
        int send_map_fd = open_bpf_map_file(pin_dir, "podip2nodepathinfo", NULL);
        int rev_map_fd = open_bpf_map_file(pin_dir, "pathkey2podpathinfo", NULL);
        if (send_map_fd < 0 || rev_map_fd < 0) {
            fprintf(stderr, "Map open failed\n");
            return EXIT_FAIL_BPF;
        } else {
            fprintf(stdout, "Map open Sucessed\n");
        }
        fprintf(stdout, "Check send map\n");
        check_send_cache_valid(send_map_fd, SENDER_EXPIRE_TIME);
        close(send_map_fd);
        fprintf(stdout, "Check Receive map\n");
        check_receive_cache_valid(rev_map_fd, RECEIVER_EXPIRE_TIME);
        close(rev_map_fd);
        sleep(CHECK_TIME);
    }
    return EXIT_OK;
}