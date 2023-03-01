#include "common_user.h"
#include <yaml-cpp/yaml.h>

static int parse_u8(char *str, unsigned char *x)
{
    unsigned long z;

    z = strtoul(str, 0, 16);
    if (z > 0xff)
        return -1;

    if (x)
        *x = z;

    return 0;
}

static int parse_mac(char *str, unsigned char mac[ETH_ALEN])
{
    if (parse_u8(str, &mac[0]) < 0)
        return -1;
    if (parse_u8(str + 3, &mac[1]) < 0)
        return -1;
    if (parse_u8(str + 6, &mac[2]) < 0)
        return -1;
    if (parse_u8(str + 9, &mac[3]) < 0)
        return -1;
    if (parse_u8(str + 12, &mac[4]) < 0)
        return -1;
    if (parse_u8(str + 15, &mac[5]) < 0)
        return -1;

    return 0;
}

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

int fillup_init_map(const char* pin_dir, const char* file_name) {
    int err, key;
    YAML::Node data_node = YAML::LoadFile(file_name)["podip2podinfo"];
    for (auto it = data_node.begin(); it != data_node.end(); it++) {
        __be32 pod_ip = inet_addr((char*)it->first.as<std::string>().data());

        struct podinfo podinfo_;
        podinfo_.ifkey = it->second["ifkey"].as<int>();
        char src_mac_ori[18];
        it->second["podmac"].as<std::string>().copy(src_mac_ori, 18, 0);
        if (parse_mac(src_mac_ori, podinfo_.podmac) < 0) {
            return EXIT_FAIL_OPTION;
        }
        // Update data to podip2podinfo map
        err = update_map_element(pin_dir, "podip2podinfo", &pod_ip, &podinfo_);
        if (err) {
            printf("ERR: podip2podinfo\n");
        }
    }

    data_node = YAML::LoadFile(file_name)["devmap"];
    for (auto it = data_node.begin(); it != data_node.end(); it++) {
        key = it->first.as<int>();
        int ifidx = it->second.as<int>();
        // Update data to sdpodip2restorekey map
        err = update_map_element(pin_dir, "devmap", &key, &ifidx);
        if (err) {
            printf("ERR: devmap\n");
            printf("key: %d, ifidx: %d\n", key, ifidx);
        }
    }
    return EXIT_SUCCESS;
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir =  "/sys/fs/bpf/";

int main(int argc, char **argv)
{
    int err, len;
    char pin_dir[PATH_MAX];

    // Fill up the initial sdpodip2restorekey and restorekey2netinfo map
    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, "tc/globals/");
    err = fillup_init_map(pin_dir, "mapdata.yaml");

    if(err < 0) return EXIT_FAIL_BPF;
    return EXIT_OK;
}