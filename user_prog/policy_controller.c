#include "common_defines.h"
#include "common_user.h"

#define ENABLENP
#ifdef ENABLENP
// Match the existing rule with adding rule
bool match_rule(struct rule *existing_rule, struct rule *adding_rule) {
    if (existing_rule->isIngress != adding_rule->isIngress) return false;
    else if (existing_rule->fivetuple_.saddr != adding_rule->fivetuple_.saddr &&
        adding_rule->fivetuple_.saddr != 0)
            return false;
    else if (existing_rule->fivetuple_.daddr != adding_rule->fivetuple_.daddr &&
        adding_rule->fivetuple_.daddr != 0)
            return false;
    else if (existing_rule->fivetuple_.sport != adding_rule->fivetuple_.sport &&
        adding_rule->fivetuple_.sport != 0)
            return false;
    else if (existing_rule->fivetuple_.dport != adding_rule->fivetuple_.dport &&
        adding_rule->fivetuple_.dport != 0)
            return false;
    else if (existing_rule->fivetuple_.protocol != adding_rule->fivetuple_.protocol &&
        adding_rule->fivetuple_.protocol != 0)
            return false;

    return true;
}

int check_and_del_rules(int np_map_fd, struct rule *adding_rule) {
    struct rule prev_rule_;
    struct rule rule_;
    struct rule del_key = {
        .isIngress = -1
    };
    while (bpf_map_get_next_key(np_map_fd, &prev_rule_, &rule_) == 0) {
        // fprintf(stdout, "Start iteration\n");
        if (del_key.isIngress != -1) {
            // Delete the previous key if it exist
            if (bpf_map_delete_elem(np_map_fd, &del_key) < 0)
                return EXIT_FAIL_BPF;
            del_key.isIngress = -1;
            fprintf(stdout, "Delete a cache!\n");
        }

        // Should merge the rules to the adding one
        if (match_rule(&rule_, adding_rule)) {
            // If this cache match the rule, should delete the cache
            // But we could not delete the key immediately.
            del_key = rule_;
        } else {
            del_key.isIngress = -1;
        }
        prev_rule_ = rule_;
    }
    if (del_key.isIngress != -1) {
        // Delete the last key if it matched
        if (bpf_map_delete_elem(np_map_fd, &del_key) < 0)
            return EXIT_FAIL_BPF;
        fprintf(stdout, "Delete a cache!\n");
    }
    return EXIT_SUCCESS;
}

const char *pin_dir =  "/sys/fs/bpf/tc/globals/";

static const struct option np_long_options[] = {
    {"ingress", no_argument,  NULL, 'I' },
    {"allow",   no_argument,  NULL, 'A' },
    {"srcip",   required_argument, NULL, 'S' },
    {"dstip",   required_argument, NULL, 'D' },
    {"srcport", required_argument, NULL, 's' },
    {"dstport", required_argument, NULL, 'd' },
    {"protocol", required_argument, NULL, 'P' },
    {0,         0,                  NULL,  0 }
};

void parse_np_args(int argc, char **argv,
            struct rule *rule_, __u8 *action)
{
    int opt, longindex = 0;

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "IASDsdP",
                  np_long_options, &longindex)) != -1) {
        switch (opt) {
        case 'S':
            rule_->fivetuple_.saddr = inet_addr(optarg);
            break;
        case 'D':
            rule_->fivetuple_.daddr = inet_addr(optarg);
            break;
        case 's':
            rule_->fivetuple_.sport = htons(atoi(optarg));
            break;
        case 'd':
            rule_->fivetuple_.dport = htons(atoi(optarg));
            break;
        case 'P':
            // Only support tcp and udp
            if (strcmp(optarg, "udp") == 0) {
                rule_->fivetuple_.protocol = IPPROTO_UDP;
            } else if (strcmp(optarg, "tcp") == 0) {
                rule_->fivetuple_.protocol = IPPROTO_TCP;
            } else {
                printf("Dont support the protocol: %s \n", optarg);
                return;
            }
            break;
        case 'I':
            rule_->isIngress = 1;
            break;
        // Only support the adding rule's action is allow
        // case 'A':
        //  *action = 1;
        //  break;
        default:
            return;
        }
    }
}

int main(int argc, char **argv) {
    // The prog should have five tuple specified
    struct rule rule_;
    rule_.isIngress = 0;
    rule_.fivetuple_.saddr = 0;
    rule_.fivetuple_.daddr = 0;
    rule_.fivetuple_.sport = 0;
    rule_.fivetuple_.dport = 0;
    rule_.fivetuple_.protocol = 0;

    __u8 action = 0;

    parse_np_args(argc, argv, &rule_, &action);
    printf("A new rule added!\n**********\nsaddr: %x ", rule_.fivetuple_.saddr);
    printf("daddr: %x ", rule_.fivetuple_.daddr);
    printf("sport: %d ", rule_.fivetuple_.sport);
    printf("dport: %d ", rule_.fivetuple_.dport);
    printf("protocol: %d ", rule_.fivetuple_.protocol);
    printf("isIngress: %d ", rule_.isIngress);
    printf("action: %d \n*********\n", action);

    // Add to rules map
    int map_fd = open_bpf_map_file(pin_dir, "rulesmap", NULL);
    check_and_del_rules(map_fd, &rule_);
    int err = bpf_map_update_elem(map_fd, &rule_, &action, BPF_ANY);

    return EXIT_OK;
}
#endif
