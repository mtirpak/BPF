#include <string.h>
#include <stdio.h>

#include <linux/bpf.h>
#include <bpf/bpf.h> // tools/lib from the kernel sources

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


static const char *blacklisted_ips_pin = "/sys/fs/bpf/xdp/globals/blacklisted_ips";

void printusage(void)
{
    printf("Usage: blacklist_user add/del <IP>\n");
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        printusage();
        return -1;
    }

    struct in_addr addr;
    if (inet_aton(argv[2], &addr) == 0)  {
        printf("Invalid address\n");
        return -1;
    }

    int blacklisted_ips_fd = bpf_obj_get(blacklisted_ips_pin);
    if (blacklisted_ips_fd <= 0) {
        printf("Missing BPF map: %s\n", blacklisted_ips_pin);
        return -1;
    }


    int value;
    if (strncmp(argv[1], "add", 3) == 0) {
        value = 1;
        if (bpf_map_update_elem(blacklisted_ips_fd, &addr.s_addr, &value, BPF_ANY) < 0) {
            printf("failed to add the address\n");
            return -1;
        }
    } else if (strncmp(argv[1], "del", 3) == 0) {
        if (bpf_map_delete_elem(blacklisted_ips_fd, &addr.s_addr) < 0) {
            printf("failed to delete the address\n");
        }
    } else {
        printusage();
        return -1;
    }
    return 0;
}
