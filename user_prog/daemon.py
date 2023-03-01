import time
import subprocess
import yaml

NODE_IFNAME = "ens1f0np0"
POD_IFNAME = "eth0"

ENVTYPE = "kubernetes"

configed_pod = []

def runcmd(cmd):
    return subprocess.check_output(cmd, shell=True).decode().strip()

def gen_pod_yaml(cmd_prefix):
    net_info_folder = "/sys/class/net/"
    pod_mac = runcmd(cmd_prefix + f"cat {net_info_folder}{POD_IFNAME}/address")
    pod_peer_ifidx = int(runcmd(cmd_prefix + f"cat {net_info_folder}{POD_IFNAME}/iflink"))      
    tmp_dict = {}
    tmp_dict["ifkey"] = pod_peer_ifidx
    tmp_dict["podmac"] = pod_mac
    return tmp_dict

# For kubernetes case. Will only check the pods in the default namespace.
def pod_watcher():
    print("Watching Pods...")
    crictl = "crictl --runtime-endpoint unix:///run/containerd/containerd.sock "
    while True:
        namelist = runcmd("kubectl get pods -o wide 2>&1 | grep Running " + r" | awk -F ' ' '{print $1}'").split()
        podsyaml = {}
        podsyaml["podip2podinfo"] = {}
        map_add = False
        for podname in namelist:
            cid = runcmd(crictl + f" ps | grep {podname}" + r"| awk '{print $1}'")
            if (not cid) or (cid in configed_pod):
                continue
            map_add = True
            configed_pod.append(cid)
            cmd = crictl + r" inspect --template '{{.info.pid}}' --output go-template " + cid
            # print(cmd)
            pid = runcmd(cmd)
            cmd_prefix=f"nsenter -t {pid} -n "
            out = runcmd(cmd_prefix + f"ethtool -K {POD_IFNAME} gro on")
            out = runcmd(cmd_prefix + f"./tc_prog_loader --dev {POD_IFNAME} --filename ../tc_prog/tc_prog_kern.o --sec-name tc_masq --egress --new-qdisc")
            podip = runcmd(f"kubectl get pods {podname} -o custom-columns=IP:.status.podIP --no-headers=true")
            cmd_prefix = crictl + f" exec -it {cid} "
            podsyaml["podip2podinfo"][podip] = gen_pod_yaml(cmd_prefix)
            print("Configed a new Pod!")

        if map_add == True:
            with open("./mapdata.yaml", 'w') as f:
                yaml.dump(podsyaml, f, default_flow_style=False)
            out = runcmd("./set_map")
            print("Added some Podinfo to the eBPF map")
        time.sleep(1)

def init_daemon():
    configed_pod.extend(runcmd("crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps | awk '{print $1}' | sed 1d").split())

    runcmd("rm -rf /sys/fs/bpf/tc/globals/*")
    runcmd(f"./tc_prog_loader --dev {NODE_IFNAME} --filename ../tc_prog/tc_prog_kern.o --sec-name tc_init --egress --new-qdisc")
    runcmd(f"./tc_prog_loader --dev {NODE_IFNAME} --filename ../tc_prog/tc_prog_kern.o --sec-name tc_restore")
    nodeyaml = {}
    nodeyaml["devmap"] = {}
    net_info_folder = "/sys/class/net/"
    nodeyaml["devmap"][0] = int(runcmd(f"cat {net_info_folder}{NODE_IFNAME}/ifindex"))
    with open("./mapdata.yaml", 'w') as f:
        yaml.dump(nodeyaml, f, default_flow_style=False)
    out = runcmd("./set_map")
    print(out)

if __name__ == '__main__':
    init_daemon()
    print("init daemon finished")
    subprocess.Popen(f"./cache_recycler", \
                shell=True, stdout = subprocess.PIPE, stdin = subprocess.PIPE, universal_newlines=True)
    print("cache_recycler started")
    pod_watcher()
