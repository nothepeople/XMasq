# XMasq
## In this repo
This repo includes all the code and scripts that are required to run XMasq.

`common` folder includes the frequently used definitions in the C++ code and Makefiles.

`headers` folder includes the header files.

`rpeer_kernel` folder includes a compiled Linux kernel (5.18) with `bpf_redirect_rpeer` support.

`rpeer_kernel_patch` folder is the kernel source code that are modified to support `bpf_redirect_rpeer`. The main modification is in  `filter.c`. You can search `rpeer` to see the detail.

`scripts` includes the scripts to provision a simple kubernetes cluster and to run a netperf test.

`tc_prog` and `user_prog` include the source code of the eBPF programs and the user space programs of XMasq.

`libbpf` and `yaml-cpp` are the submodules included in the repo, and are used in compiling.
## Tutorial to try XMasq
Before the start of the tutorial, you should prepare two hosts (e.g. VM or cloud server). Our tutorial has been tested on Ubuntu 20.04.

### Step0: Clone this repo on all the hosts
The repo includes libbpf and yaml-cpp as submodules, and should be cloned at the same time. 
```
git clone --recurse-submodules https://github.com/nothepeople/XMasq.git XMasq
```

### Step1: Install the kernel with `bpf_redirect_rpeer` support 
You can use the compiled kernel in this repo. We have tested this kernel on Ubuntu 20.04. The kernel should be updated on all the hosts.
```
sudo dpkg -i ./XMasq/rpeer_kernel/linux-*
sudo reboot
```
### Step2: Provision a container cluster
The Kubernetes is the most common container orchestrater. We take Kubernetes as an example in this tutorial. We have prepared a script that helps to provision a simple Kubernetes cluster with two nodes. You should first install docker, kubeadm, kubelet, and kubectl on all of your hosts. You can reference to these pages: 

> [Install docker using the script](https://docs.docker.com/engine/install/ubuntu/#install-using-the-convenience-script) \
[Installing kubeadm, kubelet and kubectl](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#installing-kubeadm-kubelet-and-kubectl)

Then, run the script **only on the master node** to provision a two-node kubernetes cluster with Antrea as the CNI. Note that some environment varibles in the script should be modified to match your testbed. 

```
cd ./XMasq/scripts; bash ./provision.sh
```

### Step3: Install Compilation Requirements
```
sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential cmake python3 -y
```

### Step4: Compile XMasq
XMasq should be compiled on all the hosts.
```
make all -C XMasq
```

### Step5: Start the XMasq daemon. 
To use XMasq, you can simply run the daemon.py on all the hosts to start the XMasq daemon. And the daemon will attach the eBPF program on all of the containers. **Skip this step to use the standard overlay network (Antrea in this tutorial).**
```
cd ./XMasq/user_prog/; sudo python3 daemon.py
```

### Step6: Run netperf tests
To do the performance test, we prepare a script to provision a test server and a client on the two hosts. 
```
cd ./XMasq/scripts; bash ./netperf_test.sh
```
On the return of the script, it prints the privision result of the two container and directly enter the shell of the client container. And you can try any netperf test in this shell.
```
ubuntu@node-1:~$ cd ./XMasq/scripts; bash ./netperf_test.sh
some outputs...
+ kubectl get pods -owide
NAME          READY   STATUS    RESTARTS   AGE   IP          NODE    NOMINATED NODE   READINESS GATES
test-client   1/1     Running   0          5s    10.10.1.2   node2   <none>           <none>
test-server   1/1     Running   0          6s    10.10.0.4   node1   <none>           <none>
+ kubectl exec -it test-client -- bash
bash-5.1# 
```
To run the throughput test: `netperf -H <test-client-ip>`. And the RR test: `netperf -H <test-client-ip> -t TCP_RR`
## Results
Here are our experiment results in the tutorial.
### Standard overley network (Antrea)
```
bash-5.1# netperf -H 10.10.0.13
MIGRATED TCP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 10.10.0.13 (10.10.0) port 0 AF_INET
Recv   Send    Send
Socket Socket  Message  Elapsed
Size   Size    Size     Time     Throughput
bytes  bytes   bytes    secs.    10^6bits/sec

131072  16384  16384    10.00    27043.83

bash-5.1# netperf -H 10.10.0.13 -t TCP_RR
MIGRATED TCP REQUEST/RESPONSE TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 10.10.0.13 (10.10.0) port 0 AF_INET : first burst 0
Local /Remote
Socket Size   Request  Resp.   Elapsed  Trans.
Send   Recv   Size     Size    Time     Rate
bytes  Bytes  bytes    bytes   secs.    per sec

16384  131072 1        1       10.00    23340.40
16384  131072
```

### XMasq
```
bash-5.1# netperf -H 10.10.0.12
MIGRATED TCP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 10.10.0.12 (10.10.0) port 0 AF_INET
Recv   Send    Send
Socket Socket  Message  Elapsed
Size   Size    Size     Time     Throughput
bytes  bytes   bytes    secs.    10^6bits/sec

131072  16384  16384    10.00    36838.06

bash-5.1# netperf -H 10.10.0.12 -t TCP_RR
MIGRATED TCP REQUEST/RESPONSE TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 10.10.0.12 (10.10.0) port 0 AF_INET : first burst 0
Local /Remote
Socket Size   Request  Resp.   Elapsed  Trans.
Send   Recv   Size     Size    Time     Rate
bytes  Bytes  bytes    bytes   secs.    per sec

16384  131072 1        1       10.00    37093.19
16384  131072
```

### Host Network
```
ubuntu@node-1:~$ netperf -H 172.31.77.102
MIGRATED TCP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 172.31.77.102 () port 0 AF_INET : demo
Recv   Send    Send
Socket Socket  Message  Elapsed
Size   Size    Size     Time     Throughput
bytes  bytes   bytes    secs.    10^6bits/sec

131072  16384  16384    10.00    39040.97

ubuntu@node-1:~$ netperf -H 172.31.77.102 -t TCP_RR
MIGRATED TCP REQUEST/RESPONSE TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 172.31.77.102 () port 0 AF_INET : demo : first burst 0
Local /Remote
Socket Size   Request  Resp.   Elapsed  Trans.
Send   Recv   Size     Size    Time     Rate
bytes  Bytes  bytes    bytes   secs.    per sec

16384  131072 1        1       10.00    37067.84
16384  131072
```