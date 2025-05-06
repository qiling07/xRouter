# VM setup guides



## Compile a linux kernel

These are the instructions on how to compile a linux kernel and it is assuming that this kernel will be running in a qemu-kvm virtual machine.


### Install required dependencies:

For Ubuntu/Debian systems: 
```bash
sudo apt-get install make build-essential libncurses-dev bison flex libssl-dev libelf-dev
```

### Download the kernel source code

Checkout the kernel source archive website. 

[1]: https://www.kernel.org	"The Linux Kernel Archives"

Choose the version (stable, mainline etc) that fits your need and download it.

```bash
# use command "wget" to download it
wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.12.12.tar.xz
```

Put it in your working directory and uncompress it using

```bash
tar xvf linux-5.12.12.tar.xz
```



### Create kernel configuration

Generate a kernel configuration file. This file, called `.config`, will decide, for example, what kernel modules you have in your kernel.

```bash
cd linux-5.12.12
# generate a default kernel configuration file
make defconfig
# if this kernel is used in qemu-kvm, it's better to also run this
make kvm_guest.config
```

Now, you should have a `.config` file under linux-5.12.12 directory.

If you want to use a Debian Stretch to run your VM, as mentioned in [Setup: Run a QEMU-kvm virtual machine](Setup_run_a_QEMU-kvm_virtual_machine), you have to edit `.config` manually and enable two options:

```bash
# Search for the 2 following options in .config and enable them by adding the following lines
# Required for Debian Stretch
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y
```

Since enabling these options results in more sub options being available, we need to regenerate config:

```bash
make olddefconfig
```



### Compile it!

```bash
# make -j X will run compilation in X CPU cores. Please check the core number on your machine and make the best use of them
make -j $(nproc)

# if the warnings are being given as errors and you want to suppress them, use this
make WERROR=0 -j $(nproc)
```

Now you should have `vmlinux` (kernel binary) and `bzImage` (packed kernel image)

```bash
# double-check
ls linux-5.12.12/vmlinux
ls linux-5.12.12/arch/x86/boot/bzImage
```


## Prepare a kernel image

To create a virtual machine image that installed with a Debian bullseye, do:

```bash
sudo apt-get install debootstrap
cd $IMAGE/
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
chmod +x create-image.sh
./create-image.sh
```

Now you should have a disk image called `bullseye.img`.







## Local Network Configuration

This section explains how to create three TAP interfaces and connect them to a software bridge. This setup simulates a virtual LAN, allowing your VMs to communicate through the `xrouter`.

### Create TAP and Bridge devices

Create four TAP interfaces. Each TAP device acts like a virtual Ethernet interface that can be connected to a VM:

```bash
sudo ip tuntap add name tap0-xrouter mode tap
sudo ip tuntap add name tap1-xrouter mode tap
sudo ip tuntap add name tap2-xrouter mode tap
```

Create a bridge device. The bridge aggregates the TAP interfaces, effectively forming a software switch:

```bash
sudo ip link add br0-xrouter type bridge
```

### Connect each TAP interface to the bridge

This step connects each TAP device to the bridge:

```bash
sudo ip link set tap0-xrouter master br0-xrouter
sudo ip link set tap1-xrouter master br0-xrouter
sudo ip link set tap2-xrouter master br0-xrouter
```

### Enable promiscuous mode for packet forwarding

Promiscuous mode is necessary to allow the bridge to forward packets between interfaces:

```bash
sudo ip link set tap0-xrouter promisc on
sudo ip link set tap1-xrouter promisc on
sudo ip link set tap2-xrouter promisc on
sudo ip link set br0-xrouter promisc on
```

### Bring all interfaces up

Activate the interfaces so they can start handling traffic:

```bash
sudo ip link set tap0-xrouter up
sudo ip link set tap1-xrouter up
sudo ip link set tap2-xrouter up
sudo ip link set br0-xrouter up
```

Use the following command to check that all interfaces are present and active:

```bash
sudo ip link show
```






## Boot up and initialize all VMs
In the instructions below, the `$KERNEL` and `$IMAGE` notations are used to denote paths to directories that either created when executing the instructions or that you have to create before running the instructions.

### Create an image copy for each VMs
For each VMs, create an image copy.
```bash
cp -r $IMAGE vm-router
cp -r $IMAGE vm-host1
cp -r $IMAGE vm-host2
```

### Start the router VM
This section explains how to boot the router virtual machine using QEMU with two network interfaces:
- `eth0`: for external access via host port forwarding (e.g., SSH).
- `eth1`: connected to the virtual LAN via a TAP device (`tap0-qi-cs536`).
```bash
sudo qemu-system-x86_64 \
    -m 4G \                               			# Allocate 4GB memory
    -smp 4 \                              			# Use 4 virtual CPUs
    -kernel linux-5.12.12/arch/x86/boot/bzImage \ 
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \ 
    -drive file=vm-router/bullseye.img,format=raw \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:17021-:22,hostfwd=tcp:127.0.0.1:50017-:50017 \  # User-mode networking with ssh port forwarding
    -device e1000,netdev=net0,mac=52:54:00:12:34:57 \  						# Connect net0 to a virtual NIC (eth0)
    -netdev tap,id=net1,ifname=tap0-xrouter,script=no,downscript=no \  			# Bridge to TAP for LAN (eth1)
    -device e1000,netdev=net1,mac=52:54:00:12:34:58 \  						# Connect net1 to another virtual NIC (eth1)
    -enable-kvm \
    -nographic \
    -virtfs local,path=/path/to/xrouter,mount_tag=hostshare,security_model=passthrough,id=hostshare \ 		# Share host folder
    -pidfile vm-router/vm.pid \          # Store the PID of the VM
    2>&1 | tee vm-router/vm.log          # Log output
```

Once the VM is booted, connect via SSH using the forwarded port:
```bash
ssh -i vm-router/bullseye.id_rsa -p 17021 root@localhost
```

Install some necessary packages:
```bash
apt update
apt-get update
apt install snapd -y
apt install build-essential -y
apt install net-tools -y
```

Enable the second interface (eth1, local network) and assign it a static IP:
```bash
ip link set eth1 up
ip addr add 192.168.20.1/24 dev eth1
```

Mount the shared directory passed in via `-virtfs` so you can access the host project files from the VM:
```bash
mkdir /mnt/hostshare
mount -t 9p -o trans=virtio hostshare /mnt/hostshare
ln -s /mnt/hostshare /root/xrouter
```

Run the DHCP server and the NAT router, as instructed in the main `README.md` at project root.


### Start host-1
Do the same for host-1:
```bash
# Start host
sudo qemu-system-x86_64 \
    -m 4G \
    -smp 4 \
    -kernel linux-5.12.12/arch/x86/boot/bzImage \
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
    -drive file=vm-host1/bullseye.img,format=raw \
    -netdev tap,id=net0,ifname=tap1-xrouter,script=no,downscript=no \
    -device e1000,netdev=net0,mac=52:54:00:12:34:59 \
    -netdev user,id=net1,hostfwd=tcp:127.0.0.1:17022-:22 \
    -device e1000,netdev=net1,mac=52:54:00:12:34:60 \
    -enable-kvm \
    -nographic \
    -virtfs local,path=/path/to/xrouter,mount_tag=hostshare,security_model=passthrough,id=hostshare \
    -pidfile vm-host1/vm.pid \
    2>&1 | tee vm-host1/vm.log

# Setup the second interface, for ssh port forwardhing
ip link set eth1 up
dhclient eth1

# SSH into host-1 and configure
ssh -i vm-host1/bullseye.id_rsa -p 17022 root@localhost
apt update
apt-get update
apt install snapd -y
apt install build-essential -y
apt install net-tools -y

# Mount the shared directory
mkdir /mnt/hostshare
mount -t 9p -o trans=virtio hostshare /mnt/hostshare
ln -s /mnt/hostshare /root/xrouter
```

### Start host-2
Do the same for host-2:
```bash
# Start host
sudo qemu-system-x86_64 \
    -m 4G \
    -smp 4 \
    -kernel linux-5.12.12/arch/x86/boot/bzImage \
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
    -drive file=vm-host2/bullseye.img,format=raw \
    -netdev tap,id=net0,ifname=tap2-xrouter,script=no,downscript=no \
    -device e1000,netdev=net0,mac=52:54:00:12:34:61 \
    -netdev user,id=net1,hostfwd=tcp:127.0.0.1:17023-:22 \
    -device e1000,netdev=net1,mac=52:54:00:12:34:62 \
    -enable-kvm \
    -nographic \
    -virtfs local,path=/path/to/xrouter,mount_tag=hostshare,security_model=passthrough,id=hostshare \
    -pidfile vm-host2/vm.pid \
    2>&1 | tee vm-host2/vm.log

# Setup the second interface, for ssh port forwardhing
ip link set eth1 up
dhclient eth1

# SSH into host-2 and configure
ssh -i vm-host1/bullseye.id_rsa -p 17023 root@localhost
apt update
apt-get update
apt install snapd -y
apt install build-essential -y
apt install net-tools -y

# Mount the shared directory
mkdir /mnt/hostshare
mount -t 9p -o trans=virtio hostshare /mnt/hostshare
ln -s /mnt/hostshare /root/xrouter
```

