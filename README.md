# OpenFlow Learning Controller

This is a simple implementation of an OpenFlow controller using [Ryu](https://ryu-sdn.org).

It provides the following features:

- Learn MAC/port mappings for multiple datapaths
- Add flows to datapaths to automate forwarding on the datapath level and avoid sending packets to the controller
- Loop-free networking powered by [Ryu STP](https://osrg.github.io/ryu-book/en/html/spanning_tree.html)
- ARP responder implemented in the controller to reduce the overall broadcast traffic

## Usage

1. Make sure to have `ryu` installed. You can use `pipenv` to create an isolated Python environment if you wish.
1. Run `ryu-controller ./controller.py`

### Mininet

We provide some topologies in the [`topology.py`](./topology.py) file that can be used with [mininet](https://github.com/mininet/mininet).

```bash
sudo mn --switch ovsk --controller remote --custom ./topology.py --topo ring
```

### Virtual Machine

I found the [SCC365 virtual machine](https://github.com/scc365/virtual-machine) that can be started via `vagrant` to be very useful, as it contains all the tools required.
However, you can surely use the official [mininet VM](http://mininet.org/vm-setup-notes/).

## Notes

Due to the STP protocol being used, it takes some time until the network is fully response, so make sure to wait a little.

### ARP responder

Currently, the ARP responding logic will generate the answers to ARP requests based on the controllers cache.
This sacrifices some speed, as ARP requests must be send to the controller, which generates a response and sends it back to the datapath.
Ideally, we would install a flow in the datapath that generates the correct reply for us.
However, we'd like to use the OpenFlow copy action for these flows, which are available only from OpenFlow version 1.5 on.
Sadly, this collides with the Ryu STP implementation, which only supports OpenFlow up to version 1.3.
Nevertheless, a possible implementation using flows in OpenFlow 1.5 can be found in the `__learn_arp_1_5` function in the `controller.py`.

## Resources

- [SCC365 Ryu Tutorial](https://github.com/scc365/tutorial-ryu)
- [SCC365 Network Testing Guide](https://github.com/scc365/guide-network-testing)
- [SCC365 Virtual Machine](https://github.com/scc365/virtual-machine)
- [Ryu Docs](https://ryu.readthedocs.io/en/latest/)
- [Ryu Book](https://osrg.github.io/ryu-book/en/html/index.html)
