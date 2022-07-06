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
sudo mn --switch ovsk --controller remote --custom ./topology.py --topo ringTopology
```

### Virtual Machine

I found the [SCC365 virtual machine](https://github.com/scc365/virtual-machine) that can be started via `vagrant` to be very useful, as it contains all the tools required.
However, you can surely use the official [mininet VM](http://mininet.org/vm-setup-notes/).

## Resources

- [SCC365 Ryu Tutorial](https://github.com/scc365/tutorial-ryu)
- [SCC365 Network Testing Guide](https://github.com/scc365/guide-network-testing)
- [SCC365 Virtual Machine](https://github.com/scc365/virtual-machine)
- [Ryu Docs](https://ryu.readthedocs.io/en/latest/)
- [Ryu Book](https://osrg.github.io/ryu-book/en/html/index.html)
