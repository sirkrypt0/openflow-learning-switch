from mininet.topo import Topo
from mininet.link import TCLink


class SingleSwitch(Topo):

    def build(self):
        # Add the central switch
        s1 = self.addSwitch('s1')

        # connect n hosts to the switch
        hosts_per_switch = 2
        hosts = []
        for i in range(0, hosts_per_switch):
            host = self.addHost(f'h{i}')
            hosts.append(host)
            self.addLink(s1, host, cls=TCLink)

class TwoSwitches(Topo):

    def build(self):
        # Add left switch
        s1 = self.addSwitch('s1')

        # Add right switch
        s2 = self.addSwitch('s2')
        self.addLink(s1, s2)

        # connect n*2 hosts to the switches
        hosts_per_switch = 2
        switches = [s1,s2]
        hosts = []
        for i in range(hosts_per_switch * len(switches)):
            sid = i % len(switches)
            host = self.addHost(f'h{i}')
            hosts.append(host)
            self.addLink(switches[sid], host, cls=TCLink)

class RingTopology(Topo):

    def build(self):
        # Add left switch
        s1 = self.addSwitch('s1')

        # Add right switch
        s2 = self.addSwitch('s2')
        self.addLink(s1, s2)

        # Add connecting switch
        s3 = self.addSwitch('s3')
        self.addLink(s3, s1)
        self.addLink(s3, s2)

        # connect n*2 hosts to the switches
        switches = [s1,s2,s3]
        hosts_per_switch = 2
        hosts = []
        for i in range(hosts_per_switch * len(switches)):
            sid = i % len(switches)
            host = self.addHost(f'h{i}')
            print(host)
            hosts.append(host)
            self.addLink(switches[sid], host, cls=TCLink)


# the topologies accessible to the mn tool's `--topo` flag
topos = {
    'single': (lambda: SingleSwitch()),
    'two': (lambda: TwoSwitches()),
    'ring': (lambda: RingTopology()),
}
