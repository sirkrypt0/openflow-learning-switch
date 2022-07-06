from mininet.topo import Topo
from mininet.link import TCLink


class TutorialTopology(Topo):

    def build(self):

        # Add the central switch
        s1 = self.addSwitch('s1')

        # connect n hosts to the switch
        hosts = []
        for h in range(0, 5):
            hosts.append(self.addHost("h{}".format(h+1)))
            self.addLink(s1, hosts[h], cls=TCLink, bw=40, delay='15ms')


class TutorialTopologyAdvanced(Topo):

    def build(self):
        # Add left switch
        s1 = self.addSwitch('s1')

        # Add right switch
        s2 = self.addSwitch('s2')
        self.addLink(s1, s2)

        # connect n*2 hosts to the switches
        hosts_per_switch = 3
        hosts = []
        for h in range(0, hosts_per_switch*2, 2):
            hosts.append(self.addHost("h{}".format(h+1)))
            hosts.append(self.addHost("h{}".format(h+2)))
            self.addLink(s1, hosts[h], cls=TCLink, bw=40, delay='15ms')
            self.addLink(s2, hosts[h+1], cls=TCLink, bw=80, delay='35ms')


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
# note: if using the Dockerfile, this must be the same as in the Dockerfile
topos = {
    'tutorialTopology': (lambda: TutorialTopology()),
    'tutorialTopologyAdvanced': (lambda: TutorialTopologyAdvanced()),
    'ringTopology': (lambda: RingTopology()),
}
