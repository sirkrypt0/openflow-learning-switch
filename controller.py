# -*- coding: utf-8 -*-

"""
Ryu Tutorial Controller

This controller allows OpenFlow datapaths to act as Ethernet Hubs. Using the
tutorial you should convert this to a layer 2 learning switch.

See the README for more...
"""

from ryu.base.app_manager import RyuApp
from ryu.controller import ofp_event
from ryu.controller.controller import Datapath
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import stplib
from ryu.lib.packet import packet, ethernet, arp


class Controller(RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # By setting _CONTEXTS, we can receive instances via the kwargs argument in __init__
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)

        # Stores the mapping from destination mac to outgoing switch port
        self.mac_port_mapping = dict()
        self.arp_table = dict()
        self.stplib = kwargs['stplib']

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        '''Handshake: Features Request Response Handler

        Installs a low level (0) flow table modification that pushes packets to
        the controller. This acts as a rule for flow-table misses.
        '''
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("Handshake taken place with {}".format(datapath.id))

        self.__add_flow(
            datapath,
            0,
            # Match all packets
            parser.OFPMatch(),
            # Send packet to controller
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)],
        )

    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''Packet In Event Handler

        Takes packets provided by the OpenFlow packet in event structure and
        learns from the packet information where following packets belong to.
        If the destination for a packet is known to the controller, it installs
        a corresponding flow table rule to let the switches handle similar packets
        on their own in the future.
        '''
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        pkt = packet.Packet(data)

        actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        # Only learn MAC address, if packet has an ethernet header
        if eth_header := pkt.get_protocol(ethernet.ethernet):
            out_port = self.__learn_mac_port(eth_header, in_port, datapath)
            actions = [parser.OFPActionOutput(out_port)]

            if arp_header := pkt.get_protocol(arp.arp):
                arp_data = self.__learn_arp(eth_header, arp_header, datapath)
                if arp_data is not None:
                    actions = [parser.OFPActionOutput(in_port)]
                    in_port = ofproto.OFPP_CONTROLLER
                    data = arp_data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        self.logger.info("Sending packet out")
        datapath.send_msg(out)

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def topology_change_handler(self, ev):
        '''STP Topology Changed Handler

        Handles topology changes detected by the stplib and flushes the MAC
        port mapping table accordingly.
        '''
        dp = ev.dp
        self.logger.info("{}: Topology changed, flushing MAC table".format(dp.id))

        if dp.id in self.mac_port_mapping:
            self.__delete_mac_flows(dp)
            del self.mac_port_mapping[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def port_state_change_handler(self, ev):
        '''Handle changes to a ports STP state'''
        self.logger.info("STP {}: {} -> {}".format(ev.dp.id, ev.port_no, ev.port_state))

    def __add_flow(self, datapath, priority, match, actions, timeout=0):
        '''Install Flow Table Modification

        Takes a set of OpenFlow Actions and a OpenFlow Packet Match and creates
        the corresponding Flow-Mod. This is then installed to a given datapath
        at a given priority.
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=timeout)
        self.logger.info("Flow-Mod written to {}".format(datapath.id))
        datapath.send_msg(mod)

    def __delete_mac_flows(self, datapath):
        '''Delete all stored MAC-Port mapping flows for a datapath.'''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_port_mapping[datapath.id].keys():
            # Match the destination we stored in the mapping
            match = parser.OFPMatch(eth_dst=dst)
            # Remove all flows for the datapath that match the MAC we stored
            mod = parser.OFPFlowMod(
                datapath,
                command=ofproto.OFPFC_DELETE,
                # Use any outgoing port, in case the controllers mapping changed in between
                out_port=ofproto.OFPP_ANY,
                match=match,
            )
            datapath.send_msg(mod)

    def __learn_mac_port(self, eth_header: ethernet.ethernet, src_port: int, datapath: Datapath):
        src_mac = eth_header.src
        dst_mac = eth_header.dst
        dpid = datapath.id
        self.logger.debug("{}: Packet from {} on port {} to {}".format(dpid, src_mac, src_port, dst_mac))

        # "Learn" port for src MAC address
        self.mac_port_mapping.setdefault(dpid, {})
        self.mac_port_mapping[dpid][src_mac] = src_port
        self.logger.info("{}: {} is at port {}".format(dpid, src_mac, src_port))

        if dst_mac in self.mac_port_mapping[dpid]:
            # Outport is known -> send to outport
            out_port = self.mac_port_mapping[dpid][dst_mac]
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.logger.debug("{}: {} is at port {} -> port out".format(dpid, dst_mac, out_port))

            # Make switch process packets to src on its own in the future
            # We can't add the flow entry above when learning the src MAC address.
            # If we would add the entry there, we wouldn't be able to learn where to send the
            # request to, as the response would be handled by the switch on its own.
            self.__add_flow(
                datapath,
                10,
                datapath.ofproto_parser.OFPMatch(eth_dst=dst_mac),
                actions,
                timeout=10,
            )
            return out_port
        else:
            # Outport is unknown -> flood
            self.logger.debug("{}: {} is at unknown port -> flood".format(dpid, dst_mac))
            return datapath.ofproto.OFPP_FLOOD

    def __learn_arp(self, eth_header: ethernet.ethernet, arp_header: arp.arp, datapath: Datapath):
        self.logger.info("Got ARP packet: {}".format(arp_header))

        self.arp_table[arp_header.src_ip] = arp_header.src_mac

        # If it's not a request (e.g. a gratitious ARP), nothing more to do
        if arp_header.opcode != arp.ARP_REQUEST:
            self.logger.info("ARP is not request, ignoring ...")
            return None

        dst_ip = arp_header.dst_ip

        # If we haven't seen the destination yet, nothing more to do
        if dst_ip not in self.arp_table:
            self.logger.info("Destination is not known, ignoring ...")
            return None

        # Fetch stored destination MAC
        dst_mac = self.arp_table[dst_ip]

        # Build ARP reply packet
        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(
                ethertype=eth_header.ethertype,
                dst=eth_header.src,
                src=dst_mac,
        ))
        pkt.add_protocol(
            arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=dst_mac,
                src_ip=arp_header.dst_ip,
                dst_mac=arp_header.src_mac,
                dst_ip=arp_header.src_ip
        ))
        pkt.serialize()
        self.logger.info("Using cached ARP response: {}".format(pkt))
        return pkt.data

    def __learn_arp_1_5(self, header: arp.arp, datapath: Datapath):
        '''Learn MAC/IP mappings based on ARP packets and install responder flow.

        Learns the MAC/IP mappings based on ARP packets. The learning is done by
        installing a flow to the datapath that transforms the incoming packet
        such that it represents the ARP response.

        Since this uses the OFPActionCopyField, this method only works from OpenFlow
        version 1.5.
        '''
        self.logger.info("Got ARP packet: {}".format(header))
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(arp_tpa=header.src_ip)
        actions = [
            datapath.ofproto_parser.OFPActionSetField(
                arp_op=arp.ARP_REPLY,
                arp_spa=header.src_ip,
                arp_sha=header.src_mac,
            ),
            datapath.ofproto_parser.OFPActionCopyField(
                oxm_ids=["eth_src", "eth_dst"],
            ),
        ]
        self.__add_flow(
            datapath,
            20,
            match,
            actions,
            60
        )
