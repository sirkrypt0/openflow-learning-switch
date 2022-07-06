# -*- coding: utf-8 -*-

"""
Ryu Tutorial Controller

This controller allows OpenFlow datapaths to act as Ethernet Hubs. Using the
tutorial you should convert this to a layer 2 learning switch.

See the README for more...
"""

from ryu.base.app_manager import RyuApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import stplib
from ryu.lib.packet import packet, ethernet


class Controller(RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # By setting _CONTEXTS, we can receive instances via the kwargs argument in __init__
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)

        # Stores the mapping from destination mac to outgoing switch port
        self.mac_port_mapping = dict()
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
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        pkt = packet.Packet(data)

        actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        # Only learn MAC address, if packet has an ethernet header
        if eth_header := pkt.get_protocol(ethernet.ethernet):
            src = eth_header.src
            dst = eth_header.dst
            self.logger.debug("{}: Packet from {} on port {} to {}".format(dpid, src, in_port, dst))

            # "Learn" port for src MAC address
            self.mac_port_mapping.setdefault(dpid, {})
            self.mac_port_mapping[dpid][src] = in_port
            self.logger.info("{}: {} is at port {}".format(dpid, src, in_port))

            if dst in self.mac_port_mapping[dpid]:
                # Outport is known -> send to outport
                out_port = self.mac_port_mapping[dpid][dst]
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                self.logger.debug("{}: {} is at port {} -> port out".format(dpid, dst, out_port))

                # Make switch process packets to src on its own in the future
                # We can't add the flow entry above when learning the src MAC address.
                # If we would add the entry there, we wouldn't be able to learn where to send the
                # request to, as the response would be handled by the switch on its own.
                self.__add_flow(
                    datapath,
                    10,
                    parser.OFPMatch(eth_dst=dst),
                    [datapath.ofproto_parser.OFPActionOutput(out_port)],
                    timeout=10,
                )
            else:
                # Outport is unknown -> flood
                self.logger.debug("{}: {} is at unknown port -> flood".format(dpid, dst))

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