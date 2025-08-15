from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
import networkx as nx

class SimpleSwitchRouting(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchRouting, self).__init__(*args, **kwargs)
        self.topology = nx.DiGraph()
        self.mac_to_port = {}
        self.arp_table = {}
        self.switches = set()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    
    def handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid = datapath.id

        src_ip = pkt_arp.src_ip
        src_mac = pkt_arp.src_mac
        dst_ip = pkt_arp.dst_ip

        # Update ARP table and host port mapping
        self.ip_to_mac[src_ip] = src_mac
        self.ip_to_port.setdefault(dpid, {})[src_ip] = port

        if pkt_arp.opcode == arp.ARP_REQUEST:
            if dst_ip in self.ip_to_mac:
                dst_mac = self.ip_to_mac[dst_ip]
                out_port = port

                # Build ARP reply
                arp_reply = packet.Packet()
                arp_reply.add_protocol(ethernet.ethernet(
                    ethertype=ether_types.ETH_TYPE_ARP,
                    dst=src_mac,
                    src=dst_mac
                ))
                arp_reply.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=dst_mac,
                    src_ip=dst_ip,
                    dst_mac=src_mac,
                    dst_ip=src_ip
                ))
                arp_reply.serialize()
                
                match = parser.OFPMatch(eth_type=0x0806, eth_src=src_mac, eth_dst=dst_mac)
                actions = [parser.OFPActionOutput(port)]
                self.add_flow(datapath, priority=1, match=match, actions=actions)

                actions = [parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                    data=arp_reply.data
                )
                datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        
        # Handle ARP packets manually
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            pkt_arp = pkt.get_protocol(arp.arp)
            self.handle_arp(datapath, in_port, eth, pkt_arp)
        
        # Learn MAC address to avoid FLOOD next time
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Build topology graph (you may need to update this part based on your topology discovery)
        self.topology.add_node(dpid)

        # If destination MAC is known, compute path
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow to avoid future packet_in events
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        # Send packet out
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                 in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)
