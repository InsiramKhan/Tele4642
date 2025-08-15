from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, ether_types, icmp, tcp, udp
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

import time
import json
import networkx as nx
import numpy as np

# Import the classify_flow function from model_engine.
# NOTE: We'll now use a rule-based flood detection before calling this function.
from model_engine import classify_flow

# --- CONFIGURATION FOR FLOOD DETECTION ---
# Threshold for the number of packets from a single source IP in the time window.
PACKET_THRESHOLD = 1000
# Time window in seconds to check for a packet flood.
TIME_WINDOW = 200
# ----------------------------------------


class SimpleSwitchRouting(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchRouting, self).__init__(*args, **kwargs)
        self.topology = nx.DiGraph()
        self.mac_to_port = {}
        self.arp_table = {}
        self.switches = set()
        self.ip_to_mac = {}
        self.ip_to_port = {}
        self.blocked_flows = []
        
        # New dictionaries for flood detection
        self.ip_packet_counters = {}
        self.ip_last_reset_time = {}
        
        # Load MUD policy   
        with open("mud_policy.json", "r") as f:
            self.mud_policy = json.load(f)
        
        # Register the MUD REST API controller
        wsgi = kwargs['wsgi']
        wsgi.register(MudRestController, {'mud_controller': self})
        
        # Initialize trust graph and scores
        self.trust_graph = nx.DiGraph()
        self.trust_scores = {}
        

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
     
    
    # Handle ARP packets
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
        
        # Always install ARP flow rule for this switch
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, priority=1, match=match, actions=actions)

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
            
                actions = [parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                    data=arp_reply.data
                )
                datapath.send_msg(out)
                self.logger.info(f"ARP Reply: {src_ip} is at {src_mac}, sent to {dst_ip} at {dst_mac}")
            else:
                self.logger.info(f"ARP Request: {src_ip} is asking for {dst_ip}, but no entry found in ARP table.")
        elif pkt_arp.opcode == arp.ARP_REPLY:
            self.logger.info(f"ARP Reply: {src_ip} is at {src_mac}, sent to {dst_ip} at {pkt_arp.dst_mac}")
        else:
            self.logger.warning(f"Unknown ARP opcode: {pkt_arp.opcode} from {src_ip} to {dst_ip}")  
        
                
    # Handle incoming packets
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
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        # Ignore LLDP
        if eth.ethertype == 0x88cc:
            return

        # Handle ARP normally
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            src_mac = arp_pkt.src_mac
            dst_mac = arp_pkt.dst_mac
            self.mac_to_port.setdefault(dpid, {})[src_mac] = in_port

            out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]

            match = parser.OFPMatch(eth_type=0x0806, eth_src=src_mac, eth_dst=dst_mac)
            self.add_flow(datapath, 1, match, actions)

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            datapath.send_msg(out)
            return

        # Handle IP and ML
        
        src_ip = dst_ip = "non_ip"
        src_port = dst_port = 0
        proto = 0

        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            proto = ip_pkt.proto

        if tcp_pkt:
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
            proto = 6
        elif udp_pkt:
            src_port = udp_pkt.src_port
            dst_port = udp_pkt.dst_port
            proto = 17

        flow_features = {
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "pkt_len": len(msg.data)
        }


        if src_ip == "non_ip" or dst_ip == "non_ip":
            self.logger.info(f"[SKIP] Non-IP packet skipped: proto={proto}, pkt_len={len(msg.data)}")
            return
            
        # --- NEW FLOOD DETECTION LOGIC ---
        current_time = time.time()
        
        # Reset counter if the time window has passed
        if src_ip not in self.ip_last_reset_time or (current_time - self.ip_last_reset_time[src_ip]) > TIME_WINDOW:
            self.ip_packet_counters[src_ip] = 0
            self.ip_last_reset_time[src_ip] = current_time

        # Increment packet counter
        self.ip_packet_counters[src_ip] += 1
        
        # Check if the counter exceeds the threshold
        if self.ip_packet_counters[src_ip] > PACKET_THRESHOLD:
            self.logger.warning(f"[FLOOD DETECTED] Blocking {src_ip} due to high packet rate ({self.ip_packet_counters[src_ip]} packets in {TIME_WINDOW}s)")
            
            # Install a flow rule to block all future traffic from this IP
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            self.add_flow(datapath, 20, match, [])
            
            self.blocked_flows.append({
                                        "timestamp": time.time(),
                                        "src": src_ip,
                                        "dst": dst_ip,
                                        "reason": "blocked"
                                    })
            # Log the decision and return
            with open("flow_log.csv", "a", newline="") as f:
                f.write(f"{current_time},{src_ip},{dst_ip},{proto},{len(msg.data)},{src_port},{dst_port},malicious,blocked\n")
            return
        # --- END OF NEW FLOOD DETECTION LOGIC ---
            
        # MUD policy enforcement
        allowed = self.mud_policy.get(src_ip, [])
        mud_decision = "allowed"

        # MUD policy check should apply to all relevant protocols (e.g., 6, 17, and 1 for ICMP)
        if proto in [6, 17, 1]:
            if dst_ip not in allowed:
                self.logger.warning(f"[MUD BLOCKED] {src_ip} -> {dst_ip} (No Rules Found)")
                mud_decision = "blocked"
                
                match = parser.OFPMatch(
                    eth_type=0x0800,  # IPv4
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip
                )
                self.add_flow(datapath, 10, match, [])
                self.blocked_flows.append({
                                        "timestamp": time.time(),
                                        "src": src_ip,
                                        "dst": dst_ip,
                                        "reason": "blocked"
                                    })
                
                with open("flow_log.csv", "a", newline="") as f:
                    #flow_decision == "malicious"
                    f.write(f"{time.time()},{src_ip},{dst_ip},{proto},{len(msg.data)},{src_port},{dst_port},malicious,{mud_decision}\n")
                return

        # ML Classification for flows allowed by MUD
        flow_decision = classify_flow(flow_features)
        self.logger.info(f"[ML DEBUG] Flow {src_ip} -> {dst_ip} | Features: {flow_features} | Result: {flow_decision}")

        # Block flow if ML model predicts it's malicious
        if flow_decision == "malicious":
            self.logger.warning(f"[ML BLOCKED] Predicted malicious flow: {src_ip} -> {dst_ip}")
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip
            )
            self.add_flow(datapath, 10, match, [])
            self.blocked_flows.append({
                            "timestamp": time.time(),
                            "src": src_ip,
                            "dst": dst_ip,
                            "reason": "blocked"
                        })
            
            mud_decision = "blocked"
            with open("flow_log.csv", "a", newline="") as f:
                f.write(f"{time.time()},{src_ip},{dst_ip},{proto},{len(msg.data)},{src_port},{dst_port},{flow_decision},{mud_decision}\n")
            return

        # If the flow passes all checks, log it and proceed with normal forwarding
        with open("flow_log.csv", "a", newline="") as f:
            f.write(f"{time.time()},{src_ip},{dst_ip},{proto},{len(msg.data)},{src_port},{dst_port},{flow_decision},{mud_decision}\n")


        # Learn MAC
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # Determine output port
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]


        self.trust_graph.add_edge(src_ip, dst_ip)

        # Recalculate trust scores every 20 flows
        if self.trust_graph.number_of_edges() % 20 == 0:
            self.trust_scores = nx.pagerank(self.trust_graph)
            self.logger.info(" Updated Trust Scores (PageRank):")
            for host, score in sorted(self.trust_scores.items(), key=lambda x: -x[1]):
                self.logger.info(f"{host} -> Trust Score: {score:.4f}")

        with open("trust_scores.csv", "a") as f:
            for ip, score in self.trust_scores.items():
                f.write(f"{time.time()},{ip},{score}\n")
            
        # Flood or install flow
        out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)


# Mud REST API Controller
class MudRestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(MudRestController, self).__init__(req, link, data, **config)
        self.controller = data['mud_controller']

    @route('mud', '/mud/blocked', methods=['GET'])
    def get_blocked_flows(self, req, **kwargs):
        body = json.dumps(self.blocked_flows, indent=2)
        return Response(content_type='application/json; charset=utf-8',body=body.encode('utf-8'))
    
    @route('trust', '/api/trust', methods=['GET'])
    def get_trust(self, req, **kwargs):
        body = json.dumps(self.trust_scores, indent=2)
        return Response(content_type='application/json; charset=utf-8',body=body.encode('utf-8'))