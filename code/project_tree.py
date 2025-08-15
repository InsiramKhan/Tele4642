#!/usr/bin/env python3
"""
Fat-Tree topology generator for Mininet.
Creates a k-array fat-tree with k pods (k even),
(k^2)/4 core switches, k/2 aggregation and k/2 edge switches per pod,
and (k^3)/4 hosts in total.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, OVSController, RemoteController, OVSSwitch
from mininet.log import setLogLevel
from mininet.link import Link, TCLink
from mininet.cli import CLI

class FatTreeTopo(Topo):
    def build(self, k=4):
        pods = k  
        edge_per_pod = k // 2  
        aggr_per_pod = k // 2  

        # Core switches
        core_switches = {}  
        for j in range(1, k//2 + 1):               
            for i in range(1, k//2 + 1):    
                       
                # Name core switch as "10_k_j_i" for uniqueness (pod field = k)
                sw_name = f"10_{k}_{j}_{i}"
                
                # DPID: 00:00:00:00:00:k:j:i 
                dpid = f"0000000000{int(k):02x}{j:02x}{i:02x}"
                
                core_switches[(j, i)] = self.addSwitch(
                    sw_name, dpid=dpid, stp=True, failMode='standalone'
                )

        # Pod switches (edge and aggregation) for each pod
        pod_edge = {}  
        pod_aggr = {}  
        for pod in range(pods):
            pod_edge[pod] = []
            pod_aggr[pod] = []
            
            # Edge switches 
            for e in range(edge_per_pod):
                
                # Name edge switch as "10_pod_e_1"
                sw_name = f"10_{pod}_{e}_1"
                
                # DPID: 00:00:00:00:00:pod:edge:01
                dpid = f"0000000000{pod:02x}{e:02x}01"
                
                edge_sw = self.addSwitch(sw_name, dpid=dpid, stp=True, failMode='standalone'
                )
                
                pod_edge[pod].append(edge_sw)
                
            # Aggregation switches 
            for a in range(aggr_per_pod):
                
                pos = aggr_per_pod + a   
                sw_name = f"10_{pod}_{pos}_1"
                # DPID: 00:00:00:00:00:pod:pos:01
                dpid = f"0000000000{pod:02x}{pos:02x}01"
                aggr_sw = self.addSwitch(sw_name, dpid=dpid, stp=True, failMode='standalone'
                )
                pod_aggr[pod].append(aggr_sw)

        # Hosts and links to edge switches
        for pod in range(pods):
            for e_index, edge_sw in enumerate(pod_edge[pod]): 
                for host_id in range(2, edge_per_pod + 2):  
                    host_ip = f"10.{pod}.{e_index}.{host_id}"
                    host_name = f"h_{pod}_{e_index}_{host_id}"
                    host = self.addHost(host_name, ip=host_ip)  
                    self.addLink(host, edge_sw)  
                    
        # Links between edge and aggregation switches (intra-pod)
        for pod in range(pods):
            for edge_sw in pod_edge[pod]:
                for aggr_sw in pod_aggr[pod]:
                    self.addLink(edge_sw, aggr_sw)

        # Links between aggregation and core switches (inter-pod)
        for pod in range(pods):
            for a_idx, aggr_sw in enumerate(pod_aggr[pod]):
                core_row = a_idx + 1  
                for i in range(1, k//2 + 1):
                    core_sw = core_switches[(core_row, i)]
                    self.addLink(aggr_sw, core_sw)

# If run directly, create the network and test connectivity
if __name__ == '__main__':
    import sys
    setLogLevel('info') 
    

    # Instantiate topology and network
    topo = FatTreeTopo(k=4)
    net = Mininet(topo, link=TCLink, controller= None, autoSetMacs=True, autoStaticArp=False)
    
    net.addController('ryu', controller=RemoteController, ip='127.0.0.1', port=6633, protocols='OpenFlow13')
    
    net.start()
    print(f"Fat Tree Topology, testing connectivity")
    
    print("📡 Discovered Host IPs:")
    for host in net.hosts:
        print(f"{host.name} -> {host.IP()}")
    #net.pingAll()
    CLI(net)
    
    net.stop()
