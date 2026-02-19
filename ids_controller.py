# ids_controller.py (Final Version with Persistent Alerts)
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
import joblib
import pandas as pd
from ryu.lib import hub
import time
import json
import os

class IntelligentIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IntelligentIDS, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self.logger.info("Intelligent IDS Application Loading...")
        
        self.blocked_ips = set()
        
        # --- Data structure for our dashboard ---
        self.dashboard_data = {
            "traffic_stats": {"bytes_per_sec": 0},
            "alerts": [] # This list will now be persistent
        }
        self.json_path = "dashboard_data.json"
        self.last_byte_count = 0
        # --- END NEW ---

        try:
            self.model = joblib.load('model.pkl')
            self.logger.info("ML model 'model.pkl' loaded successfully.")
        except FileNotFoundError:
            self.logger.error("FATAL: 'model.pkl' not found. Run train_model.py first.")
            self.model = None
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            self.model = None

        self.collector_thread = hub.spawn(self._monitor)
        self.logger.info("Stats collection thread spawned.")
        
        self.writer_thread = hub.spawn(self._write_to_file)
        self.logger.info("Dashboard writer thread spawned.")

    def _write_to_file(self):
        """Writes the current data to the JSON file every 2 seconds"""
        while True:
            try:
                with open(self.json_path, 'w') as f:
                    json.dump(self.dashboard_data, f)
                
                # --- FIX ---
                # The line that cleared the alert list has been REMOVED.
                # self.dashboard_data["alerts"] = [] # <-- THIS LINE IS GONE
                # Alerts will now persist in the log.
                
            except Exception as e:
                self.logger.error(f"Error writing to dashboard_data.json: {e}")
            hub.sleep(2) 

    def _monitor(self):
        """Periodically requests flow statistics"""
        self.logger.info("Monitor thread started.")
        while True:
            if self.model:
                for dp_id in list(self.datapaths.keys()):
                    datapath = self.datapaths.get(dp_id)
                    if datapath:
                        try:
                            self._request_flow_stats(datapath)
                        except Exception as e:
                            self.logger.error(f"Error requesting stats for {dp_id}: {e}")
            hub.sleep(5) 

    def _request_flow_stats(self, datapath):
        self.logger.info('Sending stats request to switch %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        if not self.model:
            return

        body = ev.msg.body
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        current_total_bytes = 0
        for flow in body:
            if flow.priority >= 1: 
                current_total_bytes += flow.byte_count
        
        self.dashboard_data['traffic_stats']['bytes_per_sec'] = max(0, (current_total_bytes - self.last_byte_count)) / 5
        self.last_byte_count = current_total_bytes
        
        for flow in body:
            if flow.priority == 1 and flow.packet_count > 0:
                try:
                    ip_match = flow.match.get('ipv4_src')
                    
                    if not ip_match or ip_match in self.blocked_ips:
                        continue 

                    features = [flow.packet_count, flow.byte_count, flow.duration_sec]
                    df = pd.DataFrame([features], columns=['packet_count', 'byte_count', 'duration'])
                    prediction = self.model.predict(df)
                    
                    if prediction[0] == 1: # 1 means 'attack'
                        self.logger.warning(f"Attack [1] DETECTED! From Source IP: {ip_match}")
                        
                        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_match)
                        actions = [] # Empty actions = DROP
                        self.add_flow(datapath, 2, match, actions, idle_timeout=60)
                        self.logger.warning(f"Drop rule installed for {ip_match}.")
                        
                        self.blocked_ips.add(ip_match)
                        
                        alert = {
                            "timestamp": time.strftime("%H:%M:%S"),
                            "src_ip": ip_match,
                            "dst_ip": flow.match.get('ipv4_dst', 'N/A'),
                            "attack_type": "DDoS/DoS",
                            "action": "Blocked"
                        }
                        # Add to list, but check if it's already the most recent one
                        if not self.dashboard_data['alerts'] or self.dashboard_data['alerts'][0]['src_ip'] != alert['src_ip']:
                            self.dashboard_data['alerts'].insert(0, alert)
                            self.dashboard_data['alerts'] = self.dashboard_data['alerts'][:10] # Keep last 10

                        # Delete the flow rule that was analyzed
                        del_match = flow.match
                        del_mod = parser.OFPFlowMod(datapath=datapath,
                                                    command=ofproto.OFPFC_DELETE_STRICT,
                                                    priority=flow.priority,
                                                    match=del_match)
                        datapath.send_msg(del_mod)
                    
                    else: # 0 means 'normal'
                        # --- LOGGING RE-ENABLED ---
                        self.logger.info(f"Normal [0] detected. From Source IP: {ip_match}")
                
                except Exception as e:
                    self.logger.error(f"Error during prediction: {e}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"Switch {datapath.id} connected.")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dpid = datapath.id

        self.mac_to_port[dpid][eth.src] = in_port

        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == 0x0800: # IP Packet
                 ip_pkt = pkt.get_protocol(ipv4.ipv4)
                 if ip_pkt:
                     if ip_pkt.src in self.blocked_ips:
                         return # Drop packet if source is blocked
                         
                     match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype,
                                             ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
                     self.add_flow(datapath, 1, match, actions, idle_timeout=15)
            else: # Other packets (like ARP)
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
                self.add_flow(datapath, 1, match, actions, idle_timeout=15)
                
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)
