# data_collector.py (Revised Filter)
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.lib import hub # Use Ryu's hub for threading
import time
import csv
import traceback # For detailed error logging

class DataCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DataCollector, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self.csv_file = None
        self.csv_writer = None
        
        try:
            self.csv_file = open('mininet_traffic.csv', 'w', newline='')
            self.csv_writer = csv.writer(self.csv_file)
            self.csv_writer.writerow(['packet_count', 'byte_count', 'duration', 'label'])
            self.logger.info("CSV file 'mininet_traffic.csv' opened successfully.")
        except Exception as e:
             self.logger.error(f"FATAL: Could not open CSV file: {e}")
             self.csv_writer = None

        self.collector_thread = hub.spawn(self._monitor)
        self.logger.info("Stats collection thread spawned.")

    def _monitor(self):
        self.logger.info("Monitor thread started.")
        while True:
            datapaths_to_poll = list(self.datapaths.keys())
            for dp_id in datapaths_to_poll:
                datapath = self.datapaths.get(dp_id)
                if datapath:
                    try:
                        self._request_flow_stats(datapath)
                    except Exception as e:
                         self.logger.error(f"Error requesting stats for {dp_id}: {e}")
                         self.logger.error(traceback.format_exc())
            hub.sleep(5) # Poll every 5 seconds

    def _request_flow_stats(self, datapath):
        self.logger.info('Sending stats request to switch %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        try:
            datapath.send_msg(req)
        except Exception as e:
            self.logger.error(f"Error sending stats request to {datapath.id}: {e}")

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

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        if not self.csv_writer:
            return
            
        body = ev.msg.body
        self.logger.info(f"Received flow stats reply with {len(body)} flows.")
        
        flows_written = 0
        for flow in body:
            # --- THIS IS THE CHANGED LINE ---
            # We now log any flow with at least 1 packet.
            if flow.priority == 1 and flow.packet_count > 0:
                try:
                    self.csv_writer.writerow([
                        flow.packet_count,
                        flow.byte_count,
                        flow.duration_sec,
                        '' # Empty label
                    ])
                    flows_written += 1
                except Exception as e:
                    self.logger.error(f"Error writing flow to CSV: {e}")
        
        if flows_written > 0:
            self.logger.info(f"Wrote {flows_written} flows to CSV.")
            try:
                self.csv_file.flush()
            except Exception as e:
                 self.logger.error(f"Error flushing CSV file: {e}")

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
            match = parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst)
            if eth.ethertype == 0x0800:
                self.add_flow(datapath, 1, match, actions, idle_timeout=15)
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)
