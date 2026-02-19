# IIDS-for-SDN (intelligent Intrusion Detection System for Software Defined Network)
This project integrates Machine Learning (Random Forest) with the Ryu SDN Controller to create a self-healing network. It detects Anomalous traffic patterns and mitigates DDoS/DoS attacks in real-time by dynamically pushing OpenFlow rules to the switch

## System Architecture
The system consists of three main layers:
1.  Data Plane (Mininet): Simulates the network topology and traffic.
2.  Control Plane (Ryu Controller):Extracts flow statistics, predicts threats, and manages flow tables.
3.  Application Plane (Flask Dashboard): Provides a REST API and a Web UI for real-time monitoring.

## Machine Learning Logic
- Algorithm:Random Forest Classifier.
- Features: - byte_count: Total bytes in a flow.
  - packet_count: Total packets in a flow.
  - duration: Age of the flow in seconds.
  - byte_rate: Calculated as byte_count / duration.
- Mitigation Strategy: If a flow is classified as 'Malicious', the controller sends a `OFPFlowMod` message with `Idle_timeout` to drop packets from the source IP for 300 seconds.

## Full Execution Steps

### 1. Prerequisites
Ensure you have Ubuntu (or a Linux-based OS) with the following installed:
- Python 3.8+
- Mininet
- Ryu Controller

### 2. Environment Setup
Clone the repository and set up a virtual environment to keep your system clean:
bash
git clone [https://github.com/Yashwanthtp-11/sdn-ids-project.git] (https://Yashwanthtp-11/sdn-ids-project.git)
cd sdn-ids-project
python3 -m venv sdn_env
source sdn_env/bin/activate
pip install ryu flask pandas scikit-learn

3. Training the Model
You must have a traffic_data.csv file. This script generates model.pkl
Bash
python train_model.py

5. Running the Project (Multi-Terminal Setup)
Terminal 1: Start the Dashboard Server
This keeps track of the logs and serves the UI

Bash
python dashboard_server.py
Terminal 2: Start the Ryu Controller
This is the "Brain" of the network

Bash
ryu-manager ids_controller.py
Terminal 3: Start the Network Topology
This creates the switches and hosts

Bash
sudo python topology.py
5. Testing Mitigation
In the Mininet CLI (Terminal 3), simulate an attack from Host 1 to Host 2:

Bash
mininet> h1 hping3 --flood --udp -p 80 h2
