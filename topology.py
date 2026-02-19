# topology.py (v2.1 - Corrected protocols argument)
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

def create_topology():
    net = Mininet(
        controller=None,
        switch=OVSKernelSwitch, # <--- ARGUMENT REMOVED FROM HERE
        autoSetMacs=True
    )
    # Connect to a remote Ryu controller
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Add hosts and a switch
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    
    # --- THIS IS THE CORRECTED LINE ---
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # Create links
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
   
