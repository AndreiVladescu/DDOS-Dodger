from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def setup():
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink, autoSetMacs=True)

    info('*** Adding controller\n')
    # Configure the remote controller with the specified IP address
    net.addController('c0', controller=RemoteController, ip='172.16.0.200', port=6633)

    info('*** Adding hosts\n')
    server = net.addHost('server', ip='10.0.0.1')
    client = net.addHost('client', ip='10.0.0.2')

    info('*** Adding switch\n')
    switch1 = net.addSwitch('s1', protocols='OpenFlow10')
    switch2 = net.addSwitch('s2', protocols='OpenFlow10')

    info('*** Creating links\n')
    net.addLink(server, switch1)
    net.addLink(switch1, switch2)
    net.addLink(switch2, client)

    info('*** Starting network\n')
    net.start()

    info('*** Configuring the server to run the web server script\n')
    server.cmd('python3 web_server.py &')

    info('*** Configuring the client to run the web client script\n')
    client.cmd('python3 web_client.py &')

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    setup()
