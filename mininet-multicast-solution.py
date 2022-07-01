#!/usr/bin/python

'''
Zazanis Georgios, georzaza@gmail.com


######################################################################
#########             M  U  L  T  I  C  A  S  T         ##############
#########             J O I N    &    L E A V E         ##############
######################################################################

For a host to join a multicast group we should run on mininet:
1) <host> smcroute -d
2) <host> smcroute -j <IFACE> <ADDRESS>

Alternatives for the commands 1) and 2) are:
1) <host> smcrouted 
2) <host> smcroutectl join <IFACE> <ADDRESS>
These alternatives are going to be used next to demonstrate the 
problem and a solution to it.

To leave a multicast group the command on mininet is:
<host> smcroutectl leave <IFACE> <ADDRESS>


            PROBLEMS
            
i)  The leave commnand only succeeds on the LAST host that
    we run the smcroute -d command. To be more clear an example follows:
    The problem lies on the command smcroute -d. 
    This command creates a new process each time it is run and it seems that 
    somehow this daemon process 'binds' to the host's interface/s it was run from.
    h1 smcroute -d
    h1 smcroute -j h1-eth1 239.0.0.1
    h2 smcroute -d 
    h2 smcroute -j h2-eth1 239.0.0.2
    h1 smcroutectl leave h1-eth1 239.0.0.1  --> FAILS with msg: "smcroutectl: unknown interface h1-eth1"
    h2 smcroutectl leave h2-eth1 239.0.0.2  --> SUCCEEDS
    
ii) smcrouted processes are NOT killed by mininet by default.


            SOLUTIONS

i)  A simple way to circumvent around this is to give an appropriate name to 
    each socket we start with smcroute -d. This can happen by passing argument -I.

    h1 smcrouted -I some-name
    h2 smcrouted -I some-other-name
    h1 smcroutectl join h1-eth1 239.0.0.1 -I some-name
    h2 smcroutectl join h2-eth1 239.0.0.2 -I some-other-name
    h1 smcroutectl leave h1-eth1 239.0.0.1 -I some-name
    h2 smcroutectl leave h2-eth1 239.0.0.2 -I some-other-name

ii) As a solution I included a Linux system command to kill any smcrouted
    processes running on the system as part of the mn clean process (line 177)


#####################################################################
#########             O T H E R    P R O B L E M S            #######
#####################################################################

Starting tcpdump on any host's interface seems to cause an issue where a host 
might start sending arp requests regarding the system's default route gateway.
These packets are not handled by the controller. Instead, to check controller's
functionality wireshark can be used, or tcpdump on switches interfaces that are
connected to the hosts. It is worth mentioning that this problem does not arise
when the computer system does not have an active Internet connection.


#####################################################################
#########             C O D E    O V E R V I E W            #########
#####################################################################

  
i)  Some extra hosts are added as comments below in order to test the 
    functionality of the controller. The extra added hosts are 2 for each switch
    s2 and s3. The last byte of their mac addresses is the hex representation of
    their number. Eg. h10 has a mac ending in :0a
                      h11 has a mac ending in :0b, etc.

    In the controller we use the above information to forward the packets. There
    is a relevant comment section in the controller src file.

ii) Lines 153, 156 and 159 if uncommented, will result in each host joining a
    multicast group based on the expression (last_byte_of_ip)mod2 + 1
    What is worth mentioning here is that the controller sometimes does not 
    receive all the igmp join packets that are executed with these lines. This 
    was mostly observed when the mininet script would run while the controller 
    had not 'completely finished' starting.
'''

import os
import subprocess
import re
from time import sleep as sleep
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController, OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.link import Intf
from mininet.util import quietRun
from mininet.log import MininetLogger

def myNet():

    CONTROLLER_IP='127.0.0.1'

    # Create network
    net = Mininet( controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)

    # Create devices 
    ## Server
    h1 = net.addHost( 'h1', ip='192.168.1.2/24', mac='00:00:00:00:01:02', defaultRoute='via 192.168.1.1' )
    h2 = net.addHost( 'h2', ip='192.168.1.3/24', mac='00:00:00:00:01:03', defaultRoute='via 192.168.1.1' )
    #h10= net.addHost('h10',ip='192.168.1.10/24', mac='00:00:00:00:01:0a', defaultRoute='via 192.168.1.1' )
    #h11= net.addHost('h11',ip='192.168.1.11/24', mac='00:00:00:00:01:0b', defaultRoute='via 192.168.1.1' )    
    h3 = net.addHost( 'h3', ip='192.168.2.2/24', mac='00:00:00:00:02:02', defaultRoute='via 192.168.2.1' )
    h4 = net.addHost( 'h4', ip='192.168.2.3/24', mac='00:00:00:00:02:03', defaultRoute='via 192.168.2.1' )
    #h20= net.addHost('h20', ip='192.168.2.20/24',mac='00:00:00:00:02:14', defaultRoute='via 192.168.2.1' )
    #h21= net.addHost('h21', ip='192.168.2.21/24',mac='00:00:00:00:02:15', defaultRoute='via 192.168.2.1' )
    
    ## Switches
    s1a = net.addSwitch( 's1a' , protocols=["OpenFlow10"], dpid='1A' )
    s1b = net.addSwitch( 's1b' , protocols=["OpenFlow10"], dpid='1B' )
    s2 = net.addSwitch( 's2' , protocols=["OpenFlow10"], dpid='2' )
    s3 = net.addSwitch( 's3' , protocols=["OpenFlow10"], dpid='3' )

    # Create links 
    net.addLink(s1a, s1b, port1=1, port2=1)
    net.addLink(s1a, s2, port1=2, port2=1)
    net.addLink(s1b, s3, port1=2, port2=1)
    net.addLink(h1, s2, port1=1, port2=2)
    net.addLink(h2, s2, port1=1, port2=3)
    net.addLink(h3, s3, port1=1, port2=2)
    net.addLink(h4, s3, port1=1, port2=3)
    #net.addLink(h10,s2, port1=1, port2=4)
    #net.addLink(h11,s2, port1=1, port2=5)
    #net.addLink(h20,s3, port1=1, port2=4)
    #net.addLink(h21,s3, port1=1, port2=5)

    # Create controllers
    c1 = net.addController( 'c1', ip=CONTROLLER_IP, port=6633)

    net.build()
    
    print("\nPlease see the comment section of this program for more info.\n")
    
    loger = MininetLogger(None, None)
    for host in net.hosts:
        host.cmd('route add -net 224.0.0.0 netmask 240.0.0.0 dev ', host.defaultIntf() )
        host.cmd("sysctl net.ipv4.icmp_echo_ignore_broadcasts=0")
        
        # start relative daemon process for each host
        host.cmd("smcrouted -I "+str(host))
        
        # join appropriate multicast groups.
        host.cmd("smcroutectl -I "+str(host)+" join "+str(host)+"-eth1 239.0.0."
                                  + str((int((host.IP()).split('.')[3])%2+1)))
                                  
        command =  "netstat -gn | grep " + str(host) + "-eth1 | "
        command += "awk '{ print substr($1, 0, 2) \" subscribed to \" $3 }' |"
        command += "grep -v : | grep -v 224.0.0.1"
        loger.output(host.cmd(command))
    
    # Start controllers and connect switches
    c1.start()
    s1a.start( [c1] )
    s1b.start( [c1] )
    s2.start( [c1] )
    s3.start( [c1] )

    CLI( net )
    
    # CLEAN UP ALL smcrouted PROCESSES ON LINUX SYSTEM
    os.system("sudo killall smcrouted")
    
    net.stop()
    subprocess.call(["mn", "-c"], stdout=None, stderr=None)    

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()

