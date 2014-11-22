Multitun v0.5 -- 'Tunnel all the things!'

Joshua Davis (multitun -!- covert.codes)  
http://covert.codes  
Copyright(C) 2014, Joshua Davis  
Released under the GNU General Public License  


Introduction
============

Efficiently and securely tunnel everything over a harmless looking WebSocket!

Multitun tunnels IPv4 over a WebSocket (RFC 6455), allowing bulk tunneling
through one connection on, for example, port 80.  One use for this is to
bypass firewalls by having a multitun server listening on a host outside
the firewall, and using a multitun client on the host behind the firewall.
Firewalls that allow web and HTML5 are assumed to allow WebSockets as well.

Multitun uses encryption with a password.  Only users with the correct
password can use the tunnel.  Multitun may be used in conjunction with other
common tools to enable port forwarding and masquerading (see the Examples
section below), and thus route arbitrary or all client traffic securely
through the Multitun server.

Multitun provides a simple web server to serve HTML to connecting clients that
don't know about or aren't using the WebSocket tunnel.


Installation
============

* Designed under Linux, with Python 2.7.

* You will need to install python-devel (aka python-dev) and pip for python 2.7

* You will need to pip (pip2, pip2.7) install the following packages:
	python-pytun, iniparse, twisted, autobahn, dpkt-fix, pycrypto

* Tested in Fedora/CentOS, Arch, Ubuntu


Usage
=====

* Edit the configuration files on both the server and client sides

* Run multitun -s to start the server, run multitun without options
  to start the client

* The program must have permission to use low port numbers, the TUN
  interface, and raw sockets (e.g. run as root)

* Make sure on the server side that the listen port is allowed through
  the host and network firewalls

* Adjust the webdir parameter in multitun.conf to specify the directory
  containing HTML to serve browsers who access the server without WS.

* Works with one client at a time (new authorized clients will bump off
  the existing client)


Configuration
=============

* Configuration is straightforward.  Here is an example multitun.conf:

	[all]  
	serv_addr = 192.168.2.1  
	serv_port = 80  
	ws_loc = mt  
	tun_nm = 255.255.255.0  
	tun_mtu = 1500  
	log_file = /var/log/multitun  
	password = secret  

	[server]  
	tun_dev = tun1  
	tun_addr = 10.10.0.1  
	webdir = ./html  

	[client]  
	tun_dev = tun0  
	tun_addr = 10.10.0.2  


Examples
========

* Simple usage, access ssh on your server using multitun:  
	server# multitun -s  
	client# multitun  
	client# ssh 10.10.0.1  


* Use Linux as a NAT gateway for your host behind the firewall:

   *Configure the server*

   * Include the following in your multitun server iptables configuration.
     In this config, eth0 is the server external interface, tun1 is the
     server multitun interface, and 10.10.0.0/255.255.255.0 is the multitun
     IP range.

    *nat  
    -A POSTROUTING -s 10.10.0.0/255.255.255.0 -o eth0 -j MASQUERADE  
    COMMIT  

    -A INPUT -s 10.10.0.0/255.255.255.0 -j ACCEPT  
    -A FORWARD -i tun1 -j ACCEPT  
    -A FORWARD -s 10.10.0.0/255.255.255.0 -j ACCEPT  
    -A FORWARD -p ALL -m state --state ESTABLISH,RELATED -j ACCEPT  

   * Enable IP forwarding:

   echo 1 > /proc/sys/net/ipv4/ip_forward

   *Configure the client*
   
   * Take care of routing:
	
    ip route add [server ext. ip] via [client gw ip] dev [client dev] proto static  
    ip route del default  
    ip route add default via [client multitun local ip] dev [client tun] proto static  


Bugs
====

* Please report bugs to me (multitun -!- covert.codes)

