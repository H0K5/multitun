#!/usr/bin/env python2

# multitun v0.9
#
# Joshua Davis (multitun -*- covert.codes)
# http://covert.codes
# Copyright(C) 2014
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import dpkt
import logging
import struct
import sys
from ast import literal_eval
from autobahn.twisted.websocket import WebSocketServerFactory
from autobahn.twisted.websocket import WebSocketServerProtocol
from autobahn.twisted.websocket import WebSocketClientFactory
from autobahn.twisted.websocket import WebSocketClientProtocol
from autobahn.twisted.resource import WebSocketResource
from iniparse import INIConfig
from pytun import TunTapDevice, IFF_TUN, IFF_NO_PI
from socket import inet_ntoa, inet_aton
from twisted.internet import protocol, reactor
from twisted.web.server import Site
from twisted.web.static import File
from twisted.python import log
from mtcrypt.mtcrypt import *

MT_VERSION= "v0.9"
CONF_FILE = "multitun.conf"
ERR = -1


class WSServerFactory(WebSocketServerFactory):
    """WebSocket client protocol callbacks"""

    def __init__(self, path, debug, debugCodePaths=False):
        WebSocketServerFactory.__init__(self, path, debug=debug, debugCodePaths=False)

        # Holds currently connected clients
        self.clients = dict()


    def tunnel_write(self, data):
        """Server: receive data from tunnel"""
        taddr = inet_ntoa(dpkt.ip.IP(data)['dst'])
        try:
            dst_proto = self.clients[taddr]
        except:
            return

        try:
            dst_proto.tunnel_write(data)
        except:
            log.msg("Couldn't reach the client over the WebSocket.", logLevel=logging.INFO)


    def register(self, taddr, proto):
        # return False if desired TUN addr already in use
        if taddr in self.clients:
            return False

        self.clients[taddr] = proto


    def unregister(self, proto):
        for c in self.clients:
            if self.clients[c] == proto:
                self.clients.pop(c, None)
                break


class WSServerProto(WebSocketServerProtocol):
    """WebSocket server protocol callbacks"""

    def onConnect(self, response):
        log.msg("WebSocket connected", logLevel=logging.INFO)


    def onOpen(self):
        log.msg("WebSocket opened", logLevel=logging.INFO)
        self.mtcrypt = MTCrypt(is_server=True)
        self.factory.proto = self
        self.mtcrypt.proto = self


    def onClose(self, wasClean, code, reason):
        self.factory.unregister(self)
        log.msg("WebSocket closed", logLevel=logging.INFO)


    def onMessage(self, data, isBinary):
        """Get data from the server WebSocket, send to the TUN"""
        data = self.mtcrypt.decrypt(data)
        if data == None:
            return

        try:
            self.factory.tun.doWrite(data)
        except:
            log.msg("Error writing to TUN", logLevel=logging.INFO)


    def connectionLost(self, reason):
        WebSocketServerProtocol.connectionLost(self, reason)


    def tunnel_write(self, data):
        """Server: TUN sends data through WebSocket to client"""
        data = self.mtcrypt.encrypt(data)
        self.sendMessage(data, isBinary=True)


class WSClientFactory(WebSocketClientFactory):
    def __init__(self, path, debug, debugCodePaths=False):
        WebSocketClientFactory.__init__(self, path, debug=debug, debugCodePaths=False)


    def tunnel_write(self, data):
        """WS Client: Received data from TUN"""
        try:
            self.proto.tunnel_write(data)
        except:
            log.msg("Couldn't reach the server over the WebSocket", logLevel=logging.INFO)


class WSClientProto(WebSocketClientProtocol):
    """WS client: WebSocket client protocol callbacks"""

    def onConnect(self, response):
        log.msg("WebSocket connected", logLevel=logging.INFO)


    def onOpen(self):
        log.msg("WebSocket opened", logLevel=logging.INFO)
        self.mtcrypt = MTCrypt(is_server=False)
        self.factory.proto = self
        self.mtcrypt.proto = self
        

    def onClose(self, wasClean, code, reason):
        log.msg("WebSocket closed", logLevel=logging.INFO)
        

    def onMessage(self, data, isBinary):
        """Client: Received data from WS, decrypt and send to TUN"""
        data = self.mtcrypt.decrypt(data)
        if data == None:
            return

        try:
            self.factory.tun.doWrite(data)
        except:
            log.msg("Error writing to TUN", logLevel=logging.INFO)


    def tunnel_write(self, data):
        """Client: TUN sends data through WebSocket to server"""
        data = self.mtcrypt.encrypt(data)
        self.sendMessage(data, isBinary=True)


class TUNReader(object):
    """TUN device"""

    def __init__(self, tun_dev, tun_addr, tun_remote_addr, tun_nm, tun_mtu, wsfactory):
        self.wsfactory = wsfactory

        try:
            self.tun = TunTapDevice(name=tun_dev, flags=(IFF_TUN|IFF_NO_PI))
        except:
            log.msg("Couldn't open the TUN device.  Are you root?  Is the interface already in use?", logLevel=logging.WARN)
            sys.exit(ERR)

        self.tun.addr = tun_addr
        self.addr = tun_addr # used by mtcrypt
        self.tun.dstaddr = tun_remote_addr
        self.tun.netmask = tun_nm
        self.tun.mtu = int(tun_mtu)
        self.tun.up()

        reactor.addReader(self)

        logstr = ("Opened TUN device on %s") % (self.tun.name)
        log.msg(logstr, logLevel=logging.INFO)


    def fileno(self):
        return self.tun.fileno()


    def connectionLost(self, reason):
        log.msg("Connection lost", logLevel=logging.INFO)


    def doRead(self):
        """Read from host, send to WS to be sent to distant end"""
        data = self.tun.read(self.tun.mtu)
        self.wsfactory.tunnel_write(data)

    def doWrite(self, data):
        self.tun.write(data)


    def logPrefix(self):
        return "TUNReader"


class Server(object):
    def __init__(self, serv_addr, serv_port, ws_loc, tun_dev, tun_addr, tun_client_addr, tun_nm, tun_mtu, webdir, users):
        # WebSocket
        path = "ws://"+serv_addr+":"+serv_port
        wsfactory = WSServerFactory(path, debug=False)
        wsfactory.protocol = WSServerProto
        wsfactory.users = users

        # Web server
        ws_resource = WebSocketResource(wsfactory)
        root = File(webdir)
        root.putChild(ws_loc, ws_resource)
        site = Site(root)

        # TUN device
        tun = TUNReader(tun_dev, tun_addr, tun_client_addr, tun_nm, tun_mtu, wsfactory)
        reactor.addReader(tun)
        wsfactory.tun = tun

        reactor.listenTCP(int(serv_port), site)
        reactor.run()


class Client(object):
    def __init__(self, serv_addr, serv_port, ws_loc, tun_dev, tun_addr, tun_serv_addr, tun_nm, tun_mtu, passwd):
        # WebSocket
        path = "ws://"+serv_addr+":"+serv_port+"/"+ws_loc
        wsfactory = WSClientFactory(path, debug=False)
        wsfactory.protocol = WSClientProto
        wsfactory.passwd = passwd

        # TUN device
        tun = TUNReader(tun_dev, tun_addr, tun_serv_addr, tun_nm, tun_mtu, wsfactory)
        wsfactory.tun = tun

        reactor.connectTCP(serv_addr, int(serv_port), wsfactory)
        reactor.run()


banner = """

                 | | | (_) |              
  _ __ ___  _   _| | |_ _| |_ _   _ _ __  
 | '_ ` _ \| | | | | __| | __| | | | '_ \ 
 | | | | | | |_| | | |_| | |_| |_| | | | |
 |_| |_| |_|\____|_|\__|_|\__|\____|_| |_|
"""

def main():
    server = False
    for arg in sys.argv:
        if arg == "-s":
            server = True

    print banner
    print " =============================================="
    print " Multitun " + MT_VERSION
    print " By Joshua Davis (multitun -*- covert.codes)"
    print " http://covert.codes"
    print " Copyright(C) 2014"
    print " Released under the GNU General Public License"
    print " =============================================="
    print ""

    config = INIConfig(open(CONF_FILE))

    serv_addr = config.all.serv_addr
    serv_port = config.all.serv_port
    ws_loc = config.all.ws_loc
    tun_nm = config.all.tun_nm
    tun_mtu = config.all.tun_mtu
    serv_tun_addr = config.all.serv_tun_addr

    log.startLogging(sys.stdout)
    if type(config.all.logfile) == type(str()):
        try:
            log.startLogging(open(config.all.logfile, 'a'))
        except:
            log.msg("Couldn't open logfile.  Permissions?", logLevel=logging.INFO)

    if server == True:
        users = literal_eval(config.server.users)
        if len(users) == 0:
            log.msg("No users specified in configuration file", logLevel=logging.WARN)
            sys.exit(ERR)
 
        tun_dev = config.server.tun_dev
        tun_client_addr = config.server.p2paddr
        webdir = config.server.webdir

        logstr = ("Starting multitun as a server on port %s") % (serv_port)
        log.msg(logstr, logLevel=logging.INFO)

        server = Server(serv_addr, serv_port, ws_loc, tun_dev, serv_tun_addr, tun_client_addr, tun_nm, tun_mtu, webdir, users)

    else: # server != True
        passwd = config.client.password
        if len(passwd) == 0:
            log.msg("Edit the configuration file to include a password", logLevel=logging.WARN)
            sys.exit(ERR)

        tun_dev = config.client.tun_dev
        tun_addr = config.client.tun_addr
        serv_tun_addr = config.all.serv_tun_addr

        logstr = ("Starting as client, forwarding to %s:%s") % (serv_addr, int(serv_port))
        log.msg(logstr, logLevel=logging.INFO)

        client = Client(serv_addr, serv_port, ws_loc, tun_dev, tun_addr, serv_tun_addr, tun_nm, tun_mtu, passwd)


if __name__ == "__main__":
    main()

