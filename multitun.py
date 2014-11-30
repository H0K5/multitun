#!/usr/bin/env python2

# multitun v0.6
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
import socket
import streql
import struct
import sys
from autobahn.twisted.websocket import WebSocketServerFactory
from autobahn.twisted.websocket import WebSocketServerProtocol
from autobahn.twisted.websocket import WebSocketClientFactory
from autobahn.twisted.websocket import WebSocketClientProtocol
from autobahn.twisted.resource import WebSocketResource
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA384
from Crypto import Random
from iniparse import INIConfig
from pytun import TunTapDevice, IFF_TUN, IFF_NO_PI
from twisted.internet import protocol, reactor
from twisted.web.server import Site
from twisted.web.static import File
from twisted.python import log

configfile = "multitun.conf"

MT_VERSION= "v0.6"
EXIT_ERR = -1

AES_KEYLEN = 32
TAG_KEYLEN = 48
TAG_LEN = TAG_KEYLEN


class WSServerFactory(WebSocketServerFactory):
    """WebSocket client protocol callbacks"""

    def __init__(self, path, debug, debugCodePaths=False):
        WebSocketServerFactory.__init__(self, path, debug=debug, debugCodePaths=False)

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except:
            log.msg("Could not create raw socket", logLevel=logging.WARN)
            reactor.stop()
        

    def tunnel_write(self, data):
        """Server: receive data from tunnel"""
        try:
            self.proto.tunnel_write(data)
        except:
            log.msg("Couldn't reach the client over the WebSocket.", logLevel=logging.WARN)


class WSServerProto(WebSocketServerProtocol):
    """WebSocket server protocol callbacks"""

    def onConnect(self, response):
        log.msg("WebSocket connected", logLevel=logging.INFO)


    def onOpen(self):
        self.factory.proto = self
        self.mtcrypt = MTCrypt(self.factory.passwd, self.factory.server)
        self.mtcrypt.proto = self
        log.msg("WebSocket opened", logLevel=logging.INFO)


    def onClose(self, wasClean, code, reason):
        log.msg("WebSocket closed", logLevel=logging.WARN)


    def onMessage(self, data, isBinary):
        """Get data from the server WebSocket, send to the TUN"""
        data = self.mtcrypt.decrypt(data)
        if data == None:
            return

        try:
            self.factory.tun.tun.write(data)
        except:
            log.msg("Error writing to TUN", logLevel=logging.WARN)
        

    def tunnel_write(self, data):
        """Server: TUN sends data through WebSocket to client"""
        data = self.mtcrypt.encrypt(data)
        self.sendMessage(data, isBinary=True)


class WSClientFactory(WebSocketClientFactory):
    def __init__(self, path, debug, debugCodePaths=False):
        WebSocketClientFactory.__init__(self, path, debug=debug, debugCodePaths=False)
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except:
            log.msg("Error creating raw socket", logLevel=logging.WARN)


    def tunnel_write(self, data):
        """WS client: Receive data from TUN"""
        try:
            self.proto.tunnel_write(data)
        except:
            log.msg("Couldn't reach the server over the WebSocket", logLevel=logging.WARN)


class WSClientProto(WebSocketClientProtocol):
    """WS client: WebSocket client protocol callbacks"""

    def onConnect(self, response):
        log.msg("WebSocket connected", logLevel=logging.INFO)


    def onOpen(self):
        self.factory.proto = self
        self.mtcrypt = MTCrypt(self.factory.passwd, self.factory.server)
        self.mtcrypt.proto = self
        log.msg("WebSocket opened", logLevel=logging.INFO)
        

    def onClose(self, wasClean, code, reason):
        log.msg("WebSocket closed", logLevel=logging.WARN)
        

    def onMessage(self, data, isBinary):
        """Client: Received data from WS, decrypt and send to TUN"""
        data = self.mtcrypt.decrypt(data)

        try:
            self.factory.tun.tun.write(data)
        except:
            log.msg("Error writing to TUN", logLevel=logging.WARN)


    def tunnel_write(self, data):
        """Client: TUN sends data through WebSocket to server"""
        data = self.mtcrypt.encrypt(data)
        self.sendMessage(data, isBinary=True)


class TUNReader(object):
    """TUN device"""

    def __init__(self, tun_dev, tun_addr, tun_remote_addr, tun_nm, tun_mtu, wsfactory):
        self.wsfactory = wsfactory

        self.tun = TunTapDevice(name=tun_dev, flags=(IFF_TUN|IFF_NO_PI))
        self.tun.addr = tun_addr
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
        log.msg("Connection lost", logLevel=logging.WARN)


    def doRead(self):
        """Read from host, send to WS to be sent to distant end"""
        data = self.tun.read(self.tun.mtu)
        self.wsfactory.tunnel_write(data)


    def logPrefix(self):
        return "TUNReader"


class MTCrypt(object):
    """Handle encryption/decryption for WS traffic"""

    def __init__(self, passwd, is_server):
        self.passwd = passwd
        self.is_server = is_server

        self.iv = Random.new().read(AES.block_size)
        self.key = SHA384.new(data=passwd).digest()[:AES_KEYLEN]

        self.initialized = 0


    def encrypt(self, data):
        data = self.pad_data(data)

        if self.initialized == 0 and self.is_server == False:
            self.aes_e = AES.new(self.key, AES.MODE_CFB, self.iv)
            self.aes_d = AES.new(self.key, AES.MODE_CFB, self.iv)

            data = self.iv+self.aes_e.encrypt(self.passwd+'\x00'+ data)
            tag = HMAC.new(self.key, msg=data, digestmod=SHA384).digest()[:TAG_LEN]
            data = data+tag

            self.initialized = 1

        else:
            data = self.aes_e.encrypt(data)
            tag = HMAC.new(self.key, msg=data, digestmod=SHA384).digest()[:TAG_LEN]
            data = data+tag

        return data


    def decrypt(self, data):
        if len(data) <= AES.block_size:
            log.msg("Received invalid (small) data", logLevel=logging.INFO)
            return None
       
        if self.initialized == 0 and self.is_server == True:
            if self.verify_tag(data) == False:
                log.msg("Invalid HMAC on first packet, remote unauthorized", logLevel=logging.INFO)
                self.proto.sendClose()
                return None

            self.iv = data[:AES.block_size]
            data = data[AES.block_size:]

            self.aes_d = AES.new(self.key, AES.MODE_CFB, self.iv)
            data = data[:len(data)-TAG_LEN]
            tmp_data = self.aes_d.decrypt(data)
            tmp = tmp_data.split('\x00', 1)

            if tmp[0] != self.passwd:
                log.msg("Remote unauthorized", logLevel=logging.INFO)
                self.proto.sendClose()
                return None

            else:
                data = tmp[1]
                log.msg("Remote authorized", logLevel=logging.INFO)
                self.aes_e = AES.new(self.key, AES.MODE_CFB, self.iv)
                self.initialized = 1
        else:
            if self.verify_tag(data) == False:
                log.msg("Invalid HMAC, ignoring data", logLevel=logging.INFO)
                return None

            data = self.aes_d.decrypt(data[:len(data)-TAG_LEN])

        return self.unpad_data(data)


    def verify_tag(self, data):
        pkt_data = data[:len(data)-TAG_LEN]
        pkt_tag = data[len(data)-TAG_LEN:]
        tag = HMAC.new(self.key, msg=pkt_data, digestmod=SHA384).digest()[:TAG_LEN]

        return streql.equals(pkt_tag, tag)


    def pad_data(self, data):
        if len(data) % AES.block_size == 0:
            return data

        padnum = 15 - (len(data) % AES.block_size)
        data = '%s\x80' % data
        data = '%s%s' % (data, '\x00' * padnum)

        return data

    
    def unpad_data(self, data):
        if not data:
            return data

        data = data.rstrip('\x00')
        if data[-1] == '\x80':
            return data[:-1]
        else:
            return data


class Server(object):
    """multitun server object"""

    def __init__(self, serv_addr, serv_port, ws_loc, tun_dev, tun_addr, tun_client_addr, tun_nm, tun_mtu, webdir, passwd):
        # WebSocket
        path = "ws://"+serv_addr+":"+serv_port
        wsfactory = WSServerFactory(path, debug=False)
        wsfactory.protocol = WSServerProto
        wsfactory.passwd = passwd
        wsfactory.server = True

        # Web server
        ws_resource = WebSocketResource(wsfactory)
        root = File(webdir)
        root.putChild(ws_loc, ws_resource)
        site = Site(root)

        # TUN device
        server_tun = TUNReader(tun_dev, tun_addr, tun_client_addr, tun_nm, tun_mtu, wsfactory)
        reactor.addReader(server_tun)
        wsfactory.tun = server_tun

        reactor.listenTCP(int(serv_port), site)
        reactor.run()


class Client(object):
    """multitun client object"""

    def __init__(self, serv_addr, serv_port, ws_loc, tun_dev, tun_addr, tun_serv_addr, tun_nm, tun_mtu, passwd):
        # WebSocket
        path = "ws://"+serv_addr+":"+serv_port+"/"+ws_loc
        wsfactory = WSClientFactory(path, debug=False)
        wsfactory.protocol = WSClientProto
        wsfactory.passwd = passwd
        wsfactory.server = False

        # TUN device
        client_tun = TUNReader(tun_dev, tun_addr, tun_serv_addr, tun_nm, tun_mtu, wsfactory)
        reactor.addReader(client_tun)
        wsfactory.tun = client_tun

        reactor.connectTCP(serv_addr, int(serv_port), wsfactory)
        reactor.run()


banner = """
                 | | | (_) |              
  _ __ ___  _   _| | |_ _| |_ _   _ _ __  
 | '_ ` _ \| | | | | __| | __| | | | '_ \ 
 | | | | | | |_| | | |_| | |_| |_| | | | |
 |_| |_| |_|\__,_|_|\__|_|\__|\__,_|_| |_|
"""

def main():
    server = False

    for arg in sys.argv:
        if arg == "-s":
            server = True

    print ""
    print banner
    print " =============================================="
    print " Multitun " + MT_VERSION
    print " By Joshua Davis (multitun -*- covert.codes)"
    print " http://covert.codes"
    print " Copyright(C) 2014"
    print " Released under the GNU General Public License"
    print " =============================================="
    print ""

    config = INIConfig(open(configfile))

    serv_addr = config.all.serv_addr
    serv_port = config.all.serv_port
    ws_loc = config.all.ws_loc
    tun_nm = config.all.tun_nm
    tun_mtu = config.all.tun_mtu
    passwd = config.all.password

    log.startLogging(sys.stdout)
    if type(config.all.logfile) == 'str':
        log.startLogging(open(config.all.logfile, 'w+'))

    if len(passwd) == 0:
        log.msg("Edit the configuration file to include a password", logLevel=logging.WARN)
        sys.exit(EXIT_ERR)
        
    if server == True:
        tun_dev = config.server.tun_dev
        tun_addr = config.server.tun_addr
        tun_client_addr = config.client.tun_addr
        webdir = config.server.webdir

        log.msg("Starting multitun as a server", logLevel=logging.INFO)
        logstr = ("Server listening on port %s") % (serv_port)
        log.msg(logstr, logLevel=logging.INFO)

        server = Server(serv_addr, serv_port, ws_loc, tun_dev, tun_addr, tun_client_addr, tun_nm, tun_mtu, webdir, passwd)

    else: # server != True
        serv_addr = config.all.serv_addr
        serv_port = config.all.serv_port
        tun_dev = config.client.tun_dev
        tun_addr = config.client.tun_addr
        tun_serv_addr = config.server.tun_addr

        log.msg("Starting multitun as a client", logLevel=logging.INFO)
        logstr = ("Forwarding to %s:%s") % (serv_addr, int(serv_port))
        log.msg(logstr, logLevel=logging.INFO)

        client = Client(serv_addr, serv_port, ws_loc, tun_dev, tun_addr, tun_serv_addr, tun_nm, tun_mtu, passwd)


if __name__ == "__main__":
    main()

