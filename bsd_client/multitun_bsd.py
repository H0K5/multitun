#!/usr/bin/env python2

# multitun v0.8 BSD
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

import logging
import os
import streql
import sys
from autobahn.twisted.websocket import WebSocketClientFactory
from autobahn.twisted.websocket import WebSocketClientProtocol
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA384
from Crypto import Random
from iniparse import INIConfig
from socket import inet_ntoa, inet_aton
from subprocess import call
from twisted.internet import protocol, reactor
from twisted.web.static import File
from twisted.python import log

MT_VERSION= "v0.8 BSD"
CONF_FILE = "multitun.conf"
ERR = -1


class WSClientFactory(WebSocketClientFactory):
    def __init__(self, path, debug, debugCodePaths=False):
        WebSocketClientFactory.__init__(self, path, debug=debug, debugCodePaths=False)


    def tunnel_write(self, data):
        """WS client: Receive data from TUN"""
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
        self.tun_dev = tun_dev
        self.tun_addr = tun_addr
        self.tun_remote_addr = tun_remote_addr
        self.tun_nm = tun_nm
        self.tun_mtu = int(tun_mtu)
        self.wsfactory = wsfactory

        try:
            self.tunfd = os.open("/dev/"+tun_dev, os.O_RDWR)
            if self.tunfd <= 3:
                log.msg("Error opening TUN device.  In use?  Permissions?", logLevel=logging.WARN)
                sys.exit(ERR)

            call(["/sbin/ifconfig", tun_dev, tun_addr, tun_remote_addr, "up"])
        except:
            log.msg("Error opening TUN device.  Configuration?  Permissions?", logLevel=logging.WARN)
            sys.exit(ERR)


        logstr = ("Opened TUN device on %s") % (self.tun_dev)
        log.msg(logstr, logLevel=logging.INFO)


    def fileno(self):
        return self.tunfd


    def connectionLost(self, reason):
        log.msg("Connection lost", logLevel=logging.INFO)


    def doRead(self):
        """Read from host, send to WS to be sent to distant end"""
        data = os.read(self.tunfd, self.tun_mtu)
        self.wsfactory.tunnel_write(data)

    def doWrite(self, data):
        """Write to TUN"""
        os.write(self.tunfd, data)

    def logPrefix(self):
        return "TUNReader"


AES_KEYLEN = 32
TAG_LEN = 48

class MTCrypt(object):
    """Handle encryption/decryption for WS traffic"""

    def __init__(self, is_server):
        self.is_server = is_server
        self.initialized = 0


    def encrypt(self, data):
        if self.initialized == 0:
            taddr = inet_aton(self.proto.factory.tun.tun_addr)
            self.iv = Random.new().read(AES.block_size)
            passwd = self.proto.factory.passwd
            self.key = SHA384.new(data=passwd).digest()[:AES_KEYLEN]
            self.aes_e = AES.new(self.key, AES.MODE_CFB, self.iv)
            self.aes_d = AES.new(self.key, AES.MODE_CFB, self.iv)

            data = self.iv+self.aes_e.encrypt(data)
            tag = HMAC.new(self.key, msg=data, digestmod=SHA384).digest()[:TAG_LEN]
            data = taddr+data+tag

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
       
        if self.verify_tag(data) == False:
            log.msg("Invalid HMAC, ignoring data", logLevel=logging.INFO)
            return None

        data = self.aes_d.decrypt(data[:len(data)-TAG_LEN])

        return data


    def verify_tag(self, data):
        pkt_data = data[:len(data)-TAG_LEN]
        pkt_tag = data[len(data)-TAG_LEN:]
        tag = HMAC.new(self.key, msg=pkt_data, digestmod=SHA384).digest()[:TAG_LEN]
        return streql.equals(pkt_tag, tag)


class Client(object):
    def __init__(self, serv_addr, serv_port, ws_loc, tun_dev, tun_addr, tun_serv_addr, tun_nm, tun_mtu, passwd):
        # WebSocket
        path = "ws://"+serv_addr+":"+serv_port+"/"+ws_loc
        wsfactory = WSClientFactory(path, debug=False)
        wsfactory.protocol = WSClientProto
        wsfactory.passwd = passwd

        # TUN device
        tun = TUNReader(tun_dev, tun_addr, tun_serv_addr, tun_nm, tun_mtu, wsfactory)

        reactor.addReader(tun)
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

