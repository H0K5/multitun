#!/usr/bin/env python2

# multitun v0.9 BSD Client
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
from mtcrypt.mtcrypt import *
from socket import inet_ntoa, inet_aton
from subprocess import call
from twisted.internet import protocol, reactor
from twisted.web.static import File
from twisted.python import log

MT_VERSION= "v0.9 BSD Client"
CONF_FILE = "multitun.conf"
ERR = -1


class WSClientFactory(WebSocketClientFactory):
    def __init__(self, path, debug, debugCodePaths=False):
        WebSocketClientFactory.__init__(self, path, debug=debug, debugCodePaths=False)


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
        try:
            self.sendMessage(data, isBinary=True)
        except:
            log.msg("Couldn't send through WebSocket", logLevel=logging.INFO)


class TUNReader(object):
    """TUN device"""

    def __init__(self, tun_dev, tun_addr, tun_remote_addr, tun_nm, tun_mtu, wsfactory):
        self.tun_dev = tun_dev
        self.tun_addr = tun_addr
        self.addr = tun_addr # used by mtcrypt
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
        self.wsfactory.proto.tunnel_write(data)

    def doWrite(self, data):
        """Write to TUN"""
        os.write(self.tunfd, data)

    def logPrefix(self):
        return "TUNReader"


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

