#!/usr/bin/env python2

# multitun v0.5
#
# Joshua Davis (multitun -*- covert.codes)
# http://covert.codes
# Copyright(C) 2014
# Released under the GNU General Public License

import sys
import logging
import struct
import socket
import dpkt
from iniparse import INIConfig
from pytun import TunTapDevice, IFF_TUN, IFF_NO_PI
from twisted.internet import protocol, reactor
from twisted.web.server import Site
from twisted.web.static import File
from twisted.python import log
from autobahn.twisted.websocket import WebSocketServerFactory
from autobahn.twisted.websocket import WebSocketServerProtocol
from autobahn.twisted.websocket import WebSocketClientFactory
from autobahn.twisted.websocket import WebSocketClientProtocol
from autobahn.twisted.resource import WebSocketResource

from Crypto.Cipher import AES
from Crypto.Hash import SHA224
from Crypto import Random

configfile = "multitun.conf"

MT_VERSION= "v0.5"
KEYLEN = 16 # bytes
EXIT_ERR = -1
PW_LEN = 10


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
		log.msg("WebSocket opened", logLevel=logging.INFO)
		self.iv = 0
		self.key = self.factory.key


	def onClose(self, wasClean, code, reason):
		log.msg("WebSocket closed", logLevel=logging.WARN)


	def onMessage(self, data, isBinary):
		"""Get data from the server WebSocket, send to the TUN"""
		if self.iv == 0:
			# First authenticate
			tmp_iv = data[:AES.block_size]
			tmp_aes_d = AES.new(self.key, AES.MODE_CFB, tmp_iv)
			tmp_data = tmp_aes_d.decrypt(data[AES.block_size:])

			if tmp_data[:len(self.key)].ljust(PW_LEN,'0') != self.key.ljust(PW_LEN, '0'):
				log.msg("Remote unauthorized", logLevel=logging.INFO)
				self.sendClose()

				return

			else:
				log.msg("Remote authorized", logLevel=logging.INFO)
				self.factory.proto = self
				self.iv = tmp_iv
				self.aes_e = AES.new(self.key, AES.MODE_CFB, self.iv)
				self.aes_d = tmp_aes_d
				data = tmp_data[len(self.key):]
		else:
			data = self.aes_d.decrypt(data)

		try:
			self.factory.tun.tun.write(data)
		except:
			log.msg("Error writing to TUN", logLevel=logging.WARN)
	

	def tunnel_write(self, data):
		"""Server: TUN sends data through WebSocket to client"""
		data = self.aes_e.encrypt(data)
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

		iv = Random.new().read(AES.block_size)
		self.set_iv = iv
		self.key = self.factory.key
		self.aes_e = AES.new(self.key, AES.MODE_CFB, iv)
		self.aes_d = AES.new(self.key, AES.MODE_CFB, iv)

		log.msg("WebSocket opened", logLevel=logging.INFO)
	

	def onClose(self, wasClean, code, reason):
		log.msg("WebSocket closed", logLevel=logging.WARN)
	

	def onMessage(self, data, isBinary):
		data = self.aes_d.decrypt(data)

		try:
			self.factory.tun.tun.write(data)
		except:
			log.msg("Error writing to TUN", logLevel=logging.WARN)


	def tunnel_write(self, data):
		"""Client: TUN sends data through WebSocket to server"""
		if self.set_iv != 0:
			# Send authentication and IV with the first packet
			data = self.set_iv + self.aes_e.encrypt(self.key + data)
			self.set_iv = 0
		else:
			data = self.aes_e.encrypt(data)

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
		data = self.tun.read(self.tun.mtu)
		self.wsfactory.tunnel_write(data)


	def logPrefix(self):
		return "TUNReader"


class Server(object):
	"""multitun server object"""

	def __init__(self, serv_addr, serv_port, ws_loc, tun_dev, tun_addr, tun_client_addr, tun_nm, tun_mtu, webdir, key):
		# WebSocket
		path = "ws://"+serv_addr+":"+serv_port
		wsfactory = WSServerFactory(path, debug=False)
		wsfactory.protocol = WSServerProto
		wsfactory.key = key

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

	def __init__(self, serv_addr, serv_port, ws_loc, tun_dev, tun_addr, tun_serv_addr, tun_nm, tun_mtu, key):
		# WebSocket
		path = "ws://"+serv_addr+":"+serv_port+"/"+ws_loc
		wsfactory = WSClientFactory(path, debug=False)
		wsfactory.protocol = WSClientProto
		wsfactory.key = key

		# TUN device
		client_tun = TUNReader(tun_dev, tun_addr, tun_serv_addr, tun_nm, tun_mtu, wsfactory)
		reactor.addReader(client_tun)
		wsfactory.tun = client_tun

		reactor.connectTCP(serv_addr, int(serv_port), wsfactory)
		reactor.run()


def main():
	server = False

	for arg in sys.argv:
		if arg == "-s":
			server = True

	print " =============================================="
	print " Multitun " + MT_VERSION
	print " By Joshua Davis (multitun -*- covert.codes)"
	print " http://covert.codes"
	print " Copyright(C) 2014"
	print " Released under the GNU General Public License"
	print " =============================================="
	print ""

	config = INIConfig(open(configfile))

	log_file = config.all.log_file
	serv_addr = config.all.serv_addr
	serv_port = config.all.serv_port
	ws_loc = config.all.ws_loc
	tun_nm = config.all.tun_nm
	tun_mtu = config.all.tun_mtu
	password = config.all.password

	log.startLogging(sys.stdout)
	log.startLogging(open(log_file, 'w+'))


	if len(password) == 0:
		log.msg("Edit the configuration file to include a password", logLevel=logging.WARN)
		sys.exit(EXIT_ERR)

	password = password.ljust(PW_LEN, '0')
	key = SHA224.new(data=password).digest()[:KEYLEN]

	if server == True:
		tun_dev = config.server.tun_dev
		tun_addr = config.server.tun_addr
		tun_client_addr = config.client.tun_addr
		webdir = config.server.webdir

		log.msg("Starting multitun as a server", logLevel=logging.INFO)
		logstr = ("Server listening on port %s") % (serv_port)
		log.msg(logstr, logLevel=logging.INFO)

		server = Server(serv_addr, serv_port, ws_loc, tun_dev, tun_addr, tun_client_addr, tun_nm, tun_mtu, webdir, key)

	else: # server != True
		serv_addr = config.all.serv_addr
		serv_port = config.all.serv_port
		tun_dev = config.client.tun_dev
		tun_addr = config.client.tun_addr
		tun_serv_addr = config.server.tun_addr

		log.msg("Starting multitun as a client", logLevel=logging.INFO)
		logstr = ("Forwarding to %s:%s") % (serv_addr, int(serv_port))
		log.msg(logstr, logLevel=logging.INFO)

		client = Client(serv_addr, serv_port, ws_loc, tun_dev, tun_addr, tun_serv_addr, tun_nm, tun_mtu, key)

if __name__ == "__main__":
	main()

