#!/usr/bin/env python2

# multitun v0.4
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
from twisted.python import log
from autobahn.twisted.websocket import WebSocketServerFactory
from autobahn.twisted.websocket import WebSocketServerProtocol
from autobahn.twisted.websocket import WebSocketClientFactory
from autobahn.twisted.websocket import WebSocketClientProtocol
from Crypto.Cipher import AES
from Crypto.Hash import SHA224
from Crypto import Random

configfile = "multitun.conf"

MT_VERSION= "v0.4"
KEYLEN = 16 # bytes
EXIT_ERR = -1


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
		log.msg("WebSocket opened", logLevel=logging.INFO)


	def onClose(self, wasClean, code, reason):
		log.msg("WebSocket closed", logLevel=logging.WARN)


	def onMessage(self, data, isBinary):
		"""Get data from the server WebSocket, send to the TUN"""
		if self.factory.encrypt == 1:
			if self.factory.iv == 0:
				self.factory.iv = data[:AES.block_size]
				self.factory.aes_e = AES.new(self.factory.key, AES.MODE_CFB, self.factory.iv)
				self.factory.aes_d = AES.new(self.factory.key, AES.MODE_CFB, self.factory.iv)

				data = data[AES.block_size:]
				data = self.factory.aes_d.decrypt(data)
			else:
				data = self.factory.aes_d.decrypt(data)

		try:
			self.factory.tun.tun.write(data)
		except:
			log.msg("Error writing to TUN", logLevel=logging.WARN)
	

	def tunnel_write(self, data):
		"""Server: TUN sends data through WebSocket to client"""
		if self.factory.encrypt == 1:
			data = self.factory.aes_e.encrypt(data)

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
			log.msg("Couldn't reach the server over the WebSocket.  Is it running?  Firewalled?", logLevel=logging.WARN)


class WSClientProto(WebSocketClientProtocol):
	"""WS client: WebSocket client protocol callbacks"""

	def onConnect(self, response):
		log.msg("WebSocket connected", logLevel=logging.INFO)


	def onOpen(self):
		self.factory.proto = self
		log.msg("WebSocket opened", logLevel=logging.INFO)
	

	def onClose(self, wasClean, code, reason):
		log.msg("WebSocket closed", logLevel=logging.WARN)
	

	def onMessage(self, data, isBinary):
		if self.factory.encrypt == 1:
			data = self.factory.aes_d.decrypt(data)

		try:
			self.factory.tun.tun.write(data)
		except:
			log.msg("Error writing to TUN", logLevel=logging.WARN)


	def tunnel_write(self, data):
		"""Client: TUN sends data through WebSocket to server"""
		if self.factory.encrypt == 1:
			if self.factory.set_iv != 0:
				data = self.factory.set_iv + self.factory.aes_e.encrypt(data)
				self.factory.set_iv = 0
			else:
				data = self.factory.aes_e.encrypt(data)

		self.sendMessage(data, isBinary=True)


class TUNReader(object):
	"""TUN device"""
	def __init__(self, tun_dev, tun_addr, tun_remote_addr, tun_nm, tun_mtu, wsfactory):
		self.tun_dev = tun_dev
		self.tun_addr = tun_addr
		self.tun_remote_addr = tun_remote_addr
		self.tun_nm = tun_nm
		self.tun_mtu = tun_mtu
		self.wsfactory = wsfactory

		self.tun = TunTapDevice(name=self.tun_dev, flags=(IFF_TUN|IFF_NO_PI))
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

	def __init__(self, listen_addr, listen_port, tun_dev, tun_addr, tun_client_addr, tun_nm, tun_mtu, encrypt, key):
		self.listen_addr = listen_addr
		self.listen_port = listen_port
		self.tun_dev = tun_dev
		self.tun_addr = tun_addr
		self.tun_client_addr =  tun_client_addr
		self.tun_nm = tun_nm
		self.tun_mtu = tun_mtu
		self.encrypt = encrypt
		self.key = key

		# WebSocket
		path = "ws://"+listen_addr+":"+listen_port
		self.wsfactory = WSServerFactory(path, debug=False)
		self.wsfactory.protocol = WSServerProto
		self.wsfactory.encrypt = self.encrypt
		self.wsfactory.key = self.key
		self.wsfactory.iv = 0

		reactor.listenTCP(int(listen_port), self.wsfactory)

		# TUN device
		self.server_tun = TUNReader(self.tun_dev, self.tun_addr, self.tun_client_addr, self.tun_nm, self.tun_mtu, self.wsfactory)
		reactor.addReader(self.server_tun)

		self.wsfactory.tun = self.server_tun

		reactor.run()


class Client(object):
	"""multitun client object"""

	def __init__(self, serv_addr, serv_port, tun_dev, tun_addr, tun_serv_addr, tun_nm, tun_mtu, encrypt, key):
		self.serv_addr = serv_addr
		self.serv_port = serv_port
		self.tun_dev = tun_dev
		self.tun_addr = tun_addr
		self.tun_serv_addr = tun_serv_addr
		self.tun_nm = tun_nm
		self.tun_mtu = tun_mtu
		self.encrypt = encrypt
		self.key = key

		# WebSocket
		path = "ws://"+serv_addr+":"+serv_port
		self.wsfactory = WSClientFactory(path, debug=False)
		self.wsfactory.protocol = WSClientProto
		self.wsfactory.encrypt = self.encrypt

		if(self.encrypt == 1):
			iv = Random.new().read(AES.block_size)
			self.wsfactory.set_iv = iv
			self.wsfactory.aes_e = AES.new(self.key, AES.MODE_CFB, iv)
			self.wsfactory.aes_d = AES.new(self.key, AES.MODE_CFB, iv)

		reactor.connectTCP(self.serv_addr, int(self.serv_port), self.wsfactory)

		# TUN device
		self.client_tun = TUNReader(self.tun_dev, self.tun_addr, self.tun_serv_addr, self.tun_nm, self.tun_mtu, self.wsfactory)
		reactor.addReader(self.client_tun)

		self.wsfactory.tun = self.client_tun

		reactor.run()


def main():
	global verbosity
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
	tun_nm = config.all.tun_nm
	tun_mtu = config.all.tun_mtu
	encrypt = int(config.all.encrypt)
	passphrase = config.all.passphrase

	log.startLogging(sys.stdout)
	log.startLogging(open(log_file, 'w+'))


	key = ''
	if encrypt == 1:
		if len(passphrase) == 0:
			log.msg("Edit the configuration file to include a key (a ten character password will do for many applications.", logLevel=logging.WARN)
			sys.exit(EXIT_ERR)

		key = SHA224.new(data=passphrase).digest()[:KEYLEN]

	if server == True:
		tun_dev = config.server.tun_dev
		tun_addr = config.server.tun_addr
		tun_client_addr = config.client.tun_addr

		log.msg("Starting multitun as a server", logLevel=logging.INFO)
		logstr = ("Server listening on port %s") % (serv_port)
		log.msg(logstr, logLevel=logging.INFO)

		server = Server(serv_addr, serv_port, tun_dev, tun_addr, tun_client_addr, tun_nm, tun_mtu, encrypt, key)

	else: # server != True
		serv_addr = config.all.serv_addr
		serv_port = config.all.serv_port
		tun_dev = config.client.tun_dev
		tun_addr = config.client.tun_addr
		tun_serv_addr = config.server.tun_addr

		log.msg("Starting multitun as a client", logLevel=logging.INFO)
		logstr = ("Forwarding to %s:%s") % (serv_addr, int(serv_port))
		log.msg(logstr, logLevel=logging.INFO)

		client = Client(serv_addr, serv_port, tun_dev, tun_addr, tun_serv_addr, tun_nm, tun_mtu, encrypt, key)

if __name__ == "__main__":
	main()

