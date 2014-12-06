import logging
import streql
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA384
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
from twisted.python import log

AES_KEYLEN = 32
SHA384_LEN = 48
SALT_LEN = 32
PBKDF2_ITERATIONS = 5000

class MTCrypt(object):
    """Handle encryption/decryption for WS traffic"""

    def __init__(self, is_server):
        self.is_server = is_server
        self.initialized = 0


    def encrypt(self, data):
        if self.initialized == 0 and self.is_server == False:
            taddr = self.proto.factory.tun.addr
            taddr_hash = SHA384.new(taddr).digest()

            iv = Random.new().read(AES.block_size)
            salt = Random.new().read(SALT_LEN)

            passwd = self.proto.factory.passwd
            self.key = PBKDF2(passwd, salt, dkLen=AES_KEYLEN*2, count=PBKDF2_ITERATIONS)
            self.aes_e = AES.new(self.key[:AES_KEYLEN], AES.MODE_CFB, iv)
            self.aes_d = AES.new(self.key[AES_KEYLEN:], AES.MODE_CFB, iv)

            data = iv+self.aes_e.encrypt(data)
            tag = HMAC.new(self.key, msg=data, digestmod=SHA384).digest()[:SHA384_LEN]
            data = taddr_hash+salt+data+tag

            self.initialized = 1

        else:
            data = self.aes_e.encrypt(data)
            tag = HMAC.new(self.key, msg=data, digestmod=SHA384).digest()[:SHA384_LEN]
            data = data+tag

        return data


    def decrypt(self, data):
        if len(data) <= AES.block_size:
            log.msg("Received invalid (small) data", logLevel=logging.INFO)
            return None
      
        taddr = None
        if self.initialized == 0 and self.is_server == True:
            taddr_hash = data[:SHA384_LEN]
            for user in self.proto.factory.users:
                user_hash = SHA384.new(user).digest()
                if user_hash == taddr_hash:
                    taddr = user
                    break

            if taddr == None:
                log.msg("Invalid TUN IP trying to register, ignored", logLevel=logging.INFO)
                self.proto.sendClose()
                return None

            salt = data[SHA384_LEN:SHA384_LEN+SALT_LEN]
            data = data[SHA384_LEN+SALT_LEN:]
            passwd = self.proto.factory.users[taddr]

            logstr = ("Received request from client with TUN address %s") % (taddr)
            log.msg(logstr, logLevel=logging.INFO)

            # Check if the TUN IP is already being used
            if(self.proto.factory.register(taddr, self.proto)) == False:
                log.msg("Duplicate TUN address tried to register, ignored", logLevel=logging.INFO)
                self.proto.sendClose()
                return None

            self.key = PBKDF2(passwd, salt, dkLen=AES_KEYLEN*2, count=PBKDF2_ITERATIONS)

            if self.verify_tag(data) == False:
                log.msg("Invalid HMAC on first packet, remote unauthorized", logLevel=logging.INFO)
                self.proto.sendClose()
                return None

            iv = data[:AES.block_size]
            self.aes_e = AES.new(self.key[AES_KEYLEN:], AES.MODE_CFB, iv)
            self.aes_d = AES.new(self.key[:AES_KEYLEN], AES.MODE_CFB, iv)

            data = data[AES.block_size:len(data)-SHA384_LEN]
            data = self.aes_d.decrypt(data)

            log.msg("Remote authorized", logLevel=logging.INFO)
            self.initialized = 1

        else: # client
            if self.verify_tag(data) == False:
                log.msg("Invalid HMAC, ignoring data", logLevel=logging.INFO)
                return None

            data = self.aes_d.decrypt(data[:len(data)-SHA384_LEN])

        return data


    def verify_tag(self, data):
        pkt_data = data[:len(data)-SHA384_LEN]
        pkt_tag = data[len(data)-SHA384_LEN:]
        tag = HMAC.new(self.key, msg=pkt_data, digestmod=SHA384).digest()[:SHA384_LEN]
        return streql.equals(pkt_tag, tag)

