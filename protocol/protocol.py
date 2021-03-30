import os
import socket
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

# cria a thread
    # pra cada thread a gente associa a uma função que recebe como argumento servidor e o client conectado
        # nessa função criamos uma classe Protocol que reebe esses argumentos
        # a função chama os metodos handShake(), generateSecretKey(), voteSession()

class Protocol:
    def __init__(self, serverSocket, clientSocket):
        self.serverSocket = serverSocket
        self.clientSocket = clientSocket

    def handshake(self):
        # Client send auth message to Server [auth(clientPublicKey, encryptPublicServer(nonce))]
        nonce = RSA.generate(1024, Random.new().read)
        auth = {'clientPublicKey': self.clientSocket.publicKey, 'encryptedNonce': self.clientSocket.encryptMessage(nonce, self.serverSocket.publicKey)}
				authAsString = str(auth)
        self.clientSocket.sendMessage(self.serverSocket, authAsString)
        
        # Server receive auth message from Client and decrypt the nonce
        data = eval(self.serverSocket.readMessage(self.clientSocket))
        decryptedNonce = self.serverSocket.decryptMessage(data['encryptedNonce'], self.serverSocket.privateKey)
        
        # Server send decrypted nonce to Client, but now encrypted with Client public key
        self.serverSocket.sendMessage(self.clientSocket, self.serverSocket.encryptMessage(decryptedNonce, data['clientPublicKey']))
        
        # Client receive decrypted nonce [now encrypted by its public key] from Server and process it 
				encryptedNonce = self.clientSocket.readMessage(self.serverSocket)
        decryptedNonce = self.clientSocket.decryptMessage(encryptedNonce, self.clientSocket.privateKey)
				everythingOk = self.clientSocket.checkNonce(nonce, decryptedNonce)
        if everythingOk == True:
        		self.clientSocket.sendMessage(self.serverSocket, "ack")
        else:
        		self.clientSocket.sendMessage(self.serverSocket, "nack")
				return everythingOk
      
    def generateSecretKey(self):
        self.secretKey = os.urandom(16) # symmetric key
 
    def voteSession(self):
    		pass

class Socket:
    def __init__(self, address, port):
        self.address = address
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.publicKey = ""
        self.privateKey = ""
        self.generateKeys()

    def connectServer(self):
        self.socket.bind((self.address, self.port))
        self.socket.listen()
    
    def connectClient(self):
        self.socket.connect((self.address, self.port))

    def sendMessage(self, destiny, message):
        destiny.send(bytes(message, "utf-8"))

    def encryptMessage(self, message, publicKey):
        encryptedMessage = publicKey.encrypt(message, 32)[0]
        return encryptedMessage
        
    def decryptMessage(self, message, privateKey):
        decryptedMessage = privateKey.decrypt(message)
        return decryptedMessage

    def generateKeys(self):
        self.privateKey = RSA.generate(1024, Random.new().read)
        self.publicKey = self.privateKey.publickey()
    
    def readMessage(self, senderSocket):
    		info = senderSocket.recv(1024)
   			return info
      
    def checkNonce(self, generatedNonce, receivedNonce):
    		if generatedNonce == receivedNonce:
        		return True
    		else:
        		return False
