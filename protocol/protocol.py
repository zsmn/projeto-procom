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

    def handShake(self):
        

    def generateSecretKey(self):
        self.secretKey = os.urandom(16)

    def voteSession(self):


class Socket:
    def __init__(self, address, port):
        self.address = address
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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