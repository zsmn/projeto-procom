import os
import socket
import ast
import random
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Socket:
    def __init__(self, address, port):
        # Take network data
        self.address = address
        self.port = port

        # Assymetric keys
        self.publicKey = ""
        self.privateKey = ""
        self.generateAssymetricKeys()

        # Create socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        pass

    def generateAssymetricKeys(self):
        self.privateKey = RSA.generate(1024, Random.new().read)
        self.publicKey = self.privateKey.publickey()

    def encryptMessage(self, message, key):
        encryptor = PKCS1_OAEP.new(key)
        return encryptor.encrypt(message)

    def decryptMessage(self, message, key):
        decryptor = PKCS1_OAEP.new(key)
        return decryptor.decrypt(ast.literal_eval(str(message)))

class Server(Socket):
    def __init__(self, address, port):
        Socket.__init__(self, address, port)

        # Save server public key in file
        file = open('serverPublicKey.txt', 'w')
        key = self.publicKey.exportKey("PEM").decode('utf-8')
        file.write(key)

        # Debug server
        print(bcolors.BOLD + 'Voting Server connected at ' + str({'address': address, 'port': port}) + bcolors.ENDC)
        print(bcolors.OKGREEN + 'Sucessfuly registered PUBLIC_KEY in serverPublicKey.txt file:\n' + bcolors.HEADER + bcolors.BOLD + key + bcolors.ENDC)

    def connect(self):
        self.socket.bind((self.address, self.port))
        self.socket.listen()

    def sendMessage(self, clientSocket, message):
        clientSocket.sendall(message)

class Client(Socket):
    def __init__(self, address, port):
        Socket.__init__(self, address, port)

        # Debug client
        print(bcolors.BOLD + 'Voting Client connected at ' + str({'address': address, 'port': port}) + bcolors.ENDC)

    def connect(self):
        self.socket.connect((self.address, self.port))

    def sendMessage(self, message):
        self.socket.sendall(message)

class Protocol:
    def __init__(self):
        self.symmetricKey = ""

    def serverProcedure(self, server, clientSocket, clientAddress):
        print(bcolors.BOLD + 'Started connection with', clientAddress, bcolors.ENDC)

        ''' [Handshake] '''
        ''' Receiving auth package from client '''
        print(bcolors.OKBLUE + '[HANDSHAKE] Awaiting auth packet from', clientAddress, bcolors.ENDC)

        # Take auth package
        auth = clientSocket.recv(1024)
        authMap = eval(auth)

        print(bcolors.OKCYAN + '[HANDSHAKE] Processing auth packet from', clientAddress, bcolors.ENDC)

        # Take clientPublicKey and encryptedNonce
        clientPublicKey = RSA.importKey(authMap['clientPublicKey'])
        encryptedNonce = authMap['encryptedNonce']

        ''' Decrypt nonce and send it encrypted with client public key to client '''

        # Decrypt nonce using server private key
        decryptedNonce = server.decryptMessage(encryptedNonce, server.privateKey)

        # Encrypt decryptedNonce with clientPublicKey and send it to client
        encryptedNonce = server.encryptMessage(decryptedNonce, clientPublicKey)
        server.sendMessage(clientSocket, encryptedNonce)

        ''' Waiting from client response [ack | nack] '''
        
        # Wait for client response
        clientResponse = clientSocket.recv(1024).decode('utf-8')
        if(clientResponse != 'ack'):
            # If differs from ack, close connection
            clientSocket.close()
            print(bcolors.FAIL + '[ERROR] Disconnected from', clientAddress, 'because answer of auth process was nack.' + bcolors.ENDC)
            pass

        print(bcolors.OKGREEN + '[HANDSHAKE] Handshake authentication successfully' + bcolors.ENDC)
        ''' [Generate symmetric key] '''

        ''' Generate symmetric key and send to client '''    
        # Generating random symmetric key
        self.symmetricKey = self.generateRandomKey()
        
        print(bcolors.OKCYAN + '[GENSYMMETRIC] Generating, encrypting and sending symmetric key to', clientAddress, bcolors.ENDC)

        # Encrypt symmetric key with clientPublicKey and send it to client
        encryptedSymmetric = server.encryptMessage(self.symmetricKey, clientPublicKey)
        server.sendMessage(clientSocket, encryptedSymmetric)

        print(bcolors.OKGREEN + '[GENSYMMETRIC] Successfully sent symmetric key to', clientAddress, bcolors.ENDC)

        ''' [Vote Session] '''

        print(bcolors.OKCYAN + '[VOTE SESSION] Starting vote session with', clientAddress, bcolors.ENDC)

        # TODO: for loop with vote session
        ###
        print(bcolors.OKBLUE + '[VOTE SESSION] Awaiting vote from', clientAddress, bcolors.ENDC)
        print(bcolors.FAIL + '[VOTE SESSION] Received an invalid vote from', clientAddress, ', re-running loop.' ,bcolors.ENDC)
        ###

        print(bcolors.OKGREEN + '[VOTE SESSION] Received an valid vote from', clientAddress, 'and vote computed successfully, finishing connection.', bcolors.ENDC)

        # End connection
        clientSocket.close()

    def clientProcedure(self, client, serverPublicKey):
        ''' [Handshake] '''

        ''' Client send auth package '''
        # Generate nonce
        nonce = self.generateRandomKey()
        print(bcolors.OKBLUE + '[HANDSHAKE] Generating random nonce' + bcolors.ENDC)

        # Generating auth package [auth(clientPublicKey, encryptedNonce)]
        auth = {'clientPublicKey': client.publicKey.exportKey("PEM").decode('utf-8'),
                'encryptedNonce': client.encryptMessage(nonce, serverPublicKey)}
        authAsString = str(auth)

        # Sending auth package to server
        client.sendMessage(bytes(authAsString, 'utf-8'))

        print(bcolors.OKGREEN + '[HANDSHAKE] Sent encrypted nonce and public key to server.' + bcolors.ENDC)

        ''' Receive encrypted nonce from server '''

        print(bcolors.OKBLUE + '[HANDSHAKE] Awaiting auth response from server' + bcolors.ENDC)

        # Wait encrypted nonce from server
        encryptedNonce = client.socket.recv(1024)

        # Decrypt nonce and check if is ok
        decryptedNonce = client.decryptMessage(encryptedNonce, client.privateKey)
        if(decryptedNonce == nonce):
            # If decryptedNonce == nonce, send ack
            client.sendMessage(b'ack')
            print(bcolors.OKGREEN + '[HANDSHAKE] Handshake server authentication successfully' + bcolors.ENDC)
        else:
            # If decryptedNonce != nonce, send nack and finish connection
            client.sendMessage(b'nack')
            print(bcolors.FAIL + '[ERROR] Disconnected from server because the auth process failed.' + bcolors.ENDC)
            client.socket.close()
            pass

        ''' [Generate symmetric key] '''
        
        print(bcolors.OKBLUE + '[GENSYMMETRIC] Awaiting for symmetric key' + bcolors.ENDC)

        # Receive encrypted symmetric key generated from server
        self.symmetricKey = client.socket.recv(1024)

        # Decrypt received symmetric key with client private key
        self.symmetricKey = client.decryptMessage(self.symmetricKey, client.privateKey)

        print(bcolors.OKGREEN + '[GENSYMMETRIC] Successfully received and decrypted symmetric key.' + bcolors.ENDC)

        ''' [Vote Session] '''

        print(bcolors.OKCYAN + '[VOTE SESSION] Starting vote session' + bcolors.ENDC)

        # TODO: for loop with vote session
        ###
        print(bcolors.OKBLUE + '[VOTE SESSION] Sent vote to server' + bcolors.ENDC)
        print(bcolors.FAIL + '[VOTE SESSION] Sent vote was not valid, send another one' + bcolors.ENDC)
        ###

        print(bcolors.OKGREEN + '[VOTE SESSION] Sent vote was valid, finished vote session and closing connection with vote server.' + bcolors.ENDC)

        # Close connection
        client.socket.close()

    def generateRandomKey(self):
        randomKey = os.urandom(16)
        return randomKey