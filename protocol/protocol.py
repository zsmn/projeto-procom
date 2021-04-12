import os
import socket
import ast
import random
from collections import Counter
from base64 import b64encode, b64decode
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
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
        self.generateAsymmetricKeys()

        # Create socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        pass

    def generateAsymmetricKeys(self):
        self.privateKey = RSA.generate(1024, Random.new().read)
        self.publicKey = self.privateKey.publickey()

    def encryptMessage(self, message, key, encryptType = 'asymmetric'):
        if(encryptType == 'asymmetric'):
            encryptor = PKCS1_OAEP.new(key)
            return encryptor.encrypt(message)
        else:
            encryptor = AES.new(key, AES.MODE_CBC)
            cipher = b64encode(encryptor.encrypt(pad(message, AES.block_size))).decode('utf-8')
            iv = b64encode(encryptor.iv).decode('utf-8')
            return {'cipher': cipher, 'iv': iv}

    def decryptMessage(self, message, key, encryptType = 'asymmetric', iv = ''):
        if(encryptType == 'asymmetric'):
            decryptor = PKCS1_OAEP.new(key)
            return decryptor.decrypt(ast.literal_eval(str(message)))
        else:
            message = b64decode(message)
            iv = b64decode(iv)
            decryptor = AES.new(key, AES.MODE_CBC, iv)
            return unpad(decryptor.decrypt(message), AES.block_size)

class Server(Socket):
    def __init__(self, address, port, candidates):
        Socket.__init__(self, address, port)

        # Save server public key in file
        file = open('serverPublicKey.txt', 'w')
        key = self.publicKey.exportKey("PEM").decode('utf-8')
        file.write(key)

        # Set candidates
        self.candidates = candidates
        self.votes = Counter(candidates)

        # Reset candidates
        for i in candidates:
            self.votes[i] = 0

        # Debug server
        print(bcolors.BOLD + 'Voting Server connected at ' + str({'address': address, 'port': port}) + bcolors.ENDC)
        print(bcolors.OKGREEN + 'Sucessfuly registered PUBLIC_KEY in serverPublicKey.txt file:\n' + bcolors.HEADER + bcolors.BOLD + key + bcolors.ENDC)

    def connect(self):
        self.socket.bind((self.address, self.port))
        self.socket.listen()

    def sendMessage(self, clientSocket, message):
        clientSocket.sendall(message)

    def checkValidCandidate(self, candidate):
        return (self.candidates.__contains__(candidate))
    
    def addVote(self, candidate):
        self.votes[candidate] += 1

    def printVotes(self):
        print("=======================")
        print(bcolors.BOLD + "Session results" + bcolors.ENDC)
        print("=======================")
        for k,v in self.votes.items():
            print(bcolors.BOLD + k + " = " + str(v) + bcolors.ENDC)

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

        while True:
            # Await for client vote
            print(bcolors.OKBLUE + '[VOTE SESSION] Awaiting vote from', clientAddress, bcolors.ENDC)
            vote = clientSocket.recv(1024)

            # Take voted candidate and IV
            voteMap = eval(vote)
            vote = server.decryptMessage(voteMap['cipher'], self.symmetricKey, encryptType='symmetric', iv=b64encode(server.decryptMessage(voteMap['iv'], server.privateKey))).decode('utf-8')

            # If is valid candidate
            if(server.checkValidCandidate(vote)):
                # Add vote
                server.addVote(vote)
                
                # Send ack
                serverResponse = server.encryptMessage(b'ack', self.symmetricKey, encryptType='symmetric')
                serverResponse['iv'] = server.encryptMessage(b64decode(serverResponse['iv']), clientPublicKey)
                strResponse = str(serverResponse)

                server.sendMessage(clientSocket, bytes(strResponse, 'utf-8'))

                # Finish vote session
                print(bcolors.OKGREEN + '[VOTE SESSION] Received an valid vote from', clientAddress, 'and vote computed successfully, finishing connection.', bcolors.ENDC)
                break
            else:
                # Send nack
                serverResponse = server.encryptMessage(b'nack', self.symmetricKey, encryptType='symmetric')
                serverResponse['iv'] = server.encryptMessage(b64decode(serverResponse['iv']), clientPublicKey)
                strResponse = str(serverResponse)

                server.sendMessage(clientSocket, bytes(strResponse, 'utf-8'))

                print(bcolors.FAIL + '[VOTE SESSION] Received an invalid vote from', clientAddress, ', re-running loop.' ,bcolors.ENDC)
        
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

        while True:
            # Take client vote
            votedPerson = input("Insert your vote: ")
            votedPerson = bytearray(votedPerson, "utf-8")
            
            # Encrypt vote with symmetric key and encrypt IV with server public key
            vote = client.encryptMessage(votedPerson, self.symmetricKey, encryptType='symmetric')
            vote['iv'] = client.encryptMessage(b64decode(vote['iv']), serverPublicKey)
            vote = str(vote)

            # Send vote to server
            client.sendMessage(bytes(vote, 'utf-8'))
            print(bcolors.OKBLUE + '[VOTE SESSION] Sent vote to server' + bcolors.ENDC)
            
            # Await server response
            serverResponse = client.socket.recv(1024)

            # Take response map and decrypt all elements
            serverResponseMap = eval(serverResponse)
            serverResponse = client.decryptMessage(serverResponseMap['cipher'], self.symmetricKey, encryptType='symmetric', iv=b64encode(client.decryptMessage(serverResponseMap['iv'], client.privateKey))).decode('utf-8')
            if(serverResponse == 'ack'):
                print(bcolors.OKGREEN + '[VOTE SESSION] Sent vote was valid, finished vote session and closing connection with vote server.' + bcolors.ENDC)
                break
            else:
                print(bcolors.FAIL + '[VOTE SESSION] Sent vote was not valid, send another one' + bcolors.ENDC)
        
        # Close connection
        client.socket.close()

    def generateRandomKey(self):
        randomKey = os.urandom(16)
        return randomKey
