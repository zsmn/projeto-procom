from Crypto.PublicKey import RSA
from protocol import Client
from protocol import Protocol

if __name__ == '__main__':
    client = Client('localhost', 10011)
    client.connect()

    keyFile = open('serverPublicKey.txt', 'r')
    serverPublicKey = keyFile.read()

    try:
        # Create protocol
        protocol = Protocol()

        # Call client procedure
        protocol.clientProcedure(client, RSA.importKey(serverPublicKey))
    except Exception as e:
        print(e)
        client.socket.close()

    client.socket.close()