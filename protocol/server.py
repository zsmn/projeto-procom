from protocol import Server
from protocol import Protocol
import threading

def serverProcedure(server, clientSocket, address):
    # Instantiate protocol
    protocol = Protocol()

    # Call client procedure
    protocol.serverProcedure(server, clientSocket, address)

if __name__ == '__main__':
    server = Server('localhost', 10011)
    server.connect()
    
    try:
        while True:
            connection, address = server.socket.accept()
            threading.Thread(target=serverProcedure(server, connection, address)).start()
    except Exception as e:
        print(e)
        server.socket.close()

    server.socket.close()