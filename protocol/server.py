import sys
from protocol import Server
from protocol import Protocol
from _thread import start_new_thread

def serverProcedure(server, clientSocket, address):
    # Instantiate protocol
    protocol = Protocol()

    # Call client procedure
    protocol.serverProcedure(server, clientSocket, address)

if __name__ == '__main__':
    server = Server('localhost', 10010, ['Zildinha', 'Vivi', 'Suruba'])
    server.connect()
    
    try:
        while True:
            connection, address = server.socket.accept()
            start_new_thread(serverProcedure, (server, connection, address))
    except KeyboardInterrupt:
        server.printVotes()
        server.socket.close()
        sys.exit()