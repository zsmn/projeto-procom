import sys, os
sys.path.append(os.path.abspath(os.path.join('..', 'protocol')))

from protocol import Server
from protocol import Protocol
from _thread import start_new_thread


def serverProcedure(server, clientSocket, address):
    # Instantiate protocol
    protocol = Protocol()

    # Call client procedure
    protocol.serverProcedure(server, clientSocket, address)


if __name__ == '__main__':
    # Loading persons
    personsFile = open('persons.txt', 'r')
    persons = [line.strip() for line in personsFile.readlines()]

    server = Server('localhost', 10010, persons)
    server.connect()

    try:
        while True:
            connection, address = server.socket.accept()
            start_new_thread(serverProcedure, (server, connection, address))
    except KeyboardInterrupt:
        server.printVotes()
        server.socket.close()
        sys.exit()

    server.printVotes()
    server.socket.close()
    sys.exit()
