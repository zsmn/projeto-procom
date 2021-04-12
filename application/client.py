import sys, os
sys.path.append(os.path.abspath(os.path.join('..', 'protocol')))

from Crypto.PublicKey import RSA
from ui.ui import voteWindow
from protocol import Client
from protocol import Protocol
from PyQt5 import QtCore
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtWidgets import QApplication

if __name__ == '__main__':
    QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_ShareOpenGLContexts)
    app = QApplication([])

    client = Client('localhost', 10010)
    client.connect()

    keyFile = open('serverPublicKey.txt', 'r')
    serverPublicKey = keyFile.read()

    personsFile = open('persons.txt', 'r')
    persons = [line.strip() for line in personsFile.readlines()]

    # Invocar GUI
    widget = voteWindow(client, persons)
    widget.show()

    def vote(person):
        protocol.clientVote(client, person, RSA.importKey(serverPublicKey))
        client.socket.close()

    try:
        # Create protocol
        protocol = Protocol()

        # Connect gui to vote function
        widget.callVote.connect(vote)

        # Call client procedure
        protocol.clientProcedure(client, RSA.importKey(serverPublicKey))
    except Exception as e:
        print(e)
        client.socket.close()
        sys.exit()

    sys.exit(app.exec_())
