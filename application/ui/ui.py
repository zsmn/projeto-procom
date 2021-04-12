from PyQt5 import uic
from PyQt5.QtCore import Qt, QRect, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QBrush, QImage, QPainter, QPixmap, QWindow
from PyQt5.QtWidgets import QHBoxLayout, QGridLayout, QFrame, QLabel, QMainWindow, QDesktopWidget, QGraphicsDropShadowEffect


def mask_image(imgdata, imgtype='jpg', size=64):
    # Load image
    image = QImage.fromData(imgdata, imgtype)

    # convert image to 32-bit ARGB (adds an alpha
    # channel ie transparency factor):
    image.convertToFormat(QImage.Format_ARGB32)

    # Crop image to a square:
    imgsize = min(image.width(), image.height())
    rect = QRect(
        (image.width() - imgsize) / 2,
        (image.height() - imgsize) / 2,
        imgsize,
        imgsize,
     )

    image = image.copy(rect)

    # Create the output image with the same dimensions
    # and an alpha channel and make it completely transparent:
    out_img = QImage(imgsize, imgsize, QImage.Format_ARGB32)
    out_img.fill(Qt.transparent)

    # Create a texture brush and paint a circle
    # with the original image onto the output image:
    brush = QBrush(image)

    # Paint the output image
    painter = QPainter(out_img)
    painter.setBrush(brush)

    # Don't draw an outline
    painter.setPen(Qt.NoPen)

    # drawing circle
    painter.drawEllipse(0, 0, imgsize, imgsize)

    # closing painter event
    painter.end()

    # Convert the image to a pixmap and rescale it.
    pr = QWindow().devicePixelRatio()
    pm = QPixmap.fromImage(out_img)
    pm.setDevicePixelRatio(pr)
    size *= pr
    pm = pm.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)

    # return back the pixmap data
    return pm


class person(QFrame):
    disablePersons = pyqtSignal()

    def __init__(self, personName):
        super().__init__()

        # Setting default values
        self.personName = personName
        self.focus = False
        self.setLayout(QGridLayout(self))
        self.setPerson(personName)
        self.removeFocus()

        # Hovering and press events
        self.mouseReleaseEvent = self.castDisable

        # Set color style
        self.updateStyleSheet('#2e3436')

    def castDisable(self, event):
        self.disablePersons.emit()
        self.setFocus()

    def removeFocus(self):
        self.focus = False
        self.updateStyleSheet('#2e3436')

    def setFocus(self):
        self.focus = True
        self.updateStyleSheet('#454e51')

    def updateStyleSheet(self, bgColor):
        self.setStyleSheet("QFrame{background-color:" + bgColor + ";}")

    def setPerson(self, personName):
        person = QLabel(self)
        imgdata = open("../img/" + personName.lower() + ".jpg", 'rb').read()
        person.setPixmap(mask_image(imgdata, 'jpg', 128))
        person.setGeometry(40, 30, 128, 128)
        person.setScaledContents(True)

        label = QLabel(self)
        label.setText(personName)
        label.setFont(QFont('URW Bookman', 16))
        label.setGeometry(0, 170, 209, 21)
        label.setAlignment(Qt.AlignCenter)


class voteWindow(QMainWindow):
    callVote = pyqtSignal(str)

    def __init__(self, client, loadedPersons):
        super(voteWindow, self).__init__()
        self.ui = uic.loadUi("ui/ui.ui", self)
        self.client = client

        # Removing top bar
        self.setWindowFlag(Qt.FramelessWindowHint)

        # Shadow
        self.shadow = QGraphicsDropShadowEffect(self)
        self.shadow.setBlurRadius(20)
        self.shadow.setXOffset(0)
        self.shadow.setYOffset(0)
        self.shadow.setColor(QColor(0, 0, 0, 60))
        self.ui.frame.setGraphicsEffect(self.shadow)

        # Setting layout and resizing
        self.ui.frame.setLayout(QHBoxLayout())
        self.resizeWindow(len(loadedPersons))

        # Center screen
        resolution = QDesktopWidget().screenGeometry()
        self.move((resolution.width() / 2) - (self.frameSize().width() / 2),
                  (resolution.height() / 2) - (self.frameSize().height() / 2))

        # Add persons
        self.persons = []

        for i in loadedPersons:
            self.addPerson(person(i))

        # Connect persons to disable slot
        for i in self.persons:
            i.disablePersons.connect(self.disablePersonsSlot)

    def keyPressEvent(self, e):
        if ((e.key() == Qt.Key_Return) or (e.key() == Qt.Key_Enter)):
            person = ""
            status = False

            for i in self.persons:
                if(i.focus):
                    person = i.personName
                    status = True

            if(status):
                self.callVote.emit(person)
                self.close()

    def resizeWindow(self, qtPersons, personWidth=210, personHeight=220):
        self.resize(personWidth*qtPersons, personHeight)
        self.ui.frame.resize(personWidth*qtPersons, personHeight)

    def addPerson(self, person):
        self.persons.append(person)
        self.ui.frame.layout().addWidget(person)

    def disablePersonsSlot(self):
        for i in self.persons:
            i.removeFocus()
