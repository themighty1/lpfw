import sys, os, thread, time, string, threading, subprocess
from PyQt4.QtGui import QApplication, QStandardItem, QDialog, QIcon, QMenu, QSystemTrayIcon, QStandardItemModel, QAction, QMainWindow, QListWidget, QListWidgetItem, QWidget, QIntValidator, QStyledItemDelegate, QPainter, QStyleOptionViewItem, QFont, QTableWidgetItem, QPalette, QColor, QSortFilterProxyModel
import resource
from PyQt4.QtCore import pyqtSignal, Qt, QModelIndex, QRect, pyqtSlot, QVariant, QString
from PyQt4.QtNetwork import QHostInfo
from multiprocessing import Pipe, Process, Lock
import socket
import Queue
import resource_rc

from PyQt4 import QtCore, QtGui, uic

data_dir = os.path.dirname(os.path.realpath(__file__))
msgQueue = Queue.Queue()

#global vars
modellock = Lock()


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        uic.loadUi(os.path.join(data_dir, 'frontend.ui'), self)


class Ui_Dialog(object):
    def setupUi(self, DialogOut):
        uic.loadUi(os.path.join(data_dir, 'popup.ui'), self)


class queryDialog(QDialog):
    dns_lookup_id = 0
    host = 0
    path = ''
    pid = ''
    def __init__(self, direction):
        self.dns_lookup_id = 0  
        QDialog.__init__(self)
        self.setupUi(self)
        if (direction == 'OUT'):
            text = 'is trying to connect to'
        if (direction == 'IN'):
            text = 'is being connected to from'
        self.setWindowTitle("Leopard Flower firewall")
        self.label_text.setText(text)
        self.pushButton_allow.clicked.connect(self.allowClicked)
        self.pushButton_deny.clicked.connect(self.denyClicked)
        self.pushButton_hide.setVisible(False)
        self.tableWidget_details.setVisible(False)
        self.rejected.connect(self.escapePressed)
        self.finished.connect(self.dialogFinished)

        fullpath_text = QTableWidgetItem("Full path")
        self.tableWidget_details.setItem(0,0,fullpath_text)
        pid_text = QTableWidgetItem("Process ID")
        self.tableWidget_details.setItem(1,0,pid_text)
        remoteip_text = QTableWidgetItem("Remote IP")
        self.tableWidget_details.setItem(2,0,remoteip_text)
        remotedomain_text = QTableWidgetItem("Remote domain")
        self.tableWidget_details.setItem(3,0,remotedomain_text)
        remoteport_text = QTableWidgetItem("Remote port")
        self.tableWidget_details.setItem(4,0,remoteport_text)
        localport_text = QTableWidgetItem("Local port")
        self.tableWidget_details.setItem(5,0,localport_text)
        #make the incoming dialog stand out. It is not common to receive incoming connections
        if (direction == 'IN'):
            pal = QPalette()
            col = QColor(255, 0, 0, 127)
            pal.setColor(QPalette.Window, col)
            self.setPalette(pal)


    def escapePressed(self):
        "in case when user pressed Escape"
        print "in escapePressed"
        msgQueue.put('ADD\n' + bytearray(self.path, encoding='utf-8') + ' \n' + self.pid + '\nIGNORED')


    def closeEvent(self, event):
        "in case when user closed the dialog without pressing allow or deny"
        print "in closeEvent"
        msgQueue.put('ADD\n' + bytearray(self.path, encoding='utf-8') + '\n' + self.pid + '\nIGNORED')


    def allowClicked(self):
        print "allow clicked"
        if (self.checkBox.isChecked()): verdict = "ALLOW_ALWAYS"
        else: verdict = "ALLOW_ONCE"     
        msgQueue.put('ADD\n' + bytearray(self.path, encoding='utf-8') + '\n' + self.pid + '\n' + verdict)


    def denyClicked(self):
        print "deny clicked"
        if (self.checkBox.isChecked()): verdict = "DENY_ALWAYS"
        else: verdict = "DENY_ONCE"     
        msgQueue.put('ADD\n' + bytearray(self.path, encoding='utf-8') + '\n' + self.pid + '\n' + verdict)


    def dialogFinished(self):
        QHostInfo.abortHostLookup(self.dns_lookup_id)

    def dnsLookupFinished(self, host):
        if ( host.error() != QHostInfo.NoError):
            print "Lookup failed %s" %(host.errorString())
            return
        hostname = host.hostName()
        item = QTableWidgetItem(hostname)
        self.tableWidget_details.setItem(3,1,item)
        self.label_domain.setText(hostname)	


class myDialogOut(queryDialog, Ui_Dialog):
    def __init__(self):
        Ui_Dialog.__init__(self)
        queryDialog.__init__(self, 'OUT')			


class myDialogIn(queryDialog, Ui_Dialog):
    def __init__(self):
        Ui_Dialog.__init__(self)
        queryDialog.__init__(self, 'IN')


class myMainWindow(QMainWindow, Ui_MainWindow):
    askusersig = pyqtSignal(str, str, str, str, str, str) #connected to askUserOUT
    refreshmodelsig = pyqtSignal(str)
    update_bytestatssig = pyqtSignal(str)
    prevstats = ''
    model = None
    sourcemodel = None

    def __init__(self):
        QMainWindow.__init__(self)
        self.setupUi(self)
        self.setWindowTitle("Leopard Flower firewall")
        self.setWindowIcon(QIcon(":/pics/pic.jpg"))
        self.tableView.setShowGrid(False)
        self.menuRules.aboutToShow.connect(self.rulesMenuTriggered)
        self.menuRules.actions()[0].triggered.connect(self.deleteMenuTriggered)
        self.actionShow_active_only.triggered.connect(self.showActiveOnly)
        self.actionShow_all.triggered.connect(self.showAll)
        self.actionExit.triggered.connect(self.realQuit)
        self.askusersig.connect(self.askUser)
        self.update_bytestatssig.connect(self.update_bytestats)
        self.refreshmodelsig.connect(self.refreshmodel)
        msgQueue.put('LIST')        

    def showActiveOnly(self):
        self.model.toggle_mode_sig.emit('SHOW ACTIVE ONLY')
        self.actionShow_active_only.setEnabled(False)
        self.actionShow_all.setEnabled(True)
        self.actionShow_all.setChecked(False)
     
    def showAll(self):
        self.model.toggle_mode_sig.emit('SHOW ALL')        
        self.actionShow_active_only.setEnabled(True)
        self.actionShow_all.setEnabled(False)
        self.actionShow_active_only.setChecked(False)


    @pyqtSlot(str, str, str, str, str, str)
    def askUser(self, req_str_in, path_in, pid_in, addr_in, dport_in, sport_in):
        print "In askUser"
        #Convert all incoming QString into normal python strings
        req_str = str(req_str_in)
        path = unicode(QString.fromUtf8(path_in))
        pid = str(pid_in)
        addr = str(addr_in)
        dport = str(dport_in)
        sport = str(sport_in)
        if (req_str == 'REQUEST_OUT'):
            dialog = dialogOut
            rport = sport
            lport = dport
        elif (req_str == 'REQUEST_IN'):
            dialog = dialogOut            
            rport = dport
            lport = sport

        name = string.rsplit(path,"/",1)
        dialog.path = path
        dialog.pid = pid
        dialog.label_name.setText(name[1])
        dialog.label_ip.setText(addr)
        dialog.label_domain.setText("Looking up DNS...")        
        fullpath = QTableWidgetItem(unicode(QString.fromUtf8(path)))
        dialog.tableWidget_details.setItem(0,1,fullpath)
        pid_item = QTableWidgetItem(pid)
        dialog.tableWidget_details.setItem(1,1,pid_item)
        remoteip = QTableWidgetItem(addr)
        dialog.tableWidget_details.setItem(2,1,remoteip)
        dns = QTableWidgetItem("Looking up DNS...")
        dialog.tableWidget_details.setItem(3,1,dns)
        rport_item = QTableWidgetItem(rport)
        dialog.tableWidget_details.setItem(4,1,rport_item)
        lport_item = QTableWidgetItem(lport)
        dialog.tableWidget_details.setItem(5,1,lport_item)
        QHostInfo.lookupHost(addr, dialog.dnsLookupFinished)
        #we don't want the user to accidentally trigger ALLOW
        dialog.pushButton_deny.setFocus()
        dialog.show()



    def rulesMenuTriggered(self):
        "If no rules are selected in the view, grey out the Delete... item"
        if (len(self.tableView.selectedIndexes()) == 0):
            self.menuRules.actions()[0].setEnabled(False)
        else:
            self.menuRules.actions()[0].setEnabled(True)


    def deleteMenuTriggered(self):
        "send delete request to backend"
        selected_indexes = self.tableView.selectedIndexes()
        bFound = False
        for index in selected_indexes:
            if index.column() != 3: continue
            path = unicode(index.data().toPyObject())
            bFound = True
            break
        if not bFound:
            print 'Could not find the path to delete'
            return
        msgQueue.put('DELETE\n' + bytearray(path, encoding='utf-8'))
    

    def closeEvent(self, event):
        event.ignore()
        self.hide()


    def realQuit(self): 
        print "see you later..."
        msgQueue.put('UNREGISTER')
        time.sleep(2) #allow queue to be processed
        exit(1)

    @pyqtSlot(unicode)
    def refreshmodel(self, data_in):  
        "Fill the frontend with rules data"
        rawstr = unicode(QString.fromUtf8(data_in))

        export_list = []            
        rules = rawstr[len('RULES_LIST\n'):].split(' CRLF ')[:-1]
        for one_rule in rules: 
            split_rule = one_rule.split('\n')
            if len(split_rule) != 5: continue
            export_list.append(split_rule)
        export_list.append("EOF")
        ruleslist = export_list
        #empty the model, we're filling it anew, we can't use clear() cause it flushes headers too:
        modellock.acquire()
        self.sourcemodel.layoutAboutToBeChanged.emit()
        self.sourcemodel.removeRows(0, self.sourcemodel.rowCount())
    
        #if there's only one element, it's EOF; dont go through iterations,just leave the model empty
        if (len(ruleslist) == 1):
            self.sourcemodel.layoutChanged.emit()            
            modellock.release()
            return
        for item in ruleslist[0:-1]:#leave out the last EOF from iteration
            path = item[0]
            fullpath = QStandardItem(path)
            #item[4] contains nfmark
            fullpath.setData(item[4])
            if (item[1] == "0"):
                pid_string = "N/A"
            else: 
                pid_string = item[1]
            pid = QStandardItem(pid_string)
            perms = QStandardItem(item[2])
            #only the name of the executable after the last /
            m_list = string.rsplit(path,"/",1)
            m_name = m_list[1]
            name = QStandardItem(m_name)
            in_allow_traf = QStandardItem()
            out_allow_traf = QStandardItem()
            in_deny_traf = QStandardItem()
            out_deny_traf = QStandardItem()
            self.sourcemodel.appendRow( (name, pid, perms, fullpath,
                                 in_allow_traf, out_allow_traf, in_deny_traf, out_deny_traf) ) 
            #print "Received: %s" %(item[0])
        self.sourcemodel.layoutChanged.emit()                    
        modellock.release()
        self.update_bytestats()        


    #Update and remember the stats. The stats may be restored from 
    #a previous save when model refreshes
    @pyqtSlot(str)
    def update_bytestats(self, data_in = ''):
        data = str(data_in)
        items = []
        if (data):
            message = data.split('EOL')[-2] #discard the last empty one and take the one before it
            #take the last message with 5 elements as it is the most recent one
            items = message.split(' CRLF ')[:-1] #discard the last empty one
        if (items):
            self.prevstats = items
        else:
            items = self.prevstats
        #one item looks like '1212 3232 3243 4343 43434'
        modellock.acquire()
        self.sourcemodel.layoutAboutToBeChanged.emit()                    
        for one_item in items:
            fields = one_item.split(' ')
            for j in range(self.sourcemodel.rowCount()):
                #4th element of each line has nfmark in its data field
                if (self.sourcemodel.item(j,3).data().toString() != fields[0]): continue
                #else
                self.sourcemodel.item(j,4).setText(fields[1])
                self.sourcemodel.item(j,5).setText(fields[2])
                self.sourcemodel.item(j,6).setText(fields[3])
                self.sourcemodel.item(j,7).setText(fields[4])
                break
        self.sourcemodel.layoutChanged.emit()                    
        modellock.release()   



class CustomDelegate (QStyledItemDelegate):
    def __init__ (self):
        QStyledItemDelegate.__init__(self)
    def paint (self, painter, option, index):
        model = index.model()
        item = model.data(index).toPyObject()
        if item == None:
            return
        text = str(item)
        if (len(text) > 6):
            # take only megabytes -->12<--345678
            mb = text[:len(text)-6]
            bytes = text[len(text)-6:]
            painter.setPen (Qt.red)
            painter.drawText (option.rect,Qt.AlignHCenter and Qt.AlignVCenter, mb)
            painter.setPen (Qt.black)
            rect = QRect()
            rect = option.rect
            rect.setX(rect.x()+8*(len(mb)))  
            painter.drawText (rect, Qt.AlignHCenter and Qt.AlignVCenter, bytes)
        else:
            painter.drawText (option.rect, Qt.AlignHCenter and Qt.AlignVCenter, text)




def conntrackThread():
    with open('/tmp/lpfwctport', 'r') as f: ctport = f.read()    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', int(ctport)))
    sock.settimeout(1)
    while True:
        data = ''
        try: 
            data  = sock.recv(8192)
        except: 
            continue
        if not data:
            time.sleep(1) 
            continue
        #print ('RECEIVED: ' + data)
        window.update_bytestatssig.emit(data)
       


def communicationThread():
    with open('/tmp/lpfwcommport', 'r') as f: commport = f.read()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', int(commport)))
    sock.settimeout(1)
    while True:
        try: 
            send_data = ''            
            send_data = msgQueue.get_nowait()
            print ('Sending:', send_data)
            sock.send(send_data)
        except Queue.Empty: 
            pass #no data in msgQueue
        try: 
            data = ''
            data  = sock.recv(8192)
        except: 
            continue
        if not data:
            time.sleep(1) 
            continue

        #print ('RECEIVED: ' + data)
        messages = data.split('EOL')
        rules_list = ''
        request = ''
        #the last rules_list it is the most recent one
        for msg in messages[::-1]:
            if not msg.startswith('RULES_LIST'): continue
            #else
            rules_list = msg
            break
        #take the first REQUEST (there should be only one anyway)
        for msg in messages:
            if not msg.startswith('REQUEST'): continue
            #else
            request = msg
            break
        if (rules_list):
            window.refreshmodelsig.emit(rules_list)
        if (request):
            split_request = request.split('\n')
            req_str = split_request[0]
            path = split_request[1]
            pid = split_request[2]
            addr = split_request[4]
            dport = split_request[5]
            sport = split_request[6]
            window.askusersig.emit(req_str, path, pid, addr, dport, sport)


class myModel(QStandardItemModel):
    layout_changed_sig = pyqtSignal()
    
    def __init__(self):
        QStandardItemModel.__init__(self)
        self.layout_changed_sig.connect(self.layout_changed)
        self.setHorizontalHeaderLabels(("Name","Process ID","Permission",
                                              "Full path","Allowed in","Allowed out",
                                              "Denied in","Denied out"))
        
    @pyqtSlot()
    def layout_changed(self):
        self.layoutAboutToBeChanged.emit()
        self.layoutChanged.emit()

        
   
class mySortFilterProxyModel(QSortFilterProxyModel):
    toggle_mode_sig = pyqtSignal(str)
    mode = 'SHOW ALL'
              
    def __init__(self):
        QSortFilterProxyModel.__init__(self) 
        self.toggle_mode_sig.connect(self.toggle_mode)        
        
    @pyqtSlot(str)
    def toggle_mode(self, mode_in):
        mode = str(mode_in)
        self.mode = mode
        self.sourceModel().layoutAboutToBeChanged.emit()
        self.sourceModel().layoutChanged.emit() 
       

    def headerData(self, section, orientation, role):
        if orientation != Qt.Vertical or role != Qt.DisplayRole:
            return QSortFilterProxyModel.headerData(self, section, orientation, role)
        return section+1

   
    def filterAcceptsRow(self, row, parent):
        if self.mode == 'SHOW ALL':
            return True
        #else mode == 'SHOW ACTIVE ONLY'
        smodel = self.sourceModel()
        pid = str(smodel.itemFromIndex(smodel.index(row,1)).text())
        if (pid == 'N/A'):
            return False
        else:
            return True
        

    def lessThan(self, left, right):
        if left.column() not in (1,4,5,6,7):
            return QSortFilterProxyModel.lessThan(self, left, right)
        model = self.sourceModel()
        try:
            leftint = int(model.data(left).toPyObject())
        except:
            leftint = 0
        try:
            rightint = int(model.data(right).toPyObject())
        except:
            rightint = 0
        return  leftint < rightint




if __name__ == "__main__":
    #don't clutter console with debuginfo
    if (len(sys.argv) <= 1 or sys.argv[1] != "debug"):
    #I don't know how to redirect output to /dev/null so just make a tmp file until I figure out
    #logfile = open("/dev/null", "w")
    #sys.stdout = logfile
        pass
    elif (sys.argv[1] != "debug"):
        import wingdbstub

    app=QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    window = myMainWindow()

    tray = QSystemTrayIcon(QIcon(":/pics/pic24.png"))
    menu = QMenu()
    actionShow = QAction("Show Leopard Flower",menu)
    actionExit = QAction("Exit",menu)
    menu.addAction(actionShow)
    menu.addAction(actionExit)
    tray.setContextMenu(menu)
    tray.show()
    actionShow.triggered.connect(window.show)
    actionExit.triggered.connect(window.realQuit)

    sourcemodel = myModel()  
    model = mySortFilterProxyModel()
    model.setSourceModel(sourcemodel)
    model.setDynamicSortFilter(True)

    window.tableView.setSortingEnabled(True)
    window.tableView.setModel(model)
    window.model = model
    window.sourcemodel = sourcemodel

    delegate = CustomDelegate()    
    window.tableView.setItemDelegateForColumn(4,delegate)
    window.tableView.setItemDelegateForColumn(5,delegate)
    window.tableView.setItemDelegateForColumn(6,delegate)
    window.tableView.setItemDelegateForColumn(7,delegate)

    dialogOut = myDialogOut()
    dialogIn = myDialogIn()

    thread = threading.Thread(target= communicationThread)
    thread.daemon = True
    thread.start()
    thread = threading.Thread(target= conntrackThread)
    thread.daemon = True
    thread.start()

    window.show()
    sys.exit(app.exec_())