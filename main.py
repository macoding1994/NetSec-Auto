import random
import sys
import time

from PyQt5.QtGui import QTextCursor
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QPushButton, QLabel, QWidget, QTreeWidgetItem
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot
from Ui_main import Ui_MainWindow
import nmap
import datetime


class NmapWorkerThread(QThread):
    progress_signal = pyqtSignal(dict)

    def __init__(self, parent=None, host=None, ports=None, arguments=None, domain="", infoSignal=None):
        super(QThread, self).__init__(parent)

        self.nm = nmap.PortScanner()
        self.scan_ip = host
        self.ports = ports
        self.domain = domain
        self.arguments = arguments
        self.infoSignal = infoSignal

    def run(self):
        if self.infoSignal:
            self.infoSignal.emit(f"[{datetime.datetime.now()}] scan {self.scan_ip} {self.ports}  {self.arguments}")
        self.nm.scan(hosts=self.scan_ip, ports=self.ports, arguments=self.arguments)

        print(self.nm.all_hosts())
        try:
            port_list = self.nm[self.scan_ip]['tcp'].keys()
            print(port_list)
        except Exception as e:
            print(e)
        else:
            for port in port_list:
                if self.nm[self.scan_ip].has_tcp(port):
                    port_info = self.nm[self.scan_ip]['tcp'][port]
                    state = port_info.get('state', 'no')
                    if self.nm[self.scan_ip].get("osmatch"):
                        os_info = ",".join(
                            f"{info['name']}({info['accuracy']}%)"
                            for info in self.nm[self.scan_ip]["osmatch"]
                        )
                    else:
                        os_info = ""
                    if state == 'open':
                        name = port_info.get('name', '')
                        product = port_info.get('product', '')
                        version = port_info.get('version', '2.0')
                        service, protocol = product, name
                        port_data = {
                            "domain": self.domain,
                            "ip": self.scan_ip,
                            "port": port,
                            "service": service,
                            "protocol": protocol,
                            "version": version,
                            "os_info": os_info,
                        }
                        time.sleep(random.randint(1, 3))
                        self.progress_signal.emit(port_data)


class SodanWorkerThread(QThread):
    progress_signal = pyqtSignal(dict)

    def __init__(self, parent=None, host=None, infoSignal=None):
        super(QThread, self).__init__(parent)

        self.nm = nmap.PortScanner()
        self.scan_ip = host
        self.infoSignal = infoSignal

    def run(self):
        if self.infoSignal:
            self.infoSignal.emit(f"[{datetime.datetime.now()}] scan {self.scan_ip} {self.ports}  {self.arguments}")


class MainWindow(QMainWindow, Ui_MainWindow):
    thSignal = pyqtSignal(str, str)
    dbSignal = pyqtSignal(tuple)
    infoSignal = pyqtSignal(str)
    graphSignal = pyqtSignal(list)
    handleSignal = pyqtSignal(list)
    startTimerSignal = pyqtSignal()
    stopTimerSignal = pyqtSignal()
    equipmentTemperatureSignal = pyqtSignal(str)

    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setupUi(self)
        self.initPara()
        self.initDB()
        self.initDialog()
        self.initEvent()

    def initDB(self):
        pass

    def initDialog(self):
        pass

    def initEvent(self):
        self.infoSignal.connect(self.infoshow)

    def initPara(self):
        pass

    @pyqtSlot()
    def on_pushButton_clicked(self):
        self.getAssetInfo()

    def getVulnInfo(self):
        # 初始化工作线程
        pass

    def getAssetInfo(self):
        # 禁用按钮，避免重复启动任务
        self.pushButton.setEnabled(False)
        self.label.setText("任务进行中...")

        # 初始化工作线程
        self._thread = NmapWorkerThread(
            host=self.lineEdit.text(),
            ports=self.lineEdit_2.text(),
            arguments=self.comboBox.currentText(),
            infoSignal=self.infoSignal
        )
        self._thread.progress_signal.connect(self.updateAssetTreeWidget)  # 连接信号到更新函数
        self._thread.finished.connect(self.taskFinished)  # 线程结束后启用按钮
        self._thread.start()  # 开始线程

    def updateAssetTreeWidget(self, value):
        """更新任务进度"""

        domain = value['domain']
        ip = value['ip']
        os_info = value['os_info']
        port = value['port']
        service = value['service']
        protocol = value['protocol']
        version = value['version']
        self.infoSignal.emit(f"[{datetime.datetime.now()}] {value}")

        # item = self.treeWidget.currentItem() if self.treeWidget.currentItem() else self.treeWidget
        node = QTreeWidgetItem(self.treeWidget)
        node.setText(0, domain)
        node.setText(1, ip)
        node.setText(2, os_info)
        node.setText(3, str(port))
        node.setText(4, service)
        node.setText(5, protocol)
        node.setText(6, version)

    def taskFinished(self):
        """任务完成后的处理"""
        self.pushButton.setEnabled(True)  # 启用按钮

    def infoshow(self, res):
        if isinstance(res, str):
            self.textBrowser.append(res + '\n')
        else:
            self.textBrowser.append(str(res.result()) + '\n')
        self.textBrowser.moveCursor(QTextCursor.End)


def main():
    app = QApplication(sys.argv)
    ui = MainWindow()
    ui.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
