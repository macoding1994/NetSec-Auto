import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, ALL_COMPLETED, wait

from PyQt5.QtGui import QTextCursor
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QPushButton, QLabel, QWidget, QTreeWidgetItem
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot
from Ui_main import Ui_MainWindow
import nmap
import datetime
from data import create_table, insert_data
from tool import resolv_ips


class NmapWorkerThread(QThread):
    progress_signal = pyqtSignal(dict)

    def __init__(self, parent=None, hosts=None, ports=None, arguments=None, domain="", infoSignal=None):
        super(QThread, self).__init__(parent)

        self.ports = ports
        self.domain = domain
        self.arguments = arguments
        self.infoSignal = infoSignal

        self.scan_ip_list, _ = resolv_ips([hosts])

    def run(self):
        all_task = []
        # 使用tqdm创建一个进度条
        with ThreadPoolExecutor(max_workers=12) as executor:
            # 创建一个Future对象列表
            for scan_ip in self.scan_ip_list:
                # 提交任务到线程池
                future = executor.submit(self.scanPort, self.domain, scan_ip, self.ports, self.arguments)
                # 将Future对象添加到列表中
                all_task.append(future)
        wait(all_task, return_when=ALL_COMPLETED)

    def scanPort(self, domain, scan_ip, ports, arguments):
        if self.infoSignal:
            self.infoSignal.emit(f"[{datetime.datetime.now()}] scan {scan_ip} {ports}  {arguments}")

        nm = nmap.PortScanner()
        nm.scan(hosts=scan_ip, ports=ports, arguments=arguments)
        try:
            port_list = nm[scan_ip]['tcp'].keys()
        except Exception as e:
            print(e)
        else:
            for port in port_list:
                if nm[scan_ip].has_tcp(port):
                    port_info = nm[scan_ip]['tcp'][port]
                    state = port_info.get('state', 'no')
                    if nm[scan_ip].get("osmatch"):
                        os_info = ",".join(
                            f"{info['name']}({info['accuracy']}%)"
                            for info in nm[scan_ip]["osmatch"]
                        )
                    else:
                        os_info = ""
                    if state == 'open':
                        name = port_info.get('name', '')
                        product = port_info.get('product', '')
                        version = port_info.get('version', '2.0')
                        service, protocol = product, name
                        port_data = {
                            "domain": domain,
                            "ip": scan_ip,
                            "port": port,
                            "service": service,
                            "protocol": protocol,
                            "version": version,
                            "os_info": os_info,
                        }
                        time.sleep(random.randint(1, 3))
                        insert_data(port_data)
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
        self.initAseertTree()

    def initDB(self):
        create_table()

    def initDialog(self):
        pass

    def initEvent(self):
        self.infoSignal.connect(self.infoshow)

    def initPara(self):
        pass

    def initAseertTree(self):
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
            hosts=self.lineEdit.text(),
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

        # 检查是否已经存在相同 domain 和 IP 的顶级节点
        existing_node = None
        for i in range(self.treeWidget.topLevelItemCount()):
            top_node = self.treeWidget.topLevelItem(i)
            if top_node.text(0) == domain and top_node.text(1) == ip:  # 检查 domain 和 IP 是否匹配
                existing_node = top_node
                break

        if existing_node is None:
            # 如果不存在相同 domain 和 IP 的节点，创建一个新的顶级节点
            top_node = QTreeWidgetItem(self.treeWidget)
            top_node.setText(0, domain)
            top_node.setText(1, ip)
            top_node.setText(2, os_info)
            top_node.setText(3, "")  # 顶级节点不需要端口
            top_node.setText(4, "")  # 顶级节点不需要服务信息
            top_node.setText(5, "")  # 顶级节点不需要协议
            top_node.setText(6, "")  # 顶级节点不需要版本信息
            existing_node = top_node

        # 检查是否已存在相同端口的子节点
        port_exists = False
        for i in range(existing_node.childCount()):
            child_node = existing_node.child(i)
            if child_node.text(3) == str(port):  # 检查端口是否匹配
                port_exists = True
                break

        if not port_exists:
            # 添加子节点（端口信息）
            child_node = QTreeWidgetItem(existing_node)
            child_node.setText(0, "")  # 子节点不需要域名
            child_node.setText(1, "")  # 子节点不需要 IP
            child_node.setText(2, "")  # 子节点不需要操作系统信息
            child_node.setText(3, str(port))
            child_node.setText(4, service)
            child_node.setText(5, protocol)
            child_node.setText(6, version)

            # 展开顶级节点以显示子节点
            existing_node.setExpanded(True)

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
