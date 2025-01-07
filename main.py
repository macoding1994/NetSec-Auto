import copy
import json
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, ALL_COMPLETED, wait
import os
import pandas as pd
import plotly.express as px
from PyQt5.QtGui import QTextCursor
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QPushButton, QLabel, QWidget, QTreeWidgetItem, \
    QTableWidgetItem
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot, QTimer, QUrl
from Ui_main import Ui_MainWindow
import nmap
import datetime

from botpress import Botpress
from data import create_table, insert_port_data, insert_shodan_data
from myshodan import get_host_info, get_vulnerabilities_info
from tool import resolv_ips, login, call_scanner_api, fetch_task_list, fetch_task_vulnerabilities, fetch_task_ip_assets, \
    get_vuln_info


class BaseWorkerThread(QThread):
    data_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int)

    def __init__(self, parent=None, hosts=None, ports=None, arguments=None, domain="", infoSignal=None):
        super(QThread, self).__init__(parent)
        self.ports = ports
        self.domain = domain
        self.arguments = arguments
        self.infoSignal = infoSignal
        self.scan_ip_list, _ = resolv_ips([hosts])
        print(self.scan_ip_list)

    def run(self):
        all_task = []
        # 使用tqdm创建一个进度条
        with ThreadPoolExecutor(max_workers=4) as executor:
            # 创建一个Future对象列表
            for scan_ip in self.scan_ip_list:
                # 提交任务到线程池
                future = executor.submit(self.scan, self.domain, scan_ip, self.ports, self.arguments)
                # 将Future对象添加到列表中
                all_task.append(future)
            # 检查任务状态
            while not all(future.done() for future in all_task):
                is_done_task = 0
                for future in all_task:
                    if future.running():
                        is_done_task += 0.3
                    if future.done():
                        is_done_task += 1
                self.progress_signal.emit(int(is_done_task / len(all_task) * 100))
                time.sleep(0.3)
        wait(all_task, return_when=ALL_COMPLETED)


class NmapWorkerThread(BaseWorkerThread):

    def scan(self, domain, scan_ip, ports, arguments):
        nm = nmap.PortScanner()
        nm.scan(hosts=scan_ip, ports=ports, arguments=arguments)
        if self.infoSignal:
            self.infoSignal.emit(f"[{datetime.datetime.now()}] Namp scan:   {nm.command_line()}")
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
                        data = {
                            "domain": domain,
                            "ip": scan_ip,
                            "port": port,
                            "service": service,
                            "protocol": protocol,
                            "version": version,
                            "os_info": os_info,
                        }
                        time.sleep(random.randint(1, 3))
                        insert_port_data(data)
                        self.data_signal.emit(data)


class SodanWorkerThread(BaseWorkerThread):

    def scan(self, domain, scan_ip, ports, arguments):
        if self.infoSignal:
            self.infoSignal.emit(f"[{datetime.datetime.now()}] shodan scan:   {scan_ip} ")
        info = get_host_info(scan_ip)
        if "vulns" in info:
            for cve_id in info['vulns']:
                cve_name, cve_id, cve_cvss, cve_cvss3, cve_summary, cve_references = get_vulnerabilities_info(cve_id)
                data = {
                    "ip": scan_ip,
                    "lat": f"{info['latitude']}",
                    "lon": f"{info['longitude']}",
                    "cve_id": cve_id,
                    "cve_name": cve_name,
                    "cve_cvss": cve_cvss,
                    "cve_cvss3": cve_cvss3,
                    "cve_summary": cve_summary,
                    "cve_references": cve_references,
                }
                insert_shodan_data(data)
                self.data_signal.emit(data)
        else:
            data = {
                "ip": scan_ip,
                "lat": info['latitude'],
                "lon": info['longitude'],
            }


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
        # 为 tab_5 添加布局
        self.chart_layout = QVBoxLayout(self.tab_5)

        # 创建资产和漏洞图表的 Web 视图
        self.asset_chart_view = QWebEngineView()
        self.vuln_chart_view = QWebEngineView()

        # 添加图表 Web 视图到布局
        self.chart_layout.addWidget(self.asset_chart_view)
        self.chart_layout.addWidget(self.vuln_chart_view)

    def initEvent(self):
        self.infoSignal.connect(self.infoshow)

    def initPara(self):
        self.token = None
        self.cookies = None

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_task_list)
        self.existing_ids = set()  # 用于存储已显示的任务 ID

        self.bot = Botpress("config.json")
        self.vuln_tables_data = []
        self.asset_tables_data = []

    def initAseertTree(self):
        pass

    @pyqtSlot()
    def on_pushButton_clicked(self):
        self.getAssetInfo()

    @pyqtSlot()
    def on_pushButton_2_clicked(self):
        self.getVulnInfo()

    def getVulnInfo(self):
        # 禁用按钮，避免重复启动任务
        self.pushButton.setEnabled(False)
        # 初始化工作线程
        self._thread1 = SodanWorkerThread(
            hosts=self.lineEdit.text(),
            infoSignal=self.infoSignal
        )
        self._thread1.data_signal.connect(self.updateVulnTreeWidget)  # 连接信号到更新函数
        self._thread1.finished.connect(self.taskFinished)  # 线程结束后启用按钮
        self._thread1.start()  # 开始线程

    def getAssetInfo(self):
        # 禁用按钮，避免重复启动任务
        self.pushButton.setEnabled(False)
        # 初始化工作线程
        self._thread = NmapWorkerThread(
            hosts=self.lineEdit.text(),
            ports=self.lineEdit_2.text(),
            arguments=self.comboBox.currentText(),
            infoSignal=self.infoSignal
        )
        self._thread.data_signal.connect(self.updateAssetTreeWidget)  # 连接信号到更新函数
        self._thread.progress_signal.connect(self.updateProgress)  # 连接信号到更新函数
        self._thread.finished.connect(self.taskFinished)  # 线程结束后启用按钮
        self._thread.start()  # 开始线程

    def updateVulnTreeWidget(self, value):
        """更新任务进度"""
        self.infoSignal.emit(f"[{datetime.datetime.now()}] {value}")
        if not hasattr(self, 'vuln_summary'):
            self.vuln_summary = {}

        value1 = copy.deepcopy(value)
        del value1['id']
        self.vuln_tables_data.append(self.value2str(value1))
        current_colum = self.tableWidget_2.columnCount()
        current_row = self.tableWidget_2.rowCount()
        self.tableWidget_2.insertRow(current_row)
        data_list = [str(value[k]) for k in value]
        ip = data_list[-2]
        id = data_list[0]

        for col_idx, cell_data in enumerate(data_list[:current_colum]):
            if ip not in self.vuln_summary:
                self.vuln_summary[ip] = {
                    "id_list": [id],
                    "data_list": [data_list]
                }
            if id not in self.vuln_summary[ip]["id_list"]:
                self.vuln_summary[ip]["id_list"].append(id)
                self.vuln_summary[ip]["data_list"].append(data_list)
            item = QTableWidgetItem(cell_data)
            if len(cell_data) >= 10:
                item.setToolTip(cell_data)
            self.tableWidget_2.setItem(current_row, col_idx, item)

    def updateAssetTreeWidget(self, value):
        """更新任务进度并统计资产信息"""
        # 初始化资产统计字典
        if not hasattr(self, 'asset_summary'):
            self.asset_summary = {}
        value1 = copy.deepcopy(value)
        del value1['id']
        self.asset_tables_data.append(self.value2str(value1))
        # 获取数据
        domain = value.get('domain', '')
        ip = value['ip']
        os_info = value.get('os_info', '')
        port = value['port']
        service = value['service']
        protocol = value['protocol']
        version = value['version']

        # 更新信息到树控件
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

        # 更新资产统计字典
        if ip not in self.asset_summary:
            self.asset_summary[ip] = {
                'domain': domain,
                'os_info': os_info,
                'ports': []
            }

        # 检查端口是否已存在
        if port not in [p['port'] for p in self.asset_summary[ip]['ports']]:
            self.asset_summary[ip]['ports'].append({
                'port': port,
                'service': service,
                'protocol': protocol,
                'version': version
            })

        # 打印统计结果（可选，调试时使用）
        print("资产统计：", self.asset_summary)

    def value2str(self, data_dict):
        return {
            k: str(data_dict[k])[:255]
            for k in data_dict
        }

    def updateProgress(self, value):
        # 更新进度条值
        self.progressBar.setValue(value)

    def taskFinished(self):
        """任务完成后的处理"""
        self.pushButton.setEnabled(True)  # 启用按钮
        self.progressBar.setValue(100)

    def infoshow(self, res):
        if isinstance(res, str):
            self.textBrowser.append(res + '\n')
        else:
            self.textBrowser.append(str(res.result()) + '\n')
        self.textBrowser.moveCursor(QTextCursor.End)

    def login(self):
        host_url = self.lineEdit_3.text()
        account = self.lineEdit_4.text()
        password = self.lineEdit_5.text()
        print(password)
        if not self.token or not self.cookies:
            response = login(host_url, account, password)
            print(response)
            if response and "token" in response and "cookies" in response:
                self.token = response["token"]
                self.cookies = response["cookies"]

    def get_properties(self, data_list):
        properties_list = [k for k in data_list[0]]
        return {
            p: {
                "type": "string",
                "x-zui": {
                    "index": properties_list.index(p),
                    "typings": "",
                    "searchable": True
                },
                "nullable": True
            }

            for p in properties_list
        }

    @pyqtSlot()
    def on_pushButton_3_clicked(self):
        """
        update bootpress
        :return:
        """
        vuln_tables = "vulnTable"
        asset_tables = "assetTable"

        for tables in self.bot.get_tables_list()['tables']:
            if tables["name"] in [vuln_tables, asset_tables]:
                self.bot.delete_table_rows(tables["name"])
        print("Creating tables...")
        # self.bot.create_table(asset_tables, self.get_properties(self.asset_tables_data))
        # self.bot.create_table(vuln_tables, self.get_properties(self.vuln_tables_data))

        chunk_size = 5
        for i in range(0, len(self.vuln_tables_data), chunk_size):
            chunk = self.vuln_tables_data[i:i + chunk_size]
            print("Vulnerability rows added:", json.dumps(chunk, indent=2))
            self.bot.add_rows(vuln_tables, {"rows": chunk})
        # self.bot.add_rows(vuln_tables, {"rows": self.vuln_tables_data})
        self.bot.add_rows(asset_tables, {"rows": self.asset_tables_data})

    def refresh_task_list(self):
        """
        定时刷新任务列表，按照 ID 更新对应行数据。
        """
        host_url = self.lineEdit_3.text()
        self.login()  # 确保用户已登录获取 token 和 cookies
        if self.token and self.cookies:
            response = fetch_task_list(host_url, self.token, self.cookies)
            column_list = self.print_column_headers()

            for data in response.get('data', []):
                task_id = data.get("id")  # 获取唯一标识 ID
                if task_id is None:
                    continue  # 如果没有 ID，跳过

                # 查找表格中是否已有该 ID 的行
                row_to_update = -1
                for row in range(self.tableWidget.rowCount()):
                    if self.tableWidget.item(row, column_list.index("id")) and \
                            self.tableWidget.item(row, column_list.index("id")).text() == str(task_id):
                        row_to_update = row
                        break

                # 如果找到行，更新该行数据；否则插入新行
                if row_to_update >= 0:
                    # 更新行数据
                    for column in column_list:
                        value = data.get(column, "")
                        if column == "progress" and isinstance(value, dict):  # 如果是进度字段的复杂类型
                            value = value.get("total_progress", "")
                        self.tableWidget.setItem(row_to_update, column_list.index(column), QTableWidgetItem(str(value)))
                else:
                    # 插入新行
                    row_position = self.tableWidget.rowCount()
                    self.tableWidget.insertRow(row_position)
                    for column in column_list:
                        value = data.get(column, "")
                        if column == "progress" and isinstance(value, dict):
                            value = value.get("total_progress", "")
                        self.tableWidget.setItem(row_position, column_list.index(column), QTableWidgetItem(str(value)))

    @pyqtSlot()
    def on_pushButton_4_clicked(self):
        """
        开始定时刷新任务列表
        """
        self.refresh_task_list()
        refresh_interval = 5000  # 定时器刷新间隔，单位为毫秒（此处为 5 秒）
        self.refresh_timer.start(refresh_interval)
        print("任务列表刷新定时器已启动！")

    def print_column_headers(self):
        column_count = self.tableWidget.columnCount()
        return [self.tableWidget.horizontalHeaderItem(col).text() for col in range(column_count) if
                self.tableWidget.horizontalHeaderItem(col)]

    def reset_headers(self, new_headers):
        # 获取新标题的列数
        new_column_count = len(new_headers)

        # 删除现有的列标题（调整列数）
        self.tableWidget_2.setColumnCount(new_column_count)

        # 设置新的列标题
        self.tableWidget_2.setHorizontalHeaderLabels(new_headers)

    @pyqtSlot(int, int)
    def on_tableWidget_cellDoubleClicked(self, row, column):
        filter_list = ["number", "tasks", "company_name", "task_visible", "is_read", "type", "dealuser"]
        if self.token and self.cookies:
            host_url = self.lineEdit_3.text()
            # self.tableWidget_2
            vuln_id_list = []
            for data in fetch_task_vulnerabilities(host_url, self.token, self.cookies,
                                                   int(self.tableWidget.item(row, column).text()))['data']:
                vuln_id_list.extend(data["risk_id_list"])

            for vuln_id in vuln_id_list:
                data = get_vuln_info(host_url, self.token, self.cookies, int(vuln_id))
                data_key_list = [k for k in data if k not in filter_list]
                for i in filter_list:
                    del data[i]
                if self.tableWidget_2.columnCount() != len(data_key_list):
                    self.reset_headers(data_key_list)
                self.updateVulnTreeWidget(data)
            # self.treeWidget
            for date in \
                    fetch_task_ip_assets(host_url, self.token, self.cookies,
                                         int(self.tableWidget.item(row, column).text()))[
                        'data']:
                self.updateAssetTreeWidget(date)

    @pyqtSlot()
    def on_pushButton_5_clicked(self):
        host_url = self.lineEdit_3.text()
        self.login()
        if self.token and self.cookies:
            ip = self.lineEdit.text()
            portRange = self.lineEdit_2.text()
            print(call_scanner_api(host_url, self.token, self.cookies, f"task_{int(time.time())}", ip, portRange))

    def show_asset_chart(self):
        """生成并展示资产数据图表（x轴是IP，y轴是端口数和服务数）"""
        # 从资产统计字典中提取数据
        if not hasattr(self, 'asset_summary') or not self.asset_summary:
            print("资产统计数据为空，无法生成图表！")
            return

        ip_list = []
        port_count_list = []
        service_count_list = []
        vuln_count_list = []

        # 解析资产统计数据
        for ip, info in self.asset_summary.items():
            ip_list.append(ip)
            ports = info['ports']
            port_count_list.append(len(ports))
            service_count_list.append(len(set(p['service'] for p in ports if p['service'] != "--")))
            if ip in self.vuln_summary:
                vuln_count_list.append(len(self.vuln_summary[ip]["id_list"]))
            else:
                vuln_count_list.append(0)

        # 创建 DataFrame
        data = pd.DataFrame({
            "IP": ip_list,
            "port": port_count_list,
            "server": service_count_list,
            "vuln": vuln_count_list
        })

        # 使用 Plotly 创建分组条形图
        fig = px.bar(
            data,
            x="IP",
            y=["port", "server", "vuln"],
            title="Asset data distribution (IP and port count/vulnerability count).",
            labels={"value": "count", "variable": "type"},
            barmode="group"  # 分组条形图
        )

        # 保存图表为 HTML 文件
        chart_path = os.path.abspath("asset_chart.html")
        fig.write_html(chart_path)

        # 在 Web 视图中展示
        self.asset_chart_view.setUrl(QUrl.fromLocalFile(chart_path))

    def show_vuln_chart(self):
        """生成并展示漏洞名称及占比的饼图"""
        # 检查漏洞统计字典
        if not hasattr(self, 'vuln_summary') or not self.vuln_summary:
            print("漏洞统计数据为空，无法生成图表！")
            return

        # 统计漏洞名称及出现次数
        vuln_name_count = {}
        for vuln_info in self.vuln_summary.values():
            for vuln in vuln_info['data_list']:
                vuln_name = vuln[1]
                if vuln_name in vuln_name_count:
                    vuln_name_count[vuln_name] += 1
                else:
                    vuln_name_count[vuln_name] = 1

        # 准备数据
        labels = list(vuln_name_count.keys())  # 漏洞名称
        values = list(vuln_name_count.values())  # 漏洞数量

        # 使用 Plotly 创建饼图
        fig = px.pie(
            values=values,
            names=labels,
            title="Vulnerability names and their proportions.",
            labels={"values": "count", "names": "name"}
        )
        # 隐藏连接线并调整标签显示
        fig.update_traces(
            pull=0,  # 不拉出扇形
            textinfo='label+percent',  # 仅显示名称和百分比
            textposition='inside'  # 标签放置在扇形内部
        )

        # 保存图表为 HTML 文件
        chart_path = os.path.abspath("vuln_pie_chart.html")
        fig.write_html(chart_path)

        # 在 Web 视图中展示
        self.vuln_chart_view.setUrl(QUrl.fromLocalFile(chart_path))

    @pyqtSlot()
    def on_pushButton_6_clicked(self):
        """
        生成chat
        :return:
        """

        # 初始化图表展示
        self.show_asset_chart()
        self.show_vuln_chart()


def main():
    app = QApplication(sys.argv)
    ui = MainWindow()
    ui.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
