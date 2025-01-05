import re
import socket
from urllib.parse import urlparse

import requests
import json


def resolv_ips(targetList: list = []):  # sourcery no-metrics
    '''
        解析手动填入的ip资源
        ps:
            ["192.168.0.1", "192.168.0.1-10", "192.168.0.1/24"]
    :param targetList:
    :return: ["192.168.0.1", "192.168.0.2" ... ], ["192.168.0.1", "192.168.0.2" ... ]
    '''
    try:
        all_ips = set()
        p_net_ips = set()
        p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        p_net = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)(\/|-)(\d+)$')
        for target in targetList:
            ip = target
            if p.match(ip):
                all_ips.add(ip)
            if p_net.match(ip):
                if '-' in ip:
                    ip_ = ip.split('-')
                    ip_start = ip_[0]
                    start_value = ''
                    if p.match(ip_start):
                        all_ips.add(ip_start)
                        p_net_ips.add(ip_start)
                        start_value = ip_start.split('.')[3]
                        ip_prex = '.'.join(ip_start.split('.')[:3])
                    ip_end = ip_[1]
                    if int(ip_end) <= 255 and start_value and int(start_value) < int(ip_end) and ip_prex:
                        for j in range(int(start_value), int(ip_end) + 1):
                            new_ip = f'{str(ip_prex)}.{str(j)}'
                            if p.match(new_ip):
                                all_ips.add(new_ip)
                                p_net_ips.add(new_ip)
        return list(all_ips), list(p_net_ips)
    except Exception as e:
        return [], []


def call_scanner_api(host_url, api_key, Cookie, taskName, ip, portRange):
    url = f"{host_url}/private/v3/tasks"

    payload = json.dumps({
        "isAccurateDetection": False,
        "formatAccurateScan": [],
        "viewportType": "vultype",
        "accurateScan": [],
        "loginCheck": False,
        "pre_login": [],
        "WAFBypass": True,
        "scanMode": 1,
        "taskName": taskName,
        "customRangeType": 1,
        "primaryDomain": {
            "domain": [],
            "label": [
                {
                    "id": 18,
                    "domainname": ip,
                    "selectAll": 1,
                    "children": [
                        {
                            "subdomainname": ip,
                            "id": None
                        }
                    ]
                }
            ]
        },
        "portType": "1-65535",
        "portRange": portRange,
        "scanContent": [
            "TASK_007",
            "TASK_008"
        ],
        "scanSpeed": 100,
        "baseOnVersion": False,
        "WAFPass": True,
        "primaryDomain_display": [
            ip
        ],
        "primaryDomain_submit": {
            "domain": [],
            "label": [
                {
                    "id": 18,
                    "domainname": ip,
                    "selectAll": 1,
                    "children": [
                        {
                            "subdomainname": ip,
                            "id": None
                        }
                    ]
                }
            ]
        },
        "taskFrequency": "singleTime",
        "resultPush": [
            1
        ],
        "autoWorkOrder": 0,
        "startTime": "2022-09-27 15:44",
        "timeSlot": [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12
        ],
        "repeatCycle": {
            "repeatCycleUnit": 1,
            "repeatExecInterval": 1,
            "totalExecCount": 1
        },
        "repeatCycleUnit": 1,
        "repeatExecInterval": 1,
        "totalExecCount": 1,
        "timeSlot_display": [],
        "taskType": 1,
        "responsiblePerson": None,
        "scheduleScanDate": None,
        "domainCheck": True,
        "internetCheck": True
    })
    headers = {
        'User-Agent': 'Apifox/1.0.0 (https://apifox.com)',
        'Content-Type': 'application/json',
        'Authorization': f'JWT {api_key}',
        'Accept': '*/*',
        'Host': '192.168.133.132:18002',
        'Connection': 'keep-alive',
        'Cookie': Cookie
    }

    try:
        response = requests.post(url, headers=headers, data=payload)
        if response.status_code == 200:
            print("扫描任务已成功发送！")
            return response.json()
        else:
            print(f"发送扫描任务失败，状态码: {response.status_code}")
            return response.text
    except requests.RequestException as e:
        print(f"请求时发生错误: {e}")
        return None


def login(host_url, account, password):
    """
    调用登录接口获取用户 Token 和其他信息。

    :param host_url: 登录接口的 URL
    :param account: 用户名
    :param password: 加密后的密码
    :return: 登录响应结果，包括 token 和其他信息
    """
    payload = {
        "account": account,
        "password": password
    }
    headers = {
        "Content-Type": "application/json"
    }
    url = f"{host_url}/private/v1/authorizations"

    try:
        # 发送登录请求
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        if response.status_code == 200:
            res_data = response.json()
            if res_data.get("code") == 200:
                print("登录成功！")
                token = res_data["data"][0]["token"]
                return {
                    "token": token,
                    "user_id": res_data["data"][0]["user_id"],
                    "username": res_data["data"][0]["username"],
                    "role": res_data["data"][0]["role"],
                    "ip": res_data["data"][0]["ip"],
                    "sessionid": res_data["data"][0]["sessionid"],
                    "cookies": "; ".join([f"{key}={value}" for key, value in response.cookies.items()])
                }
            else:
                print(f"登录失败: {res_data.get('message', '未知错误')}")
                return None
        else:
            print(f"接口调用失败，状态码: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"请求时发生错误: {e}")
        return None


def fetch_task_list(host_url, token, Cookie, params=None):
    """
    调用任务列表页接口获取任务数据。

    :param host_url: 任务列表接口的完整 URL
    :param token: 用户的认证 Token
    :param params: URL 查询参数（可选）
    :return: 接口响应结果
    """
    url = f"{host_url}/private/v3/tasks/list?page=1&page_size=50"

    payload = {}
    headers = {
        'User-Agent': 'Apifox/1.0.0 (https://apifox.com)',
        'Authorization': f'JWT {token}',
        'Accept': '*/*',
        'Host': '192.168.133.132:18002',
        'Connection': 'keep-alive',
        'Cookie': Cookie
    }

    try:
        # 发送 GET 请求
        response = requests.request("GET", url, headers=headers, data=payload)
        if response.status_code == 200:
            print("任务列表获取成功！")
            return response.json()
        else:
            print(f"获取任务列表失败，状态码: {response.status_code}")
            return response.text
    except requests.RequestException as e:
        print(f"请求时发生错误: {e}")
        return None


def fetch_task_vulnerabilities(host_url, token, Cookie, task_id, page=1, page_size=50):
    """
    获取任务中的漏洞数据。

    :param host_url: 漏洞数据接口的完整 URL
    :param token: 用户的认证 Token
    :param task_id: 任务 ID
    :param page: 当前页码（默认 1）
    :param page_size: 每页条目数量（默认 10）
    :return: 接口响应结果
    """
    url = f"{host_url}/private/v3/tasks/risk/group/list?task_id={task_id}&page_size=50"

    payload = {}
    headers = {
        'Authorization': f'JWT {token}',
        'Accept': '*/*',
        'Host': '192.168.133.132:18002',
        'Connection': 'keep-alive',
        'Cookie': Cookie
    }

    try:
        # 发送 GET 请求
        response = requests.request("GET", url, headers=headers, data=payload)
        if response.status_code == 200:
            print("漏洞数据获取成功！")
            return response.json()
        else:
            print(f"获取漏洞数据失败，状态码: {response.status_code}")
            return response.text
    except requests.RequestException as e:
        print(f"请求时发生错误: {e}")
        return None


def fetch_task_ip_assets(host_url, token, Cookie, task_id, page=1, page_size=10):
    """
    获取任务中的 IP 资产数据。

    :param host_url: IP 资产接口的完整 URL
    :param token: 用户的认证 Token
    :param task_id: 任务 ID
    :param page: 当前页码（默认 1）
    :param page_size: 每页条目数量（默认 10）
    :return: 接口响应结果
    """
    url = f"{host_url}/private/v3/tasks/port/service/list?task_id={task_id}&page_size=50"

    payload = {}
    headers = {
        'Authorization': f'JWT {token}',
        'Accept': '*/*',
        'Host': '192.168.133.132:18002',
        'Connection': 'keep-alive',
        'Cookie': Cookie
    }

    try:
        # 发送 GET 请求
        response = requests.get(url, headers=headers, verify=False)  # verify=False 忽略 HTTPS 证书
        if response.status_code == 200:
            print("IP 资产数据获取成功！")
            return response.json()
        else:
            print(f"获取 IP 资产数据失败，状态码: {response.status_code}")
            return response.text
    except requests.RequestException as e:
        print(f"请求时发生错误: {e}")
        return None


def get_ip_and_port(url):
    """
    获取 URL 的 IP 和端口。

    :param url: 要解析的 URL
    :return: IP 和端口的元组 (ip, port)
    """
    try:
        # 解析 URL
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port

        # 如果端口为空，根据协议使用默认端口
        if port is None:
            if parsed_url.scheme == "http":
                port = 80
            elif parsed_url.scheme == "https":
                port = 443

        # 获取主机名的 IP 地址
        ip_address = socket.gethostbyname(hostname)

        return ip_address, port
    except Exception as e:
        print(f"解析 URL 时出错: {e}")
        return "", ""


def get_vuln_info(host_url, token, cookies, id):
    url = f"{host_url}/private/v3/vulnerability/risk?id={id}"
    payload = {}
    headers = {
        'Authorization': f'JWT {token}',
        'Accept': '*/*',
        'Host': '192.168.133.132:18002',
        'Connection': 'keep-alive',
        'Cookie': cookies
    }
    try:
        # 发送 GET 请求
        response = requests.get(url, headers=headers, verify=False)  # verify=False 忽略 HTTPS 证书
        if response.status_code == 200:
            print("IP 资产数据获取成功！")
            data = response.json()["data"]
            ip_address, port = get_ip_and_port(data["url"])
            data.update({
                "ip": ip_address,
                "port": port,
            })
            return data
        else:
            print(f"获取 IP 资产数据失败，状态码: {response.status_code}")
            return response.text
    except requests.RequestException as e:
        print(f"请求时发生错误: {e}")
        return None


if __name__ == '__main__':
    host_url = "http://192.168.133.132:18002"
    account = "admin"
    password = "048c60971e056793518850b8f1a5bd56bab153a12f303d1296d2b4844330f19c3ce98c8972f908722f9e80aa371d9e4a3667d64f9f57f6d3483b63a647dd3270af0f6dc59fb294fd65bcf2dbe03ca6d96e726fc931eb65f280c7e7a42025f422180c2c1b1253a82873"

    response = login(host_url, account, password)
    token = response["token"]
    cookies = response["cookies"]
    # response = fetch_task_list(host_url, token, cookies)
    # print(response)
    #
    # print(fetch_task_vulnerabilities(host_url, token, cookies, 4))
    # print(fetch_task_ip_assets(host_url, token, cookies, 4))
    # print(get_vuln_info(host_url, token, cookies, 4))
