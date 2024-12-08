# -- coding: utf-8 --
import copy
import os
import requests
from shodan import Shodan

# 从环境变量中获取API密钥
SHODAN_API_KEY = "ebSqyadKL91rXbRNLHg8dIKcIzBRvfS1"


def get_cve_search_info(cveid: str):
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36'
    }
    cve_url = f"https://192.168.133.133/api/cve/{cveid}"
    try:
        response = requests.get(cve_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching CVE info: {e}")
        return {}


def parse_cve_search_data(json_data):
    return json_data


def get_vulnerabilities_info(cveid: str):
    return parse_cve_search_data(get_cve_search_info(cveid))


def get_host_info(host):
    try:
        api = Shodan(SHODAN_API_KEY)
        result = api.host(host)
    except Exception as e:
        print(f"Error fetching host info: {e}")
        return {}
    print(f"find host: [{host}]!")
    return result
