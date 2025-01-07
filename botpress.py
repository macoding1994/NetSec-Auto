import json
import time

import requests


class Botpress:
    def __init__(self, config_path: str = "config.json"):
        # 加载配置文件
        with open(config_path, "r") as config_file:
            config = json.load(config_file)

        # 从配置文件中获取 token 和 botid
        self.token = config.get("token")
        self.botid = config.get("botid", "default_botid")

        self.headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "authorization": f"Bearer {self.token}",
            "x-bot-id": f"{self.botid}",
        }

    def get_tables_list(self):
        url = "https://api.botpress.cloud/v1/tables"
        method = "GET"
        response = requests.request(method, url, headers=self.headers)

        if response.status_code == 200:
            return response.json()
        print(response.text)

    def get_table(self, table: str):
        url = f"https://api.botpress.cloud/v1/tables/{table}"
        method = "GET"
        response = requests.request(method, url, headers=self.headers)

        if response.status_code == 200:
            return response.json()
        print(response.text)

    def create_table(self, table: str, properties: dict):
        '''
        table name must end with 'Table'
        '''
        body = {
            "name": f"{table}",
            "factor": 1,
            "frozen": False,
            "schema": {
                "type": "object",
                "x-zui": {},
                "properties": properties,
                "additionalProperties": True
            },
            "partitionName": "partitions.tbl_data_default"
        }

        url = "https://api.botpress.cloud/v1/tables"
        method = "POST"
        response = requests.request(method, url, headers=self.headers, json=body)

        if response.status_code == 200:
            return response.json()
        print(response.text)

    def detele_table(self, table: str):
        url = f"https://api.botpress.cloud/v1/tables/{table}"
        method = "DELETE"
        response = requests.request(method, url, headers=self.headers)

        if response.status_code == 200:
            return response.json()
        print(response.text)

    def add_rows(self, table: str, body: dict):
        url = f"https://api.botpress.cloud/v1/tables/{table}/rows"
        method = "POST"
        response = requests.request(method, url, headers=self.headers, json=body)

        if response.status_code == 200:
            return response.json()
        print(response.text)

    def delete_table_rows(self, table: str):
        url = f"https://api.botpress.cloud/v1/tables/{table}/rows/delete"
        method = "POST"
        payload = {"deleteAllRows": True}
        response = requests.post(url, json=payload, headers=self.headers)

        if response.status_code == 200:
            return response.json()
        print(response.text)



if __name__ == "__main__":
    tables = "vulnTable"

    # 初始化 Botpress 类
    bot = Botpress("config.json")
    bot.delete_table_rows(tables)

    # print(json.dumps(bot.get_tables_list(), indent=2))
    # print(bot.detele_table(tables))
    # time.sleep(2)
    #
    # properties_list = ["cve_name", "cve_id", "cve_severity", "cve_description", "cve_solution"]
    # properties = {
    #     p: {
    #         "type": "string",
    #         "x-zui": {
    #             "index": properties_list.index(p),
    #             "typings": "",
    #             "searchable": True
    #         },
    #         "nullable": True,
    #         "maxLength": 2048
    #     }
    #
    #     for p in properties_list
    # }
    # print(bot.create_table(tables, properties))
    #
    # rows = []
    # for i in range(10):
    #     rows.append({
    #         p: str(i) for p in properties_list
    #     })
    #
    # body = {
    #     "rows": rows
    # }
    # print(bot.add_rows(tables, body))
