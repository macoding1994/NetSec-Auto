import json
import requests


class Botpree():

    def __init__(self, token: str, botid: str = "125260ab-60bb-4c02-a63d-a7b8c7ed88b2"):
        self.token = token
        self.headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "authorization": f"Bearer {self.token}",
            "x-bot-id": f"{botid}",
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
        :param table:
        :param properties:
        :return:
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

        url = f"https://api.botpress.cloud/v1/tables"
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


if __name__ == '__main__':
    bot = Botpree("bp_pat_OSWnSAavcdjQbQVimyRDayzEz26p2Oc1h8jy")
    print(json.dumps(bot.get_tables_list(), indent=2))

    tables = "vulnTable"

    properties_list = ["cve_name", "cve_id", "cve_severity", "cve_description", "cve_solution"]
    # properties = {
    #     p: {
    #         "type": "string",
    #         "x-zui": {
    #             "index": properties_list.index(p),
    #             "typings": "",
    #             "searchable": True
    #         },
    #         "nullable": True
    #     }
    #
    #     for p in properties_list
    # }
    # print(bot.create_table(tables, properties))

    rows = []
    for i in range(10):
        rows.append({
            p: str(i) for p in properties_list
        })

    body = {
        "rows": rows
    }
    print(bot.add_rows(tables, body))
