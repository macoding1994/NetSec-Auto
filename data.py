import sqlite3

def create_table():
    connection = sqlite3.connect("port_scan.db")  # 创建或连接数据库
    cursor = connection.cursor()

    # 创建端口扫描表
    create_port_table_query = """
    CREATE TABLE IF NOT EXISTS port_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        service TEXT,
        protocol TEXT,
        version TEXT,
        os_info TEXT
    );
    """
    cursor.execute(create_port_table_query)

    # 创建 Shodan 漏洞表
    create_shodan_table_query = """
    CREATE TABLE IF NOT EXISTS shodan_vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        latitude REAL,
        longitude REAL,
        cve_id TEXT,
        cve_name TEXT,
        cve_cvss REAL,
        cve_cvss3 REAL,
        cve_summary TEXT,
        cve_references TEXT
    );
    """
    cursor.execute(create_shodan_table_query)

    connection.commit()
    connection.close()


def insert_port_data(port_data):
    connection = sqlite3.connect("port_scan.db")
    cursor = connection.cursor()

    insert_query = """
    INSERT INTO port_data (domain, ip, port, service, protocol, version, os_info)
    VALUES (:domain, :ip, :port, :service, :protocol, :version, :os_info);
    """
    try:
        cursor.execute(insert_query, port_data)
        connection.commit()
        print("端口数据插入成功")
    except sqlite3.Error as e:
        print(f"插入端口数据时发生错误: {e}")
    finally:
        connection.close()


def insert_shodan_data(shodan_data):
    connection = sqlite3.connect("port_scan.db")
    cursor = connection.cursor()

    # 插入数据的 SQL 语句
    insert_query = """
    INSERT INTO shodan_vulnerabilities (ip, latitude, longitude, cve_id, cve_name, cve_cvss, cve_cvss3, cve_summary, cve_references)
    VALUES (:ip, :lat, :lon, :cve_id, :cve_name, :cve_cvss, :cve_cvss3, :cve_summary, :cve_references);
    """
    # 确保字典中所有键都存在，未提供的字段设置为 None
    default_values = {
        "ip": None,
        "lat": None,
        "lon": None,
        "cve_id": None,
        "cve_name": None,
        "cve_cvss": None,
        "cve_cvss3": None,
        "cve_summary": None,
        "cve_references": None,
    }
    complete_data = {**default_values, **shodan_data}  # 合并字典，确保所有键都有值
    print(complete_data)

    try:
        cursor.execute(insert_query, complete_data)
        connection.commit()
        print("Shodan 漏洞数据插入成功")
    except sqlite3.Error as e:
        print(f"插入漏洞数据时发生错误: {e}")
    finally:
        connection.close()



if __name__ == "__main__":
    create_table()
