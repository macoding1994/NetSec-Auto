import sqlite3


def create_table():
    connection = sqlite3.connect("port_scan.db")  # 创建或连接数据库
    cursor = connection.cursor()

    # 创建表结构
    create_table_query = """
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
    cursor.execute(create_table_query)
    connection.commit()
    connection.close()


def insert_data(port_data):
    connection = sqlite3.connect("port_scan.db")
    cursor = connection.cursor()

    # 插入数据的 SQL 语句
    insert_query = """
    INSERT INTO port_data (domain, ip, port, service, protocol, version, os_info)
    VALUES (:domain, :ip, :port, :service, :protocol, :version, :os_info);
    """
    try:
        cursor.execute(insert_query, port_data)  # 使用字典进行参数化查询
        connection.commit()
        print("数据插入成功")
    except sqlite3.Error as e:
        print(f"插入数据时发生错误: {e}")
    finally:
        connection.close()


if __name__ == "__main__":
    # 示例字典数据
    port_data = {
        "domain": "example.com",
        "ip": "192.168.1.1",
        "port": 80,
        "service": "http",
        "protocol": "tcp",
        "version": "1.1",
        "os_info": "Linux"
    }

    # 创建表
    create_table()

    # 插入数据
    insert_data(port_data)
