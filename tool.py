import re


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
