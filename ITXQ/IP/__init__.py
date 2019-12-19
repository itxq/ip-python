# ==================================================================
#       文 件 名: __init__.py
#       概    要: 
#       作    者: IT小强 
#       创建时间: 12/19/19 6:58 PM
#       修改时间: 
#       copyright (c) 2016 - 2019 mail@xqitw.cn
# ==================================================================
import socket
import struct


def ip_to_string(ip):
    """
    整数IP转化为IP字符串
    :param ip:
    :return:
    """
    return str(ip >> 24) + '.' + str((ip >> 16) & 0xff) + '.' + str((ip >> 8) & 0xff) + '.' + str(ip & 0xff)


def string_to_ip(s):
    """
    IP字符串转换为整数IP
    :param s:
    :return:
    """
    (ip,) = struct.unpack('I', socket.inet_aton(s))
    return ((ip >> 24) & 0xff) | ((ip & 0xff) << 24) | ((ip >> 8) & 0xff00) | ((ip & 0xff00) << 8)
