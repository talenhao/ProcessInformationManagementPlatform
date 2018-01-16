#!/usr/bin/env python3
# -*- coding: utf-8 -*-  
"""
 @Author: 郝天飞/Talen Hao (talenhao@gmail.com)
 @Site: talenhao.github.io
 @Since: 2017/12/13 11:15 AM
"""


# builtin
import re
import sys
import uuid
import getopt
import psutil
import datetime
import subprocess

# user module
from processIMP import model
from processIMP.configprocess import python_config_parser
# for log
import logging
import os
import log4p


SCRIPT_NAME = os.path.basename(__file__)
pLogger = log4p.GetLogger(SCRIPT_NAME, logging.DEBUG).get_l()
all_args = sys.argv[1:]
usage = '''
用法：
%s [--命令选项] [参数]

命令选项：
    --help, -h              帮助。
''' % sys.argv[0]

identify_line = "=*=" * 10
db_con = model.DbInitConnect()


# script commandline
def get_options():
    if all_args:
        pLogger.debug("Command arguments: {!r}".format(str(all_args)))
    # else:
        # pLogger.error(usage)
        # sys.exit()
    try:
        opts, args = getopt.getopt(all_args, "h", ["help"])
    except getopt.GetoptError:
        pLogger.error(usage)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', "--help"):
            pLogger.info(usage)
            sys.exit()


# script wrapper
def script_head(func):
    def wrapper(*args, **kwargs):
        if sys.version_info < (3, 4):
            pLogger.warning('友情提示：当前系统版本低于3.6，请升级python版本。')
            raise RuntimeError('At least Python 3.6 is required')
        return func(*args, **kwargs)
    return wrapper


def spend_time(func):
    def wrapper(*args, **kwargs):
        start_time = datetime.datetime.now()
        pLogger.info("Time start %s", start_time)
        func(*args, **kwargs)
        end_time = datetime.datetime.now()
        pLogger.info("Time over %s,spend %s", end_time, end_time - start_time)
    return wrapper


def start_end_point(info):
    def _wrapper(fun):
        def wrapper(*args, **kwargs):
            pLogger.debug("\n" + ">" * 50 + "process project start : %s", info)
            fun(*args, **kwargs)
            pLogger.debug("\n" + "<" * 50 +
                          "process project finish : %s ", info)
        return wrapper
    return _wrapper


# db commit
def db_commit(func):
    def wrapper(*args, **kwargs):
        sql_cmd = func(*args, **kwargs)
        pLogger.debug("SQL_CMD is =====> {!r} ".format(sql_cmd))
        db_con.dictcursor.execute(sql_cmd)
        pLogger.info("==> DB operation command result: {!r}".format(
            db_con.dictcursor.rowcount)
        )
        db_con.connect.commit()
    return wrapper


# db close_all
def db_close(func):
    def wrapper(*args, **kwargs):
        func(*args, **kwargs)
        db_con.finally_close_all()
    return wrapper


def create_list_to_str(item, num):
    format_str = ",".join([item for i in range(num)])
    return format_str


# machine information collect
def get_server_uuid():
    """
    Get machine server uuid which want to collected.
    """
    server_uuid = str(uuid.UUID(int=uuid.getnode()))
    pLogger.info("server_uuid is: %s", server_uuid)
    return server_uuid


def get_server_serial_number():
    """
    Get system information dispatch command 'dmidecode'
    :return:
    """
    cmdline = 'dmidecode -t 1'
    cmd_output = subprocess.getoutput(cmdline)
    pLogger.debug("cmd_output is {}".format(cmd_output))
    re_compile = re.compile('Serial Number:.*')
    serial_number = re_compile.search(str(cmd_output)).group(0).split(':')[1].strip()
    return serial_number


def get_host_ip():
    ip_set = set()
    nia = psutil.net_if_addrs()
    pLogger.debug(nia)
    for i_face, addresses in nia.items():
        pLogger.debug("i_face is {}".format(i_face))
        if i_face == 'lo':
            pLogger.debug("{!r} is loop address ".format(i_face))
            continue
        else:
            for address in addresses:
                pLogger.debug("address is {}".format(address))
                # here we don't need ipv6
                if str(address.family) == 'AddressFamily.AF_INET':
                        # or str(addr.family) == 'AddressFamily.AF_INET6':
                    pLogger.debug('get ip {}'.format(address.address))
                    ip_set.add(address.address)
                else:
                    pLogger.debug("{!r} is not a INET address".format(address))
    pLogger.debug("ip_set = {!r}, type {!r}".format(ip_set, type(ip_set)))
    return ip_set


def convert_ipv6_ipv4(ipv6):
    """
    ::ffff:192.168.1.103 convert to 192.168.1.103
    """
    ip = ipv6.split(":")[-1]
    return ip


def listen_ports_collect(process, connections):
    listen_ports_set = set()
    # First, collect all listen ip port to a set.
    pLogger.debug("First, collect all listen ip port to a set.")
    for connection in connections:
        # tcp
        if connection.status == psutil.CONN_LISTEN:
                # or (connection.status == psutil.CONN_NONE and not connection.raddr)\
            pLogger.debug("[{!r}] CONN_LISTEN connection is {!r}".format(
                process.pid, connection))
            listen_ports_set.add(connection.laddr)
            pLogger.debug("[{}] connection.laddr is {!r}".format(
                process.pid, connection.laddr))
    pLogger.debug('listen_ports_set : {}'.format(listen_ports_set))
    pLogger.debug("End, collect all listen ip port to a set.")
    return listen_ports_set


def processes(table, server_uuid=None):
    """
    进程处理
    :return:
    """
    server_uuid = server_uuid
    # 直接使用process_iter()迭代实例化每个进程.
    try:
        for process in psutil.process_iter():
            pLogger.debug("{}\n\nPID [{}] begin to process.".format(
                identify_line,
                process.pid)
            )
            # detect process is running.
            if process.is_running():
                # salt-minion with different pid but use the same socket.
                pid = process.pid
                ppid = process.ppid()
                name = process.name()
                exe = process.exe()
                cwd = process.cwd()
                cmdline = process.cmdline()
                status = process.status()
                # 转换成utc写入数据库
                create_time = process.create_time()
                create_time = datetime.datetime.utcfromtimestamp(
                        create_time) + datetime.timedelta(hours=8)
                create_time = str(create_time)
                pLogger.debug("{!r} create_time is {!r}".format(pid, create_time))
                username = process.username()
                process_listen_port = None
                # 一次性抓取运行快照
                with process.oneshot():
                    # 连接信息
                    connections = process.connections(kind='inet')
                    if connections:
                        # collect all listen ports with this process.
                        process_listen_port = listen_ports_collect(process, connections)
                    else:
                        pLogger.debug("{} has no connections.".format(pid))
                insert2db_processes(table, p_name=name, p_ppid=ppid, p_pid=pid, p_status=status, p_cwd=cwd, p_exe=exe,
                                    p_username=username, p_create_time=create_time, p_cmdline=cmdline,
                                    listen_ip_port=process_listen_port, server_uuid=server_uuid)
            else:
                pLogger.debug(
                    "process {} is already not exist!".format(process.pid))
            pLogger.debug("Porcesses [{1}] end to process. {0}".format(
                identify_line, process.pid))
    except psutil.AccessDenied:
        pLogger.exception("用户权限不足.")
        sys.exit()


def process_before_insert_db(string):
    """
    process cmdline @,#... because it will raise error when insert mysql
    """
    try:
        rcm = re.compile(r'[@#}{ ,"\']+')
        # rcm_data = re.compile(r'data[0-9]?/')
        # rcm_solr = re.compile(r'solr[/0-9]?/')
        for arg in range(len(string)):
            if rcm.search(string[arg]):
                string[arg] = re.sub(rcm, '_', string[arg])
    except Exception:
        pLogger.error("There has some error when convert {}.".format(string))
        exit()


def get_cpu_info():
    """
    Get CPU info
    :return:
    """
    cpu_count = psutil.cpu_count()
    cpu_freq = psutil.cpu_freq()
    return {"cpu_count": cpu_count,
            "cpu_freq": cpu_freq}


def get_mem_info():
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {"virtual_memory": mem,
            "swap_memory": swap}


@db_commit
def insert2db_hosts(table, server_uuid=None, ip_addresses=None,
                    serial_number=None, cpu_info_dict=None, mem_info_dict=None):
    """
    hosts表数据插入sql语句生成.
    :param table:
    :param server_uuid:
    :param ip_addresses:
    :param cpu_info_dict:
    :param mem_info_dict:
    :param serial_number:
    :return:
    """
    if server_uuid and ip_addresses:
        if cpu_info_dict and mem_info_dict:
            columns_list = ["server_uuid",
                            "ip_addresses",
                            "serial_number",
                            "cpu_count",
                            "cpu_freq",
                            "virtual_memory",
                            "swap_memory"]
            values_list = [server_uuid,
                           ip_addresses,
                           serial_number,
                           cpu_info_dict["cpu_count"],
                           cpu_info_dict["cpu_freq"],
                           mem_info_dict["virtual_memory"],
                           mem_info_dict["swap_memory"]
                           ]
        else:
            columns_list = ["server_uuid", "ip_addresses", "serial_number"]
            values_list = [server_uuid,
                           ip_addresses,
                           serial_number
                           ]
        columns_str = ','.join(['{1' + str([field]) + '}' for field in range(len(columns_list))])
        values_str = ','.join(['"{2' + str([field]) + '}"' for field in range(len(values_list))])
        pLogger.debug("columns_str is : {!r}, values_str is : {!r} .".format(
            columns_str, values_str))
        sql_format_str = 'INSERT IGNORE INTO {0} (' + columns_str + ') VALUES (' + values_str + ')'
        pLogger.debug("sql_format_str is : {!r}".format(sql_format_str))
        sql_cmd = sql_format_str.format(table, columns_list, values_list)
        return sql_cmd
    else:
        pLogger.error("The server_uuid or ip_addresses can't be empty.")
        exit()


@db_commit
def insert2db_processes(table, p_name, p_ppid, p_pid, p_status, p_cwd, p_exe, p_username, p_create_time,
                        p_cmdline, listen_ip_port, server_uuid):
    """
    进程数据入库
    :param table:
    :param p_name:
    :param p_ppid:
    :param p_pid:
    :param p_status:
    :param p_cwd:
    :param p_exe:
    :param p_username:
    :param p_create_time:
    :param p_cmdline:
    :param listen_ip_port:
    :param server_uuid:
    :return:
    """
    process_before_insert_db(p_cmdline)
    columns_list_process = ["p_name", "p_ppid", "p_pid", "p_status", "p_cwd", "p_exe", "p_username", "p_create_time",
                            "p_cmdline", "listen_ip_port", "server_uuid"]
    values_list = [p_name, p_ppid, p_pid, p_status, p_cwd, p_exe, p_username, p_create_time,
                   p_cmdline, listen_ip_port, server_uuid]
    pLogger.debug("columns_list_process is {}, values_list is {}".format(
        columns_list_process, values_list))

    # 2 SQL create
    columns_str = ','.join(
        ['{1' + str([i]) + '}' for i in range(len(columns_list_process))])
    values_str = ",".join(
        ['"{2' + str([i]) + '}"' for i in range(len(values_list))])
    pLogger.debug("columns_str is : {!r}, values_str is : {!r} .".format(
        columns_str, values_str))
    sql_format_str = 'INSERT ignore INTO {0} (' + \
        columns_str + ') VALUES (' + values_str + ')'
    pLogger.debug("sql_format_str is : {!r}".format(sql_format_str))
    sql_cmd = sql_format_str.format(
        table, columns_list_process, values_list)
    pLogger.debug("_sql is : {!r}".format(sql_cmd))
    pLogger.debug("{} insert database operation command: {}".format(p_exe, sql_cmd))
    return sql_cmd


@db_commit
def reset_local_db_info(table_name, column_name, value_str):
    """
    在每台服务器执行全收集的时候，先清除旧的数据库信息;
    """
    server_uuid =value_str
    pLogger.debug("Clean record base column [{1}] on table [{0} with value_str is {2}].".format(
        table_name, column_name, value_str))
    sql_like_string = "%s = '{0}'" % column_name
    pLogger.debug("sql_like_string: {}".format(sql_like_string))
    sql_like_pattern = sql_like_string.format(server_uuid)
    pLogger.debug("sql_like_pattern: {}".format(sql_like_pattern))
    sql_cmd = "DELETE FROM %s WHERE %s" % (table_name, sql_like_pattern)
    pLogger.debug("{} truncate database table operation: {}".format(
        table_name, sql_cmd))
    return sql_cmd


@spend_time
@start_end_point(SCRIPT_NAME)
@script_head
def do_collect():
    try:
        hosts_table = python_config_parser.get("TABLE", "hosts_table")
        processes_table = python_config_parser.get("TABLE", "processes_table")
        # Clean old data
        server_uuid = get_server_uuid()
        # 由于外键的存在，必须先清除processes表，再清除hosts表
        for table in (processes_table, hosts_table):
            reset_local_db_info(table, 'server_uuid', server_uuid)
        # Collect new data
        # hosts
        host_ip_addresses = get_host_ip()
        serial_number = get_server_serial_number()
        cpu_info = get_cpu_info()
        mem_info = get_mem_info()
        insert2db_hosts(hosts_table, server_uuid=server_uuid, ip_addresses=host_ip_addresses,
                        serial_number=serial_number,
                        cpu_info_dict=cpu_info, mem_info_dict=mem_info)
        processes(processes_table, server_uuid=server_uuid)
    except PermissionError:
        pLogger.exception("Use root user.")
        exit()


@db_close
def main():
    get_options()
    try:
        do_collect()
    except PermissionError:
        pLogger.exception("Use root user to execution.")
        exit()


if __name__ == "__main__":
    main()
