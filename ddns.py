#! /usr/bin/env python
# encoding:utf-8

import requests
import ConfigParser
import logging
import sys
import os
import signal
import time

# url_ip = "http://ddns.oray.com/checkip"
url_ip = "http://ip.cip.cc"
request_url_format = "http://{0}:{1}@ddns.oray.com/ph/update?hostname={2}&myip={3}"
absolute_path = os.path.realpath(__file__).replace("ddns.py", "")
conf_path = absolute_path + 'conf.ini'
pid_file = absolute_path + "pid"
log_file = absolute_path + "logger.log"
retry_time = 600    # minute
test_time = 60      # second


def get_conf():
    cp = ConfigParser.ConfigParser()
    cp.read(conf_path)
    return {s[0]: s[1] for s in cp.items("oray")}


def write_pid_file(filename, pid):
    import fcntl
    import stat
    try:
        fd = os.open(filename, os.O_RDWR | os.O_CREAT,
                     stat.S_IRUSR | stat.S_IWUSR)
    except OSError as ose:
        logging.error(ose)
        return -1
    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    assert flags != -1
    flags |= fcntl.FD_CLOEXEC
    r = fcntl.fcntl(fd, fcntl.F_SETFD, flags)
    assert r != -1
    # There is no platform independent way to implement fcntl(fd, F_SETLK, &fl)
    # via fcntl.fcntl. So use lockf instead
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
    except IOError:
        r = os.read(fd, 32)
        if r:
            logging.error('already started at pid %s' % to_str(r))
        else:
            logging.error('already started')
        os.close(fd)
        return -1
    os.ftruncate(fd, 0)
    os.write(fd, to_bytes(str(pid)))
    return 0


def to_bytes(s):
    if bytes != str:
        if type(s) == str:
            return s.encode('utf-8')
    return s


def to_str(s):
    if bytes != str:
        if type(s) == bytes:
            return s.decode('utf-8')
    return s


def freopen(f, mode, stream):
    oldf = open(f, mode)
    oldfd = oldf.fileno()
    newfd = stream.fileno()
    os.close(newfd)
    os.dup2(oldfd, newfd)


def update_address(ip):
    request_url = request_url_format.format(conf["name"], conf["pwd"], conf["host"], ip)
    logging.info("request url : " + request_url)
    try:
        response = requests.get(request_url).text
        logging.debug("response : " + response)
        if response.find("good") != -1 or response.find("nochg") != -1:
            logging.info("update success!  " + response)
            return True
        else:
            return False
    except IOError as e:
        logging.error(e)
    except :
        import traceback
        logging.error(traceback.format_exc())
    return False


# MAIN program
if len(sys.argv) != 2:
    print("wrong!")
    sys.exit(0)

if "start" == sys.argv[1]:
    # ####### daemon #################################
    if os.name != "posix":
        raise Exception("run in Unix")

    # def fun handle signal
    def handle_exit(signum, _):
        if signum == signal.SIGTERM:
            sys.exit(0)
        sys.exit(1)


    # register signal
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    pid = os.fork()
    assert pid != -1

    if pid > 0:
        # parent waits and exit
        import time

        time.sleep(5)
        sys.exit(0)

    ppid = os.getppid()
    pid = os.getpid()
    if write_pid_file(pid_file, pid):
        os.kill(ppid, signal.SIGINT)
        sys.exit(1)

    os.setsid()
    signal.signal(signal.SIGHUP, signal.SIG_IGN)

    print("started")
    os.kill(ppid, signal.SIGTERM)

    sys.stdin.close()
    try:
        freopen(log_file, 'a', sys.stdout)
        freopen(log_file, 'a', sys.stderr)
    except IOError as e:
        logging.error(e)
        sys.exit(1)
elif "stop" == sys.argv[1]:
    import errno

    try:
        with open(pid_file) as f:
            buf = f.read()
            pid = to_str(buf)
            if not buf:
                logging.error("not running")
    except IOError as e:
        logging.error(e)
        if e.errno == errno.ENOENT:
            logging.error("not running")
        sys.exit(1)
    pid = int(pid)
    if pid > 0:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            if e.errno == errno.ESRCH:
                logging.error("not running")
            logging.error(e)
            sys.exit(1)
    else:
        sys.exit(0)

    # sleep for maximum 10s
    for i in range(0, 200):
        try:
            # query for the pid
            os.kill(pid, 0)
        except OSError as e:
            if e.errno == errno.ESRCH:
                break
        time.sleep(0.05)
    else:
        logging.error('timed out when stopping pid %d', pid)
        sys.exit(1)
    print('stopped')
    os.unlink(pid_file)
    sys.exit(0)
else:
    print "wrong!"
    sys.exit(0)

# real process start
# set logger
# logging.basicConfig(filename='logger.log', level=logging.INFO)
logging.basicConfig(
    level=logging.INFO,    # 定义输出到文件的log级别，
    format='%(asctime)s  %(filename)s : %(levelname)s  %(message)s',    # 定义输出log的格式
    datefmt='%Y-%m-%d %A %H:%M:%S',                                     # 时间
    filename=log_file,      # log文件名
    filemode='w'
)                        # 写入模式“w”或“a”
console = logging.FileHandler(log_file)             # 定义console handler
console.setLevel(logging.INFO)                      # 定义该handler级别
formatter = logging.Formatter('%(asctime)s  %(filename)s : %(levelname)s  %(message)s')
console.setFormatter(formatter)
logging.getLogger().addHandler(console)             # 实例化添加handler
# disable some logger
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
# load conf
conf = get_conf()
logging.info("load config : " + str(conf))
ip = "0.0.0.0"
iterator = retry_time  # 更新计时
while True:
    # get IP
    try:
        response = requests.get("http://ip.cip.cc")
        if response.status_code >= 200 and response.status_code<300:
            ip_temp = response.text
    except IOError as e:
        logging.error(e)
    except :
        import traceback
        logging.error(traceback.format_exc())
    logging.debug("get IP:" + ip_temp)
    iterator -= 1  # 计时
    logging.debug("iterator:"+str(iterator))
    if ip != ip_temp:
        logging.info("ip address changed update DNS")
        logging.info("update " + ip + "to " + ip_temp)
        ip = ip_temp
        if update_address(ip):
            iterator = retry_time  # 成功更新重置计时
        else:
            logging.info("update fail")
    if iterator < 1:
        logging.info("time out update DNS")
        ip = ip_temp
        if update_address(ip):
            iterator = retry_time  # 成功更新重置计时
        else:
            logging.info("update fail")
    time.sleep(test_time)
