#! /usr/bin/env python
# encoding:utf-8

import requests
import ConfigParser
import logging
import sys
import os
import signal
import time

conf_path = 'conf.ini'
# url_ip = "http://ddns.oray.com/checkip"
url_ip = "http://ip.cip.cc"
request_url_format = "http://{0}:{1}@ddns.oray.com/ph/update?hostname={2}&myip={3}"
pid_file = "pid"


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
    # TODO logger??
    # ####### END daemon #############################
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
logging.basicConfig(filename='logger.log', level=logging.INFO)
# disable some logger
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
# set log format
console = logging.StreamHandler()
formatter = logging.Formatter("[%(levelname)s][%(asctime)s][%(process)d:%(processName)s]%(message)s")
console.setFormatter(formatter)
logging.getLogger("").addHandler(console)
# load conf
conf = get_conf()
logging.info("load config : " + str(conf))
ip = "0.0.0.0"
request_url = request_url_format.format(conf["name"], conf["pwd"], conf["host"], ip)
logging.debug("request url : " + request_url)
iterator = 600   # 更新计时
while True:
    # get IP
    ip_temp = requests.get("http://ip.cip.cc").text
    logging.debug("get IP:" + ip_temp)
    iterator -= 1   # 计时
    if ip != ip_temp:
        response = requests.get(request_url).text
        logging.debug("response : " + response)
        if response.find("good") != -1 or \
                response.find("nochg") != -1:
            logging.info("update success!  " + response)
            iterator = 600   # 成功更新重置计时
        else:
            logging.info("update fail")
    if iterator < 1:
        response = requests.get(request_url).text
        logging.debug("response : " + response)
        if response.find("good") != -1 or \
                response.find("nochg") != -1:
            logging.info("update success!  " + response)
            iterator = 600   # 成功更新重置计时
        else:
            logging.info("update fail")
    time.sleep(60)
