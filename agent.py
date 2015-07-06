#!/usr/bin/env python
import sys, time, json, platform, os, requests, multiprocessing, string, netifaces, pingparser, bz2, re
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass
from subprocess import Popen, PIPE
from configobj import ConfigObj
from collections import namedtuple
try:
  import psutil
except ImportError:
   print "Cannot import psutil module - this is needed for this application.";
   print "Exiting..."
   sys.exit();
try:
    import pwd
except ImportError:
    pwd = None

try:
    from pymdstat import MdStat
except ImportError:
    pass

def systemCommand(Command, newlines=True):
    Output = ""
    Error = ""
    try:
        #Output = subprocess.check_output(Command,stderr = subprocess.STDOUT,shell='True')
        proc = Popen(Command.split(), stdout=PIPE)
        Output = proc.communicate()[0]
    except:
        pass

    if Output:
        if newlines == True:
            Stdout = Output.split("\n")
        else:
            Stdout = Output
    else:
        Stdout = []
    if Error:
        Stderr = Error.split("\n")
    else:
        Stderr = []

    return (Stdout,Stderr)

def diskstats_parse(dev=None):
    file_path = '/proc/diskstats'
    result = {}

    # ref: http://lxr.osuosl.org/source/Documentation/iostats.txt
    columns_disk = ['m', 'mm', 'dev', 'reads', 'rd_mrg', 'rd_sectors',
                    'ms_reading', 'writes', 'wr_mrg', 'wr_sectors',
                    'ms_writing', 'cur_ios', 'ms_doing_io', 'ms_weighted']

    columns_partition = ['m', 'mm', 'dev', 'reads', 'rd_sectors', 'writes', 'wr_sectors']

    lines = open(file_path, 'r').readlines()
    for line in lines:
        if line == '': continue
        split = line.split()
        if len(split) == len(columns_disk):
            columns = columns_disk
        elif len(split) == len(columns_partition):
            columns = columns_partition
        else:
            # No match
            continue

        data = dict(zip(columns, split))

        if "loop" in data['dev']: continue

        if dev != None and dev != data['dev']:
            continue
        for key in data:
            if key != 'dev':
                data[key] = int(data[key])
        result[data['dev']] = data

    return result

def yield_lines(data):
    for line in data.split("\n"):
        yield line

def line_to_list(line):
    pattern = re.compile(r"([\w\/\s\-\_]+)\s+(\w+)\s+([\d\.]+?[GKM]|\d+)"
                          "\s+([\d\.]+[GKM]|\d+)\s+([\d\.]+[GKM]|\d+)\s+"
                          "(\d+%)\s+(.*)")
    matches = pattern.search(line)
    if matches:
        return matches.groups()
    _line = re.sub(r" +", " ", line).split()
    return _line

def collectDiskIO(configobj):
    if(os.path.isfile("/proc/diskstats")):
        return diskstats_parse()
    else:
        return False

def collectDiskUsage(configobj):
    disk = {}
    if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
        disk['df'] = [s.split() for s in os.popen("df -P").read().splitlines()]
        disk['di'] = [s.split() for s in os.popen("df -iP").read().splitlines()]
    elif sys.platform == "win32":
        c = wmi.WMI ()
        for d in c.Win32_LogicalDisk():
            disk['windows'] = ( d.Caption, d.FreeSpace, d.Size, d.DriveType)
    return disk


def disk_partitions(all=False):
    """Return all mountd partitions as a nameduple.
    If all == False return phyisical partitions only.
    """
    phydevs = []
    disk_ntuple = namedtuple('partition',  'device mountpoint fstype')
    f = open("/proc/filesystems", "r")
    for line in f:
        if not line.startswith("nodev"):
            phydevs.append(line.strip())

    retlist = []
    f = open('/etc/mtab', "r")
    for line in f:
        if not all and line.startswith('none'):
            continue
        fields = line.split()
        device = fields[0]
        mountpoint = fields[1]
        fstype = fields[2]
        if not all and fstype not in phydevs:
            continue
        if device == 'none':
            device = ''
        ntuple = disk_ntuple(device, mountpoint, fstype)
        retlist.append(ntuple)
    return retlist

def collectCPU(configobj):
    cpus = {}
    cpu = psutil.cpu_times_percent(interval=0.5, percpu=True)
    for cpu_num, perc in enumerate(psutil.cpu_percent(interval=None, percpu=True)):
        cpus[cpu_num] = {}
        for name in cpu[cpu_num]._fields:
            cpus[cpu_num][name] = getattr(cpu[cpu_num], name)
    return cpus

def collectMemory(configobj):
    memory = {}
    mem = psutil.virtual_memory()
    for name in mem._fields:
        memory[name] = getattr(mem, name)
    return memory

def collectSwap(configobj):
    swap = {}
    mem = psutil.swap_memory()
    for name in mem._fields:
        swap[name] = getattr(mem, name)
    return swap

def collectNetwork(configobj):
    return psutil.net_io_counters(pernic=True)

def collectMdstat(configobj):
    if(os.path.isfile("/proc/mdstat")):
        mds = MdStat()
        return mds.get_stats()
    else:
        return False

def collectRaidStatus(configobj):
    # https://github.com/jnv/ansible-fedora-infra/blob/master/roles/nagios_client/files/scripts/check_raid.py
    devices = []
    mdstat = string.split(open('/proc/mdstat').read(), '\n')
    error = ""
    i = 0
    for line in mdstat:
        if line[0:2] == 'md':
            device = string.split(line)[0]
            devices.append(device)
            status = string.split(mdstat[i+1])[3]
            if string.count(status, "_"):
                # see if we can figure out what's going on
                err = string.split(mdstat[i+2])
                msg = "device=%s status=%s" % (device, status)
                if len(err) > 0:
                    msg = msg + " rebuild=%s" % err[0]
                if not error:
                    error = msg
                else:
                    error = error + ", " + msg
        i = i + 1
    if not error:
        return True
    else:
        return error
def procStats(pid):
    process = {}
    process['pid'] = int(pid)

    if os.path.exists('/proc/%s/cmdline' % pid):
        with open(os.path.join('/proc/', pid, 'cmdline'), 'r') as file:
            process['cmdline'] = file.readline().replace('\x00', '')
        if process['cmdline'] == '':
            return False
        else:
            if os.path.exists('/proc/%s/stat' % pid):
                with open(os.path.join('/proc/', pid, 'stat'), 'r') as pidfile:
                    proctimes = pidfile.readline()
                    process['name'] = proctimes.split(' ')[1].strip(')').strip('(')
                    # count total process used time
                    process['ctime'] = float(int(proctimes.split(' ')[13]) + int(proctimes.split(' ')[14]))
                if os.path.exists('/proc/%s/io' % pid):
                    process['io'] = {}
                    with open(os.path.join('/proc/', pid, 'io'), 'r') as file:
                        for line in file:
                            process['io'][line.strip().split(': ')[0]] = line.strip().split(': ')[1]
                if os.path.exists('/proc/%s/statm' % pid):
                    pextmem = namedtuple('pextmem', 'rss vms shared text lib data dirty')
                    with open(os.path.join('/proc/', pid, 'statm'), 'r') as file:
                        vms, rss, shared, text, lib, data, dirty = \
                                        [int(x) for x in file.readline().split()[:7]]
                        process['mem'] = pextmem(rss, vms, shared, text, lib, data, dirty)._asdict()
                if os.path.exists('/proc/%s/status' % pid):
                    with open(os.path.join('/proc/', pid, 'status'), 'r') as file:
                        for line in file:
                            if line.split(':')[0] == 'Uid':
                                process['username'] = pwd.getpwuid(int(line.split(':')[1].split('\t')[1])).pw_name
                                break
                            if line.split(':')[0] == 'PPid':
                                process['ppid'] = int(line.split(':')[1].split('\t')[1])
                return process

def getPids():
    return [int(x) for x in os.listdir(b'/proc') if x.isdigit()]

def collectProcesses(configobj):
    process = []
    if sys.platform == "linux" or sys.platform == "linux2":
        processlist = []
        for pid in getPids():
            proc = procStats(str(pid))
            if proc != False:
                process.append(proc)
    elif sys.platform == "darwin":
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=['pid', 'name', 'ppid', 'exe', 'cmdline', 'username', 'cpu_percent','memory_percent'])
            except psutil.NoSuchProcess:
                pass
            else:
                if ''.join(pinfo['cmdline']) != '':
                    process.append(pinfo)
    elif sys.platform == "win32":
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=['pid', 'name', 'ppid', 'exe', 'cmdline', 'username', 'cpu_percent','memory_percent'])
            except psutil.NoSuchProcess:
                pass
            else:
                process.append(pinfo)
    return process

def linux_distribution():
  try:
    return platform.linux_distribution()
  except:
    return "N/A"

def ip_addresses():
    ip_list = {}
    ip_list['v4'] = {}
    ip_list['v6'] = {}
    for interface in netifaces.interfaces():
        link = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in link:
            if interface not in ip_list['v4']:
                ip_list['v4'][interface] = []
            ip_list['v4'][interface].append(link[netifaces.AF_INET])
        if netifaces.AF_INET6 in link:
            if interface not in ip_list['v6']:
                ip_list['v6'][interface] = []
            ip_list['v6'][interface].append(link[netifaces.AF_INET6])
    return ip_list

def collectSystem():
    systeminfo = {}
    cpu = {}
    if(os.path.isfile("/proc/cpuinfo")):
        with open('/proc/cpuinfo') as f:
            for line in f:
                # Ignore the blank line separating the information between
                # details about two processing units
                if line.strip():
                    if "model name" == line.rstrip('\n').split(':')[0].strip():
                        cpu['brand'] = line.rstrip('\n').split(':')[1].strip()
                    if "processor" == line.rstrip('\n').split(':')[0].strip():
                        cpu['count'] = line.rstrip('\n').split(':')[1].strip()
    else:
        cpu['brand'] =  "Unknown CPU"
        cpu['count'] =  0
    mem = psutil.virtual_memory()
    if sys.platform == "linux" or sys.platform == "linux2":
        systeminfo['os'] = str(' '.join(platform.linux_distribution()))
    elif sys.platform == "darwin":
        systeminfo['os'] = platform.mac_ver()
    elif sys.platform == "win32":
        systeminfo['os'] = str(platform.uname())
    systeminfo['cpu'] = cpu['brand']
    systeminfo['cores'] = cpu['count']
    systeminfo['memory'] = mem.total
    systeminfo['ip_addresses'] = ip_addresses()
    return systeminfo


def collectPing(hostname):
    if sys.platform == "linux" or sys.platform == "linux2":
        response = pingparser.parse(str(systemCommand("ping -W 5 -c 1 " + hostname, False)))
    elif sys.platform == "darwin":
        response = pingparser.parse(str(systemCommand("ping -W 5 -c 1 " + hostname, False)))
    elif sys.platform == "win32":
        response = systemCommand("ping "+hostname+" -n 1")
    else:
        response = systemCommand("ping -W -c 1 " + hostname)
    return response

def collectLoadavg(config):
    return os.getloadavg()

def collectMysql(config):
    import mysql.connector
    mysqlstatus = False
    try:
       cnx = mysql.connector.connect(user=config['username'], password=config['password'],
                                      host=config['host'], unix_socket=config['socket'])
       cursor = cnx.cursor()
       cursor.execute("""
          SHOW GLOBAL STATUS;
       """)
       mysqlstatus = cursor.fetchall()
       cnx.close()
    except:
        pass
    return mysqlstatus


def collectApache(config):
    raw = requests.get("%s?auto" % config['url'])
    # From https://pythonhosted.org/pyserverstatus/
    # Initialize with None because mod_status has different levels of
    # verbosity. So if it doesn't respond with a value, we'll just have
    # a None instead which is nicer than getting unpredictable exceptions
    # when accessing the output later on.
    parsed = {'total_accesses': None,
              'total_kbytes': None,
              'cpuload': None,
              'uptime': None,
              'requests_per_second': None,
              'bytes_per_second': None,
              'bytes_per_request': None,
              'busy_workers': None,
              'idle_workers': None,
              'waiting_for_connection': None,
              'starting_up': None,
              'reading_request': None,
              'sending_reply': None,
              'keepalive': None,
              'dns_lookup': None,
              'closing_connection': None,
              'logging': None,
              'gracefully_finishing': None,
              'idle_cleanup_of_worker': None,
              'open_slots': None}

    if raw.status_code == 200:
        # Do the nasty parsing. Doing this programatically may be
        # more extensible but it's much rougher looking.
        for line in raw.text.splitlines():
            (key, value) = line.split(': ')
            if key == 'Total Accesses':
                parsed['total_accesses'] = int(value)
            if key == 'Total kBytes':
                parsed['total_kbytes'] = int(value)
            if key == 'CPULoad':
                parsed['cpuload'] = float(value)
            if key == 'Uptime':
                parsed['uptime'] = int(value)
            if key == 'ReqPerSec':
                parsed['requests_per_second'] = float(value)
            if key == 'BytesPerSec':
                parsed['bytes_per_second'] = float(value)
            if key == 'BytesPerReq':
                parsed['bytes_per_request'] = float(value)
            if key == 'BusyWorkers':
                parsed['busy_workers'] = int(value)
            if key == 'IdleWorkers':
                parsed['idle_workers'] = int(value)
            if key == 'Scoreboard':
                parsed['waiting_for_connection'] = value.count('_')
                parsed['starting_up'] = value.count('S')
                parsed['reading_request'] = value.count('R')
                parsed['sending_reply'] = value.count('W')
                parsed['keepalive'] = value.count('K')
                parsed['dns_lookup'] = value.count('D')
                parsed['closing_connection'] = value.count('C')
                parsed['logging'] = value.count('L')
                parsed['gracefully_finishing'] = value.count('G')
                parsed['idle_cleanup_of_worker'] = value.count('I')
                parsed['open_slots'] = value.count('.')
    return parsed

def collectNginx(config):
    results = dict()
    url = ('{https}://{host}:{port}/{path}'
        ''.format(
            https=config['schema'],
            host=config['host'],
            port=config['port'],
            path=config['path']
        )
    )
    r = requests.get(url, verify=False)
    if r.status_code == 200:
        response = r.text.split("\n")
        # Active connections
        results['active_con'] = int(response[0].split(':')[1].strip())

        # server accepted handled request
        keys = response[1].split()[1:]
        values = response[2].split()
        for key, value in zip(keys, values):
            results['{0}'.format(key)] = int(value)

        # Reading: N Writing: N Waiting: N
        keys = response[3].split()[0::2]
        keys = [entry.strip(':').lower() for entry in keys]
        values = response[3].split()[1::2]
        for key, value in zip(keys, values):
            results['{0}'.format(key)] = int(value)
        return results
    else:
        return False

def runCollector(config,saveto,post):
    data = {}
    timestamp = int(time.time())
    data['time'] = timestamp
    if post is True:
        data['agent'] = 0.961
        data['system'] = collectSystem()
        data['uptime'] = time.time()-psutil.boot_time()
    for key, configitem in enumerate(config['collectors']):
        if config['collectors'][configitem]['enabled'] == 'True':
            if config['collectors'][configitem]['interval']:
                interval = int(config['collectors'][configitem]['interval'])
            else:
                interval = 1  # default interval, every second
            if configitem == 'disk_io' and timestamp % interval==0:
                data['diskio']= collectDiskIO(config['collectors'][configitem])

            if configitem == 'disk_usage' and timestamp % interval==0:
                data['diskusage'] = collectDiskUsage(config['collectors'][configitem])

            if configitem == 'cpu' and timestamp % interval == 0:
                data['cpu'] = collectCPU(config['collectors'][configitem])

            if configitem == 'network' and timestamp % interval==0:
                data['network'] = collectNetwork(config['collectors'][configitem])

            if configitem == 'swap' and timestamp % interval==0:
                data['swap'] = collectSwap(config['collectors'][configitem])

            if configitem == 'memory' and timestamp % interval==0:
                data['memory'] = collectMemory(config['collectors'][configitem])

            if configitem == 'loadavg' and timestamp % interval==0:
                data['loadavg'] = collectLoadavg(config['collectors'][configitem])

            if configitem == 'mysql' and timestamp % interval==0:
                data['mysql'] = collectMysql(config['collectors'][configitem])

            if configitem == 'raidstatus' and timestamp % interval==0:
                data['raidstatus'] = collectMdstat(config['collectors'][configitem])

            if configitem == 'process' and timestamp % interval==0:
                data['process'] = collectProcesses(config['collectors'][configitem])

            if configitem == 'nginx' and timestamp % interval==0:
                data['nginx'] = collectNginx(config['collectors'][configitem])

            if configitem == 'apache' and timestamp % interval==0:
                data['apache'] = collectApache(config['collectors'][configitem])

            if configitem == 'ping' and timestamp % interval==0:
                my_hosts = config['collectors'][configitem]['hosts']
                if type(my_hosts) is list:
                    data['ping'] = []
                    for host in my_hosts:
                        data['ping'].append(collectPing(host))
                else:
                    data['ping'] = collectPing(config['collectors'][configitem]['hosts'])
    saveToFile(data, timestamp, config, saveto, post)

def saveToFile(data, timestamp, config, saveto, post):
    if os.path.isfile('/opt/nixstats/%d.data' % saveto):
        f = open('/opt/nixstats/%d.data' % saveto,'a')
        f.write(str(json.dumps(data))+"\n") # python will convert \n to os.linesep
        f.close()
        if post == True:
            time.sleep(15)
            r = postMetrics('/opt/nixstats/%d.data' % saveto, config)
            if r.text == '200':
                os.unlink('/opt/nixstats/%d.data' % saveto)
                for filename in os.listdir('/opt/nixstats/retry/'):
                    r = postMetrics('/opt/nixstats/retry/%s' % filename,config)
                    if r.text == "200":
                        os.unlink('/opt/nixstats/retry/%s' % filename)
                    else:
                        break
            else:
                os.rename('/opt/nixstats/%d.data' % saveto,'/opt/nixstats/retry/%d.data' % saveto)
    else:
        pass

def postMetrics(sourcefile,config):
    f = open(sourcefile,'r')
    payload = {'server': config['nixstats']['server'], 'user': config['nixstats']['user']}
    files = {'data': bz2.compress(f.read())}
    r = requests.post("https://api.nixstats.com/v2/server/poll", verify=False, data=payload, files=files)
    return r


config = ConfigObj('nixstats.cfg')
config['nixstats']['post_interval'] = 60

def touch(fname, times=None):
    with open(fname, 'a'):
        os.utime(fname, times)

def startCollector():
    count = 0
    saveto = time.time()
    touch('/opt/nixstats/%d.data' % saveto)
    while True:
        count += 1
        if count == int(config['nixstats']['post_interval']):
            jobs = multiprocessing.Process(name='nixstats_daemon_'+str(time.time()), target=runCollector, args=(config,saveto,True,))
            count = 0
            saveto = time.time()
            touch('/opt/nixstats/%d.data' % saveto)
        else:
            jobs = multiprocessing.Process(name='nixstats_daemon_'+str(time.time()), target=runCollector, args=(config,saveto,False,))
        jobs.daemon = True
        jobs.start()
        time.sleep(1)