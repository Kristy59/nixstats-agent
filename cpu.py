#! /usr/bin/python
# -*- python -*-
# -*- coding: utf-8 -*-
import os, time, utilist
VERSION="0.3"
def process_cmdline(pid_info):
	if pid_info["cmdline"]:
		return reduce(lambda a, b: a + " %s" % b, pid_info["cmdline"]).strip()
	return pid_info["stat"]["comm"]
class pidstat:
	PF_ALIGNWARN	 = 0x00000001
	PF_STARTING	 = 0x00000002
	PF_EXITING	 = 0x00000004
	PF_EXITPIDONE	 = 0x00000008
	PF_VCPU		 = 0x00000010
	PF_FORKNOEXEC	 = 0x00000040
	PF_SUPERPRIV	 = 0x00000100
	PF_DUMPCORE	 = 0x00000200
	PF_SIGNALED	 = 0x00000400
	PF_MEMALLOC	 = 0x00000800
	PF_FLUSHER	 = 0x00001000
	PF_USED_MATH	 = 0x00002000
	PF_NOFREEZE	 = 0x00008000
	PF_FROZEN	 = 0x00010000
	PF_FSTRANS	 = 0x00020000
	PF_KSWAPD	 = 0x00040000
	PF_SWAPOFF	 = 0x00080000
	PF_LESS_THROTTLE = 0x00100000
	PF_KTHREAD	 = 0x00200000
	PF_RANDOMIZE	 = 0x00400000
	PF_SWAPWRITE	 = 0x00800000
	PF_SPREAD_PAGE	 = 0x01000000
	PF_SPREAD_SLAB	 = 0x02000000
	PF_THREAD_BOUND	 = 0x04000000
	PF_MEMPOLICY	 = 0x10000000
	PF_MUTEX_TESTER	 = 0x20000000
	PF_FREEZER_SKIP	 = 0x40000000
	PF_FREEZER_NOSIG = 0x80000000
	proc_stat_fields = [ "pid", "comm", "state", "ppid", "pgrp", "session",
			     "tty_nr", "tpgid", "flags", "minflt", "cminflt",
			     "majflt", "cmajflt", "utime", "stime", "cutime",
			     "cstime", "priority", "nice", "num_threads",
			     "itrealvalue", "starttime", "vsize", "rss",
			     "rlim", "startcode", "endcode", "startstack",
			     "kstkesp", "kstkeip", "signal", "blocked",
			     "sigignore", "sigcatch", "wchan", "nswap",
			     "cnswap", "exit_signal", "processor",
			     "rt_priority", "policy",
			     "delayacct_blkio_ticks" ]
	def __init__(self, pid, basedir = "/proc"):
		self.pid = pid
		self.load(basedir)
	def __getitem__(self, fieldname):
		return self.fields[fieldname]
	def keys(self):
		return self.fields.keys()
	def has_key(self, fieldname):
		return self.fields.has_key(fieldname)
	def load(self, basedir = "/proc"):
		f = open("%s/%d/stat" % (basedir, self.pid))
		fields = f.readline().strip().split()
		f.close()
		self.fields = {}
		nr_fields = min(len(fields), len(self.proc_stat_fields))
		for i in range(nr_fields):
			attrname = self.proc_stat_fields[i]
			value = fields[i]
			if attrname == "comm":
				self.fields["comm"] = value.strip('()')
			else:
				try:
					self.fields[attrname] = int(value)
				except:
					self.fields[attrname] = value
	def is_bound_to_cpu(self):
		return self.fields["flags"] & self.PF_THREAD_BOUND and \
			True or False
	def process_flags(self):
		sflags = []
		for attr in dir(self):
			if attr[:3] != "PF_":
				continue
			value = getattr(self, attr)
			if value & self.flags:
				sflags.append(attr)
		return sflags
class pidstatus:
	def __init__(self, pid, basedir = "/proc"):
		self.pid = pid
		self.load(basedir)
	def __getitem__(self, fieldname):
		return self.fields[fieldname]
	def keys(self):
		return self.fields.keys()
	def has_key(self, fieldname):
		return self.fields.has_key(fieldname)
	def load(self, basedir = "/proc"):
		f = open("%s/%d/status" % (basedir, self.pid))
		self.fields = {}
		for line in f.readlines():
			fields = line.split(":")
			if len(fields) != 2:
				continue
			name = fields[0]
			value = fields[1].strip()
			try:
				self.fields[name] = int(value)
			except:
				self.fields[name] = value
		f.close()
class process:
	def __init__(self, pid, basedir = "/proc"):
		self.pid = pid
		self.basedir = basedir
	def __getitem__(self, attr):
		if not hasattr(self, attr):
			if attr in ("stat", "status"):
				if attr == "stat":
					sclass = pidstat
				else:
					sclass = pidstatus
				setattr(self, attr, sclass(self.pid, self.basedir))
			elif attr == "cmdline":
				self.load_cmdline()
			elif attr == "threads":
				self.load_threads()
		return getattr(self, attr)
	def has_key(self, attr):
		return hasattr(self, attr)
	def load_cmdline(self):
		f = file("/proc/%d/cmdline" % self.pid)
		self.cmdline = f.readline().strip().split('\0')[:-1]
		f.close()
	def load_threads(self):
		self.threads = pidstats("/proc/%d/task/" % self.pid)
		# remove thread leader
		del self.threads[self.pid]
class pidstats:
	def __init__(self, basedir = "/proc"):
		self.basedir = basedir
		self.processes = {}
		self.reload()
	def __getitem__(self, key):
		return self.processes[key]
	def __delitem__(self, key):
		# not clear on why this can fail, but it can
		try:
			del self.processes[key]
		except:
			pass
	def keys(self):
		return self.processes.keys()
	def has_key(self, key):
		return self.processes.has_key(key)
	def reload(self):
		del self.processes
		self.processes = {}
		pids = os.listdir(self.basedir)
		for spid in pids:
			try:
				pid = int(spid)
			except:
				continue
			self.processes[pid] = process(pid, self.basedir)
	def reload_threads(self):
		for pid in self.processes.keys():
			try:
				self.processes[pid].load_threads()
			except OSError:
				# process vanished, remove it
				del self.processes[pid]
	def find_by_name(self, name):
		name = name[:15]
		pids = []
		for pid in self.processes.keys():
			try:
				if name == self.processes[pid]["stat"]["comm"]:
					pids.append(pid)
			except IOError:
				# We're doing late loading of /proc files
				# So if we get this exception is because the
				# process vanished, remove it
				del self.processes[pid]
				
		return pids
	def find_by_regex(self, regex):
		pids = []
		for pid in self.processes.keys():
			if regex.match(self.processes[pid]["stat"]["comm"]):
				pids.append(pid)
		return pids
	def find_by_cmdline_regex(self, regex):
		pids = []
		for pid in self.processes.keys():
			if regex.match(process_cmdline(self.processes[pid])):
				pids.append(pid)
		return pids
	def get_per_cpu_rtprios(self, basename):
		cpu = 0
		priorities=""
		processed_pids = []
		while True:
			name = "%s/%d" % (basename, cpu)
			pids = self.find_by_name(name)
			if not pids or len([n for n in pids if n not in processed_pids]) == 0:
				break
			for pid in pids:
				priorities += "%s," % self.processes[pid]["stat"]["rt_priority"]
			processed_pids += pids
			cpu += 1
		priorities = priorities.strip(',')
		return priorities
	def get_rtprios(self, name):
		cpu = 0
		priorities=""
		processed_pids = []
		while True:
			pids = self.find_by_name(name)
			if not pids or len([n for n in pids if n not in processed_pids]) == 0:
				break
			for pid in pids:
				priorities += "%s," % self.processes[pid]["stat"]["rt_priority"]
			processed_pids += pids
			cpu += 1
		priorities = priorities.strip(',')
		return priorities
	def is_bound_to_cpu(self, pid):
		return self.processes[pid]["stat"].is_bound_to_cpu()
class interrupts:
	def __init__(self):
		self.interrupts = {}
		self.reload()
	def __getitem__(self, key):
		return self.interrupts[str(key)]
	def keys(self):
		return self.interrupts.keys()
	def has_key(self, key):
		return self.interrupts.has_key(str(key))
	def reload(self):
		del self.interrupts
		self.interrupts = {}
		f = open("/proc/interrupts")
		for line in f.readlines():
			line = line.strip()
			fields = line.split()
			if fields[0][:3] == "CPU":
				self.nr_cpus = len(fields)
				continue
			irq = fields[0].strip(":")
			self.interrupts[irq] = {}
			self.interrupts[irq] = self.parse_entry(fields[1:], line)
			try:
				nirq = int(irq)
			except:
				continue
			self.interrupts[irq]["affinity"] = self.parse_affinity(nirq)
		f.close()
	def parse_entry(self, fields, line):
		dict = {}
		dict["cpu"] = []
		dict["cpu"].append(int(fields[0]))
		nr_fields = len(fields)
		if nr_fields >= self.nr_cpus:
			dict["cpu"] += [int(i) for i in fields[1:self.nr_cpus]]
			if nr_fields > self.nr_cpus:
				dict["type"] = fields[self.nr_cpus]
				# look if there are users (interrupts 3 and 4 haven't)
				if nr_fields > self.nr_cpus + 1:
					dict["users"] = [a.strip() for a in line[line.index(fields[self.nr_cpus + 1]):].split(',')]
				else:
					dict["users"] = []
		return dict
	def parse_affinity(self, irq):
		if os.getuid() != 0:
			return
		try:
			f = file("/proc/irq/%s/smp_affinity" % irq)
			line = f.readline()
			f.close()
			return utilist.bitmasklist(line, self.nr_cpus)
		except IOError:
			return [ 0, ]
	def find_by_user(self, user):
		for i in self.interrupts.keys():
			if self.interrupts[i].has_key("users") and \
			   user in self.interrupts[i]["users"]:
				return i
		return None
	def find_by_user_regex(self, regex):
		irqs = []
		for i in self.interrupts.keys():
			if not self.interrupts[i].has_key("users"):
				continue
			for user in self.interrupts[i]["users"]:
				if regex.match(user):
					irqs.append(i)
					break
		return irqs
class cmdline:
	def __init__(self):
		self.options = {}
		self.parse()
	def parse(self):
		f = file("/proc/cmdline")
		for option in f.readline().strip().split():
			fields = option.split("=")
			if len(fields) == 1:
				self.options[fields[0]] = True
			else:
				self.options[fields[0]] = fields[1]
		f.close()
class cpuinfo:
	def __init__(self, filename="/proc/cpuinfo"):
		self.tags = {}
		self.nr_cpus = 0
		self.sockets = []
		self.parse(filename)
	def __getitem__(self, key):
		return self.tags[key.lower()]
	def keys(self):
		return self.tags.keys()
	def parse(self, filename):
		f = file(filename)
		for line in f.readlines():
			line = line.strip()
			if len(line) == 0:
				continue
			fields = line.split(":")
			tagname = fields[0].strip().lower()
			if tagname == "processor":
				self.nr_cpus += 1
				continue
			elif tagname == "core id":
				continue
			self.tags[tagname] = fields[1].strip()
			if tagname == "physical id":
				socket_id = self.tags[tagname]
				if socket_id not in self.sockets:
					self.sockets.append(socket_id)
		f.close()
		self.nr_sockets = self.sockets and len(self.sockets) or \
				  (self.nr_cpus / ("siblings" in self.tags and int(self.tags["siblings"]) or 1))
		self.nr_cores = ("cpu cores" in self.tags and int(self.tags["cpu cores"]) or 1) * self.nr_sockets
class smaps_lib:
	def __init__(self, lines):
		fields = lines[0].split()
		self.vm_start, self.vm_end = map(lambda a: int(a, 16), fields[0].split("-"))
		self.perms = fields[1]
		self.offset = int(fields[2], 16)
		self.major, self.minor = fields[3].split(":")
		self.inode = int(fields[4])
		if len(fields) > 5:
			self.name = fields[5]
		else:
			self.name = None
		self.tags = {}
		for line in lines[1:]:
			fields = line.split()
			self.tags[fields[0][:-1].lower()] = int(fields[1])
	def __getitem__(self, key):
		return self.tags[key.lower()]
	def keys(self):
		return self.tags.keys()
class smaps:
	def __init__(self, pid):
		self.pid = pid
		self.entries = []
		self.reload()
	def parse_entry(self, f, line):
		lines = []
		if not line:
			line = f.readline().strip()
		if not line:
			return
		lines.append(line)
		while True:
			line = f.readline()
			if not line:
				break
			line = line.strip()
			if len(line.split()) < 4:
				lines.append(line)
			else:
				break
		self.entries.append(smaps_lib(lines))
		return line
	def reload(self):
		f = file("/proc/%d/smaps" % self.pid)
		line = None
		while True:
			line = self.parse_entry(f, line)
			if not line:
				break
		f.close()
		self.nr_entries = len(self.entries)
	def find_by_name_fragment(self, fragment):
		result = []
		for i in range(self.nr_entries):
			if self.entries[i].name and \
			   self.entries[i].name.find(fragment) >= 0:
			   	result.append(self.entries[i])
				
		return result
class cpustat:
	def __init__(self, fields):
		self.name = fields[0]
		(self.user,
		 self.nice,
		 self.system,
		 self.idle,
		 self.iowait,
		 self.irq,
		 self.softirq) = [int(i) for i in fields[1:8]]
		if len(fields) > 7:
			self.steal = int(fields[7])
			if len(fields) > 8:
				self.guest = int(fields[8])
class cpusstats:
	def __init__(self, filename = "/proc/stat"):
		self.entries = {}
		self.time = None
		self.hertz = os.sysconf(2)
		self.filename = filename
		self.reload()
	def __iter__(self):
		return iter(self.entries)
	def __getitem__(self, key):
		return self.entries[key]
	def __len__(self):
		return len(self.entries.keys())
	def keys(self):
		return self.entries.keys()
	def reload(self):
		last_entries = self.entries
		self.entries = {}
		f = file(self.filename)
		for line in f.readlines():
			fields = line.strip().split()
			if fields[0][:3].lower() != "cpu":
				continue
			c = cpustat(fields)
			if c.name == "cpu":
				idx = 0
			else:
				idx = int(c.name[3:]) + 1
			self.entries[idx] = c
		f.close()
		last_time = self.time
		self.time = time.time()
		if last_entries:
			delta_sec = self.time - last_time
			interval_hz = delta_sec * self.hertz
			for cpu in self.entries.keys():
				if cpu not in last_entries:
					curr.usage = 0
					continue
				curr = self.entries[cpu]
				prev = last_entries[cpu]
				delta = (curr.user - prev.user) + \
					(curr.nice - prev.nice) + \
					(curr.system - prev.system)
				curr.usage = (delta / interval_hz) * 100
				if curr.usage > 100:
					curr.usage = 100
if __name__ == '__main__':
	import sys
	ints = interrupts()
	for i in ints.interrupts.keys():
		print "%s: %s" % (i, ints.interrupts[i])
	options = cmdline()
	for o in options.options.keys():
		print "%s: %s" % (o, options.options[o])
	cpu = cpuinfo()
	print "\ncpuinfo data: %d processors" % cpu.nr_cpus
	for tag in cpu.keys():
		print "%s=%s" % (tag, cpu[tag])
	print "smaps:\n" + ("-" * 40)
	s = smaps(int(sys.argv[1]))
	for i in range(s.nr_entries):
		print "%#x %s" % (s.entries[i].vm_start, s.entries[i].name)
	print "-" * 40
	for a in s.find_by_name_fragment(sys.argv[2]):
		print a["Size"]
	ps = pidstats()
	print ps[1]
	cs = cpusstats()
	while True:
		time.sleep(1)
		cs.reload()
		for cpu in cs:
			print "%s: %d" % (cpu.name, cpu.usage)
		print "-" * 10
