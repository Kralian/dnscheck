# So simple it's almost a hack

Lots of it is inspired by
	https://github.com/tykling/tykdnscheck
	https://pypi.org/project/dnslib/ aka https://github.com/paulc/dnslib

And some digging around in socketserver do find out what to put where to make it dual
stack. I should probably suggest dnslib some kind of patch to DNSServer

I use supervisor to run it and requirements.txt is the easiest way to pull in dnslib.

```conf
[program:dnscheckv4]
command=/usr/bin/python /home/dnscheck/dnscheck.py -o domain -m uptime:uptime -m date:date --log-prefix --log truncated,error -a 0.0.0.0 --tcp
directory=/home/dnscheck
user=root
stdout_syslog=False
stderr_syslog=False
startsecs=1
autostart=True
redirect_stderr=true
stdout_logfile=/home/dnscheck/v4.supervisor.log
stdout_logfile_maxbytes=10MB
stdout_logfile_backups=3

[program:dnscheckv6]
command=/usr/bin/python /home/dnscheck/dnscheck.py -o domain -m uptime:uptime -m date:date --log-prefix --log truncated,error -a :: --tcp
directory=/usr/home/amd/dnscheck
user=root
stdout_syslog=False
stderr_syslog=False
startsecs=1
autostart=True
redirect_stderr=true
stdout_logfile=/usr/home/amd/dnscheck/v6.supervisor.log
stdout_logfile_maxbytes=10MB
stdout_logfile_backups=3
```
