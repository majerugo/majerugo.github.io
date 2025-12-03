# Cap

## Reconnaissance

First step use nmap to find open ports and services
nmap -p- -sT <target_ip>

## Exploitation

And go to the web site find previously and get the wireshark capture file for the id 0 by changing the id in the url.

We can see FTP exchange of password in clear text.
So we can try to login in ssh with the same credentials.

And now we have a shell.

## Privilege Escalation

But we need to escalate our privileges to root.

Get the `linpeas.sh` script from [LINPEAS Github](https://github.com/peass-ng/PEASS-ng/blob/master/linPEAS/README.md) and run it to find possible privilege escalation vectors.

We find `/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip` which means that the binary has the capabilities to bind to low ports and to change user ids.

We will exploit the setuid capability to spawn a root shell.

```bash
python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
And we are root!