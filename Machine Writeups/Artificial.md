
![image](img/Artificial/Artificial.png)

## Nmap Enumeration

```bash
└─$ nmap -p $(cat ports.txt) -sVT -O --min-rate=2000 10.10.11.74
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-22 07:56 EDT
Nmap scan report for 10.10.11.74
Host is up (0.44s latency).

PORT     STATE  SERVICE        VERSION
22/tcp   open   ssh            OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open   http           nginx 1.18.0 (Ubuntu)
8888/tcp closed sun-answerbook
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.30 seconds

```


This box is still active on HackTheBox. Once retired, this writeup will be published for public access as per HackTheBox's policy on publishing content from their platform