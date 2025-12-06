# React2Shell NSE Test Report

| Port | App | Test Success | Expected Vulnerable | Detected Vulnerable | Listening |
|------|-----|--------------------|--------------------|-----------|---------|
| 3000 | Next.js 15.5.6 | ✅ | ✅ | ✅ | ✅ |
| 3001 | Next.js 15.5.7 | ✅ | ❌ | ❌ | ✅ |

## Detailed Nmap Output

### Port 3000 (Next.js 15.5.6)

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-06 17:31 EST
NSE: Loaded 1 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 17:31
Completed NSE at 17:31, 0.00s elapsed
Initiating Ping Scan at 17:31
Scanning localhost (127.0.0.1) [2 ports]
Completed Ping Scan at 17:31, 0.00s elapsed (1 total hosts)
Initiating Connect Scan at 17:31
Scanning localhost (127.0.0.1) [1 port]
Discovered open port 3000/tcp on 127.0.0.1
Completed Connect Scan at 17:31, 0.00s elapsed (1 total ports)
NSE: Script scanning 127.0.0.1.
Initiating NSE at 17:31
Completed NSE at 17:31, 0.43s elapsed
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00055s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE
3000/tcp open  ppp
|_detect_react2shell: VULNERABLE: React2Shell detected!

NSE: Script Post-scanning.
Initiating NSE at 17:31
Completed NSE at 17:31, 0.00s elapsed
Read data files from: /usr/local/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.55 seconds

```

### Port 3001 (Next.js 15.5.7)

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-06 17:31 EST
NSE: Loaded 1 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 17:31
Completed NSE at 17:31, 0.00s elapsed
Initiating Ping Scan at 17:31
Scanning localhost (127.0.0.1) [2 ports]
Completed Ping Scan at 17:31, 0.00s elapsed (1 total hosts)
Initiating Connect Scan at 17:31
Scanning localhost (127.0.0.1) [1 port]
Discovered open port 3001/tcp on 127.0.0.1
Completed Connect Scan at 17:31, 0.00s elapsed (1 total ports)
NSE: Script scanning 127.0.0.1.
Initiating NSE at 17:31
Completed NSE at 17:31, 0.52s elapsed
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00032s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE
3001/tcp open  nessus

NSE: Script Post-scanning.
Initiating NSE at 17:31
Completed NSE at 17:31, 0.00s elapsed
Read data files from: /usr/local/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.63 seconds

```
