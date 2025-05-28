# Forensics

- [Forensics](#forensics)
  - [Investigate installed software](#investigate-installed-software)
  - [Common Tools](#common-tools)
    - [Wireshark](#wireshark)
  - [Linux commands](#linux-commands)
    - [`file` command](#file-command)
    - [`exiftool` command](#exiftool-command)
    - [`strings` command](#strings-command)
    - [`xxd` command](#xxd-command)
    - [`binwalk` command](#binwalk-command)
    - [`dig` command](#dig-command)
    - [`nslookup` command](#nslookup-command)
    - [`whois` command](#whois-command)
    - [`ipconfig` and `ifconfig` command](#ipconfig-and-ifconfig-command)
    - [`netstat` command](#netstat-command)
    - [`nmap` command](#nmap-command)
    - [`tcpdump` command](#tcpdump-command)
    - [`curl` command](#curl-command)
    - [`lsof` command](#lsof-command)
    - [`ps` command](#ps-command)

## Investigate installed software

Common paths to check for an installed software:

## Common Tools

### Wireshark

## Linux commands

### `file` command
`file <filename>`  
Identifies the file type. This command analyzes the file’s magic bytes and returns its actual format, rather than relying on file extensions.

### `exiftool` command
`exiftool <filename>`  
Check the metadata, extracts metadata from various file types, including images, documents, and media files. Useful for retrieving timestamps, authorship info, and embedded comments.

### `strings` command
`strings <filename> | less`  
Extract Strings from the File Scans the file for readable text embedded within binary data. Helps detect encoded messages, hidden clues, or potential passwords. (Use less first in case it's very long)

### `xxd` command
`xxd <filename> | head`  
Check Hex Dump for deeper inspection. Displays the file’s contents in hexadecimal and ASCII format. Useful for spotting patterns, file signatures, or anomalies.

### `binwalk` command

Check for Embedded Data & Compressed Archives. File extraction using ```binwalk```

    ```bash
    $ binwalk --extract --dd=".*" <filename>
    ```

### `dig` command

`dig` is "Domain Information Groper" which is used to query DNS servers and obtain DNS records for a domain.

```bash
$ dig example.com
```

This returns the DNS information for the domain `example.com`, including IP.

Types of DNS records includes:

- `A` (Address Record)
- `AAAA` (IPv6 Address Record)
- `MX` (Mail Exchange Record)
- `CNAME` (Canonical Name Record)
- `NS` (Name Server Record)
- `TXT` (Text Record)
- `SOA` (Start of Authority Record)

### `nslookup` command

`nslookup` is usable on both Linux and Windows. It is also used to query DNS servers  to retrieve domain name or IP address information. However, in Linux, `dig` is more commonly used as it provides advanced features over `nslookup`.

### `whois` command

`whois` retrieves domain registration information, including owner details and expiration date.

```bash
$ whois example.com
```

Windows Equivalent: There isn’t a built-in equivalent of whois on Windows, but you can install tools like WHOIS command-line client or use online WHOIS services (e.g., https://whois.domaintools.com).

### `ipconfig` and `ifconfig` command

- **Windows**: `ipconfig` displays network configurations and IP addresses.
- **Linux**: `ifconfig` shows active network interfaces and their details. For modern Linux distributions, `ip a` serves as an alternative to `ifconfig`.

### `netstat` command

Displays network connections, routing tables, interface statistics, and network protocols.

```bash
$ netstat -tuln
```

This shows all active network connections, listening ports, and associated services.

### `nmap` command

A tool for network discovery and vulnerability scanning. It is widely used for scanning open ports on remote systems and identifying services.

```bash
$ nmap -sP 192.168.1.0/24
```

This will perform a Ping Sweep on the 192.168.1.0 network to identify live hosts.

### `tcpdump` command

A network packet analyzer that captures network traffic.

```bash
$ tcpdump -i eth0
```

This will capture all traffic on the eth0 network interface.  
Alternative: Wireshark (Graphical interface) or tshark (command-line version of Wireshark).  

### `curl` command

Used to interact with URLs, often used to test web servers, make HTTP requests, and download data.

```bash
$ curl http://example.com
```

### `lsof` command

Lists all open files and processes using those files.

```bash
$ lsof -i :80
```

This shows all processes that are listening on port 80 (HTTP).

### `ps` command

Displays information about the running processes.

```bash
$ ps aux
```

This shows a list of all running processes along with detailed information.
