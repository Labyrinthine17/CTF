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

### `ipconfig` and `ifconfig` command

- **Windows**: `ipconfig` displays network configurations and IP addresses.
- **Linux**: `ifconfig` shows active network interfaces and their details. For modern Linux distributions, `ip a` serves as an alternative to `ifconfig`.
