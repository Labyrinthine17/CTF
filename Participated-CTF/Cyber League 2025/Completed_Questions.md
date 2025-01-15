# Table of Contents

- [Table of Contents](#table-of-contents)
- [Forensics](#forensics)
  - [Uncover Me (0 points, warm up question)](#uncover-me-0-points-warm-up-question)
    - [Problem Overview](#problem-overview)
    - [Step-by-Step Solution](#step-by-step-solution)
  - [Baby PCAP (68 points)](#baby-pcap-68-points)
    - [Problem Overview](#problem-overview-1)
    - [Step-by-Step Solution](#step-by-step-solution-1)
- [Miscellaneous](#miscellaneous)
  - [Pwn-Dis-File (50 points)](#pwn-dis-file-50-points)
    - [Problem Overview](#problem-overview-2)
    - [Step-by-Step Solution](#step-by-step-solution-2)
  - [Matryoshka (144 points)](#matryoshka-144-points)
    - [Problem Overview](#problem-overview-3)
    - [Step-by-Step Solution](#step-by-step-solution-3)

# Forensics

## Uncover Me (0 points, warm up question)

### Problem Overview

We are provided with a zip file named `hello_there_v2`. Extracting it leads to another compressed file, and through several steps, we eventually crack the password to obtain the flag.

### Step-by-Step Solution

1. **Extract the initial zip file:**
   Given the zip file `hello_there_v2`, we begin by extracting it:

   ```bash
   unzip hello_there_v2
   ```

   This results in a file named `hello_there_v2.7z`.

2. **Extract the `.7z` file:**
   Next, we use the 7z command to extract the `.7z` archive:

   ```bash
   7z x hello_there_v2.7z
   ```

   This gives us a `hello_there.tar` file.

3. **Extract the .tar file:**
   Using the tar command, we extract the contents of the hello_there.tar archive:

   ```bash
   tar -xvf hello_there.tar
   ```

   This produces another zip file: `hello_there.zip`.

4. **Extract the hash for cracking:**
   Now that we have the hello_there.zip file, we use the `zip2john` utility to extract the hash for password cracking:

   ```bash
   zip2john hello_there.zip > hash.txt
   ```

5. **Crack the password using John the Ripper:** 
   We run John the Ripper with a wordlist (`rockyou.txt`) to crack the password:

   ```bash
   john --wordlist=rockyou.txt hash.txt
   ```

   The output from John the Ripper is:

   ```bash
    Using default input encoding: UTF-8
    Loaded 1 password hash (PKZIP [32/64])
    Will run 18 OpenMP threads
    Note: Passwords longer than 21 [worst case UTF-8] to 63 [ASCII] rejected
    Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
    2hot4u           (hello_there.zip/hello_there.txt)
    1g 0:00:00:00 DONE (2025-01-15 21:40) 25.00g/s 921600p/s 921600c/s 921600C/s 123456..holabebe
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed.
    ```

    The cracked password for the zip file is `2hot4u`.

6. **Extract the contents of the zip file:**
   Using the cracked password, we unzip the hello_there.zip file:

   ```bash
   unzip hello_there.zip
   ```

   This gives us a text file: `hello_there.txt`.

7. **Retrieve the flag:**
   Opening the hello_there.txt file reveals the flag:
   
   `CYBERLEAGUE{Y0U_Fo|_|nD_3e!}`.

## Baby PCAP (68 points)

### Problem Overview

We are provided with a pcap file. By analyzing the packets within the file, we can extract the flag through a series of steps involving decoding and decryption.

### Step-by-Step Solution

1. **Open the pcap file:**
   We begin by opening the pcap file using **Wireshark**. After examining the packets, we start with follow the HTTP stream.

2. **Identifying the relevant packet:**
   In the HTTP stream, we find that **Packet 12** contains a Python script. From the Python script, we can deduce that the flag is obtained by:
   - XORing the flag with a key (provided in the script)
   - Base64 encoding the result

3. **Extracting the encoded flag:**
   After sorting the packets by their length in **Wireshark**, we locate the following base64 encoded string: 
   `ECwydiAfdiIyJ3YrIhIRLm8lBVNMVCMqA0cdPVgQKkoKZCUZFT9DOAFEUFw=`

4. **Reversing the encoding:**
   To retrieve the original flag, we reverse the process:
   - First, we decode the base64 string.
   - Then, we XOR the decoded result with the key provided in the Python script.

5. **Flag obtained:**
   After performing the reverse operations, we obtain the flag:

   `CYBERLEAGUE{baby_warmup_stonks_894ejfhsjeeq}`

# Miscellaneous

## Pwn-Dis-File (50 points)

### Problem Overview

We are given a PDF file that contains hidden information. By opening the file in Adobe Acrobat and inspecting the attached files, we can uncover the flag.

### Step-by-Step Solution

1. **Open the file in Adobe Acrobat:**
   Begin by opening the provided file in **Adobe Acrobat**.

2. **Inspect the right panel:**
   In Adobe Acrobat, navigate to the panel on the right. Here, you will find a section labeled **Attachments** / **Files**.

3. **Open the attached file:**
   Within the **Attachments** section, you will see a file named `file.txt`. Open this file to reveal its contents.

4. **Retrieve the flag:**
   The contents of the file `file.txt` is the flag:

   `CYBERLEAGUE{hidden_in_plain_sight}`

## Matryoshka (144 points)

### Problem Overview

We are given a compressed file. The task is to decompress it repeatedly until we reach a file that is no longer compressed. This requires us to identify the compression type and decompress it accordingly, repeating the process until the final file is obtained.

### Step-by-Step Solution

1. **Write the shell script:**
   We write a shell script that will:
   - Check if the file is compressed.
   - Rename the file to the corresponding compression type.
   - Decompress it based on the compression type.
   - Repeat the process until the file is no longer compressed.

2. **Shell Script:**
   The following shell script handles the decompression process:

   [decompress_repeatedly.sh](/Participated-CTF/Cyber%20League%202025/decompress_repeatedly.sh)

3. **Running the Script:**
   When running the script on the compressed file, it will repeatedly decompress the file until it is no longer compressed. The final output will reveal the flag.

4. **Flag obtained:**
   After many decompressions, the final file contains the flag: 

   `CYBERLEAGUE{m0r3_c0mpr3ss_m0r3_b3tt3r3r}`.

