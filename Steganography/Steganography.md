# Steganography

- [Steganography](#steganography)
  - [File format](#file-format)
    - [`png` images](#png-images)
    - [`zip` files](#zip-files)
  - [Common Tools](#common-tools)
    - [Steghide](#steghide)
    - [Stegosuite](#stegosuite)
    - [Stegsolve](#stegsolve)

## File format

1. Identify file type using `file <filename>`
2. check the metadata using `exiftool <filename>`
- File extraction using `binwalk`

    ```bash
    binwalk --extract --dd=".*" <filename>
    ```

### `png` images

Run `pngcheck` to check if it is a valid png image and if it requires fixing.  

Minimal PNG Hex Structure (1x1 red pixel, non-interlaced RGB)  

```yaml
[PNG Signature] (8 bytes)
89 50 4E 47 0D 0A 1A 0A      → Always the same

[IHDR Chunk] (25 bytes total)
00 00 00 0D                  → Length: 13 bytes of data
49 48 44 52                  → Chunk Type: IHDR
00 00 00 01                  → Width: 1
00 00 00 01                  → Height: 1
08                           → Bit depth: 8
02                           → Color type: 2 (Truecolor RGB)
00                           → Compression method: 0 (deflate)
00                           → Filter method: 0
00                           → Interlace method: 0 (no interlace)
90 77 53 DE                  → CRC32 of IHDR chunk

[IDAT Chunk] (17 bytes total)
00 00 00 0A                  → Length: 10 bytes
49 44 41 54                  → Chunk Type: IDAT
08 D7 63 F8 CF C0 00 00 04 00 → zlib-compressed image data (1 pixel: red)
B5 5C 4C 3B                  → CRC32 of IDAT chunk

[IEND Chunk] (12 bytes total)
00 00 00 00                  → Length: 0
49 45 4E 44                  → Chunk Type: IEND
AE 42 60 82                  → CRC32 of IEND
```

- All chunk lengths are big-endian 4-byte values.
- CRCs are calculated over [chunk type] + [chunk data], not including length.
- The IDAT data is deflate-compressed; here, it decodes to 1 red pixel (R=255, G=0, B=0) with filter byte prefix.

### `zip` files

Minimal ZIP File Hex Structure (1 file: hello.txt, empty content)

ZIP files are structured in these main parts:

1. Local File Header
2. File Data (optional)
3. Central Directory
4. End of Central Directory Record (EOCD)

```yaml
[Local File Header] (30 bytes + filename)
50 4B 03 04                  → Signature: Local File Header (0x04034b50)
14 00                        → Version needed to extract (2.0)
00 00                        → General purpose bit flag
00 00                        → Compression method (0 = no compression)
00 00                        → File modification time
00 00                        → File modification date
00 00 00 00                  → CRC-32 (zero because file is empty)
00 00 00 00                  → Compressed size
00 00 00 00                  → Uncompressed size
05 00                        → File name length: 5
00 00                        → Extra field length
68 65 6C 6C 6F              → Filename: "hello"

[Central Directory Header] (46 bytes + filename)
50 4B 01 02                  → Signature: Central Directory File Header (0x02014b50)
14 00                        → Version made by
14 00                        → Version needed to extract
00 00                        → General purpose bit flag
00 00                        → Compression method
00 00                        → File mod time
00 00                        → File mod date
00 00 00 00                  → CRC-32
00 00 00 00                  → Compressed size
00 00 00 00                  → Uncompressed size
05 00                        → File name length: 5
00 00                        → Extra field length
00 00                        → File comment length
00 00                        → Disk number start
00 00                        → Internal file attributes
00 00 00 00                  → External file attributes
00 00 00 00                  → Offset of local header
68 65 6C 6C 6F              → Filename: "hello"

[End of Central Directory Record] (22 bytes)
50 4B 05 06                  → Signature: End of central directory (0x06054b50)
00 00                        → Number of this disk
00 00                        → Disk where central directory starts
01 00                        → Number of central directory records on this disk
01 00                        → Total number of central directory records
2E 00 00 00                  → Size of central directory (46 bytes)
1F 00 00 00                  → Offset of central directory (31 bytes after start)
00 00                        → ZIP file comment length
```

## Common Tools

### Steghide

Install using `sudo apt-get install steghide`

Usage:

```bash
$ steghide extract -sf kapow.jpg
Enter passphrase:
wrote extracted data to "flag.txt".

$ steghide info kapow.jpg
<information about the jpg will be shown>
<such as any hidden data>
```

Sometimes a passphrase will be needed.

### Stegosuite

Install using `sudo apt-get install stegosuite`

Usage: `stegosuite gui` and upload the image to extract data

### Stegsolve

Install the jar file, run it with `java -jar ./bin/stegsolve.jar`. Replace the path to the jar file accordingly.