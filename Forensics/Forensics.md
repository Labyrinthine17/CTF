# Forensics

## File format

1. Identify file type using ```file <filename>```
2. check the metadata using ```exiftool <filename>```

- File extraction using ```binwalk```

    ```bash
    binwalk --extract --dd=".*" <filename>
    ```

