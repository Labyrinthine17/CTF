#!/bin/bash

is_compressed() {
    file "$1" | grep -qE 'gzip|bzip2|XZ|zip|tar'
}

process_file() {
local file="$1"

echo "Original Filename: $file"

while is_compressed "$file"; do
    file_type=$(file -b "$file")
    echo "File Type: $file_type"

    case "$file_type" in
    *gzip*)
        new_filename="${file}.gz"
        ;;
    *bzip2*)
        new_filename="${file}.bz2"
        ;;
    *XZ*)
        new_filename="${file}.xz"
        ;;
    *Zip*)
        new_filename="${file}.zip"
        ;;
    *tar*)
        new_filename="${file}.tar"
        ;;
    *)
        new_filename="$file"
        ;;
    esac

    mv "$file" "$new_filename"

    echo "Updated Filename: $new_filename"

    case "$new_filename" in
    *.gz)
        gunzip "$new_filename"
        ;;
    *.bz2)
        bunzip2 "$new_filename"
        ;;
    *.xz)
        unxz "$new_filename"
        ;;
    *.zip)
        unzip "$new_filename"
        ;;
    *.tar)
        tar -xvf "$new_filename"
        ;;
    *)
        echo "Unknown compression type."
        break
        ;;
    esac

done

echo "Final Filename: $file"
}

if [ -z "$1" ]; then
echo "No file is provided."
exit 1
fi

process_file "$1"
