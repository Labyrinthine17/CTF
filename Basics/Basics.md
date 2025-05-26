# Basics

- [Basics](#basics)
  - [Shell scripting](#shell-scripting)
    - [Basic bash script](#basic-bash-script)
    - [Variables](#variables)
    - [Parsing arguments](#parsing-arguments)
    - [Arithmetic operations](#arithmetic-operations)
    - [For loop](#for-loop)
    - [While loop](#while-loop)
    - [Until loop](#until-loop)
    - [Arrays](#arrays)
    - [Exit status](#exit-status)
    - [Conditional statements](#conditional-statements)
    - [Executing the script](#executing-the-script)
  - [Common linux commands](#common-linux-commands)
    - [`grep` command](#grep-command)
    - [Scheduling](#scheduling)
    - [Network related commands](#network-related-commands)
  - [SSH](#ssh)

## Shell scripting

[Reference link](https://zerotomastery.io/blog/bash-scripting-interview-questions/)

### Basic bash script

```bash
#!/bin/bash
echo "Hello, world!"
```

To make the script executable: `chmod +x script.sh`

To run the script: `./script.sh`

### Variables

```bash
#!/bin/bash
name = "John Smith"
echo "Hello, $name"
```

### Parsing arguments

```bash
#!/bin/bash
echo "Script name: $0"
echo "Argument 1: $1"
echo "Argument 2: $2"
```

For more complex argument handling, you can use getopts to process options:

```bash
#!/bin/bash
while getopts ":a:b:" opt; do
  case $opt in
	a) echo "Option A with value: $OPTARG" ;;
	b) echo "Option B with value: $OPTARG" ;;
	\?) echo "Invalid option: -$OPTARG" ;;
  esac
done
```

### Arithmetic operations

```bash
#!/bin/bash
result=$((5 + 3))
echo "Result: $result"

# OR
result=$(expr 5 + 3)
echo "Result: $result"

# OR
let result=5+3
echo "Result: $result"
```

### For loop

```shell
for file in ./files/*; do decrypt.sh "$file" ; done
```

```bash
#!/bin/bash
for i in 1 2 3; do 
    echo "i = $i"
done
```

### While loop

```bash
#!/bin/bash
count = 0
while [ $count -le 5 ]; do
    echo "count = $count"
    (( count++ ))
done
```

### Until loop

```bash
#!/bin/bash
i = 5
until [ $i == 1 ]
do
    echo "$i is not equal to 1";
    i=$((i-1))
done
echo "i value is $i"
echo "loop terminated"
```

### Arrays

```bash
#!/bin/bash
fruits=("Apple" "Banana" "Cherry")

echo ${fruits[0]}  # Outputs: Apple

# Outputs: each of the fruit in the array
for fruit in "${fruits[@]}"; do
  echo $fruit
done
```

### Exit status

A command returns 0 on success and a non-zero value on failure.

```bash
#!/bin/bash
command1
if [ $? -ne 0 ]; then
  echo "command1 failed"
  exit 1
fi
```

If command1 fails, this script prints an error message and exits with a status of 1.

Alternatively, use `set -e` option, which automatically exits the script if any command returns a non-zero exit status. This ensures the script stops immediately when an error occurs:

```bash
#!/bin/bash
set -e

command1
command2
command3 || true # allows command3 to fail without causing the script to exit.
```

### Conditional statements

```bash
#!/bin/bash
case $variable in
  pattern1)
    echo "Pattern 1 matched"
    ;;
  pattern2)
    echo "Pattern 2 matched"
    ;;
  *)
    echo "No pattern matched"
    ;;
esac
```

### Executing the script

The `source` (or its shorthand `.`) command runs a script within the current shell environment, meaning any changes to variables, functions, or the environment persist after the script finishes.

```shell
source script.sh
# or
. script.sh
```

On the other hand, ./ runs the script in a new subshell, which is a separate process. Any changes made by the script do not affect the current shell environment:

```shell
./script.sh
```

## Common linux commands

### `grep` command

```shell
grep "pattern" file.txt
grep -i "pattern" file.txt # case sensitive
grep -r "pattern" /path/to/directory # recursively through directory
grep -c "pattern" file.txt # count number of matching lines
```

### Scheduling
`cron` is a job scheduler that lets you run scripts at specified times or intervals, managed using `crontab` file, which lists the scheduled tasks.

```shell
crontab -e # to edit the crontab file
```

A cron job is defined by a line with five time fields followed by the command:

`* * * * * /path/to/script.sh`

This job runs a script every day at 5:00 AM:

`0 5 * * * /path/to/script.sh`

### Network related commands

Refer to [Forensics](/Forensics/Forensics.md) Notes for related commands.

## SSH

[Linux SSH commands](https://phoenixnap.com/kb/linux-ssh-commands)

Format: ssh -p 123456 userName@address