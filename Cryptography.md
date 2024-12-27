# Cryptography

- [Cryptography](#cryptography)
  - [Different type representations](#different-type-representations)
  - [Conversions between different types](#conversions-between-different-types)
    - [From ASCII](#from-ascii)
    - [From base-10 / integer](#from-base-10--integer)
    - [From Hexadecimal](#from-hexadecimal)
    - [From Base64](#from-base64)
    - [From Bytes](#from-bytes)
    - [From Big Integers (long)](#from-big-integers-long)
  - [Examples of possible conversions](#examples-of-possible-conversions)
  - [XOR](#xor)
    - [Properties of XOR](#properties-of-xor)
    - [Examples of XOR questions](#examples-of-xor-questions)
  - [RSA](#rsa)
    - [Greatest Common Divisor](#greatest-common-divisor)
    - [Extended Euclidean Algorithm](#extended-euclidean-algorithm)

## Different type representations

message: HELLO\
ascii bytes: [72, 69, 76, 76, 79]\
hex bytes: [0x48, 0x45, 0x4c, 0x4c, 0x4f]\
bytes: b'r\xbc\xa9\xb6\x8f\xc1j\xc7\xbe\xeb'\
base-16: 0x48454c4c4f\
base-10: 310400273487

## Conversions between different types

### From ASCII

| Convert To Type | Function | Description |
| ----------- | ----------- | ----------- |
| numbers / base 10| ```ord(string)``` | convert letters to numbers |
| base64 encoding | ```base64.b64encode(b'string')``` | encode bytes string into base64 |

### From base-10 / integer

| Convert To Type | Function | Description |
| ----------- | ----------- | ----------- |
| strings | ```chr(integer)``` |  convert numbers to letters |

### From Hexadecimal

| Convert To Type | Function | Description |
| ----------- | ----------- | ----------- |
| bytes | ```bytes.fromhex("<hex>")``` |  convert hex to byte string |
| bytes | ```binascii.unhexlify("<hex>")``` | from hex to byte string |

### From Base64

- Represent binary data as ASCII string using an alphabet of 64 characters
- One character of a Base64 string encodes 6 binary digits (bits), and so 4 characters encode 3 8-bit bytes
- Allows binary data such as images included into HTML or CSS files

| Convert To Type | Function | Description |
| ----------- | ----------- | ----------- |
| byte string | ```base64.b64decode(b'encoded_string')``` | decode from base64|

### From Bytes

- Python's PyCryptodome library implements this with the methods ```bytes_to_long()``` and ```long_to_bytes()```.
- You will first have to install PyCryptodome and import it with ```from Crypto.Util.number import *```.

| Convert To Type | Function | Description |
| ----------- | ----------- | ----------- |
| hex | ```<byte_string>.hex()``` | instance method can be called on byte strings to get hex representation |
| hex | ```binascii.hexlify(b'string')``` | from bytes string to hex |
| base64 encoding | ```base64.b64encode(b'string')``` | encode bytes string into base64 |
| bytes | ```bytes_to_long(b'string')``` | convert bytes string to long value |

### From Big Integers (long)

- Python's PyCryptodome library implements this with the methods ```bytes_to_long()``` and ```long_to_bytes()```.
- You will first have to install PyCryptodome and import it with ```from Crypto.Util.number import *```.

| Convert To Type | Function | Description |
| ----------- | ----------- | ----------- |
| bytes | ```long_to_bytes(long_value)``` | convert long to bytes string |

## Examples of possible conversions

1. From hex string → bytes → base64 encoded string

    ```python
    import base64
    x = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"
    y = bytes.fromhex(x)
    print("y:",y)
    z = base64.b64encode(y)
    print("z:",z)

    y: b'r\xbc\xa9\xb6\x8f\xc1j\xc7\xbe\xeb\x8f\x84\x9d\xca\x1d\x8ax>\x8a\xcf\x96y\xbf\x92i\xf7\xbf'
    z: b'crypto/Base+64+Encoding+is+Web+Safe/'
    ```

2. From a list of numbers → ASCII letters → base-16 numbers (hexadecimal) → combine into one long hex string

3. Using binascii to convert between byte strings and hex

   ```python
    import binascii
    binascii.hexlify(b'HELLO')  # to Hex
    >>> b'48454c4c4f'
    binascii.unhexlify('48454c4c4f')  # from Hex
    >>> b'HELLO'

   ```

## XOR

| A | B | Output |
| - | - | - |
| 0 | 0 | 0 |
| 0 | 1 | 1 |
| 1 | 0 | 1 |
| 1 | 1 | 0 |

### Properties of XOR

Commutative
: A ⊕ B = B ⊕ A

Associative
: A ⊕ (B ⊕ C) = (A ⊕ B) ⊕ C

Identity
: A ⊕ 0 = A → XOR with 0 does nothing, return you the thing itself

Self-Inverse
: A ⊕ A = 0 → XOR with itself return 0

### Examples of XOR questions

1. Given the string label, XOR each character with the integer 13. Convert these integers back to a string and submit the flag as crypto{new_string}. The Python pwntools library has a convenient xor() function that can XOR together data of different types and lengths. Note that the below code doesn't work on google colab.

    ```python
    %pip install pwntools
    from pwn import xor

    given = "label"
    print("crypto{", end="")
    for x in given:
    print(chr(ord(x)^13), end="")
    print("}")
    ```

2. I've hidden some data using XOR with a single byte, but that byte is a secret. Don't forget to decode from hex first.

    73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d

    SOLUTION 1

    ```python
    FLAG = '73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d'
    FLAG = bytes.fromhex(FLAG)

    # For all byte value from 0 to 255
    for i in range (256):
    res = [b ^ i for b in FLAG] 
    res = ''.join([chr(i) for i in res])
    if res.startswith('crypto'):
        print(res)
    ```

    SOLUTION 2

    ```python
    input_str = bytes.fromhex('73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d')
    # Can just take the first one since xor is commutative
    print(input_str[0])
    key = input_str[0] ^ ord('c')
    print(''.join(chr(c ^ key) for c in input_str))
    ```

3. We have known part of plaintext that is 'crypto{...}', so you can use this to xor with corresponding ciphertext, then get part of key. finally just to guess the full key.

    ```python
    from pwn import * 
    FLAG = '0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104' 
    FLAG = bytes.fromhex(FLAG) 
    print(FLAG) 
    partial = FLAG[:7] 
    print(partial)
    string = "crypto{" 
    string = string.encode() 
    print(string) 
    xorkey = xor(string, partial) 
    print(xorkey) 
    partial_key = "myXORkey" 
    complete_key = (partial_key * (len(FLAG)//len(partial_key)+1))[:len(FLAG)]
    print(complete_key) 
    res = xor(FLAG, complete_key.encode()).decode() 
    print(res) 

    b"\x0e\x0b!?&\x04\x1eH\x0b&!\x7f'4.\x17]\x0e\x07\n<[\x10>%&!\x7f'4.\x17]\x0e\x07~&4Q\x15\x01\x04" 
    b'\x0e\x0b!?&\x04\x1e' 
    b'crypto{' 
    b'myXORke' 
    myXORkeymyXORkeymyXORkeymyXORkeymyXORkeymy
    crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll} 
    ```

## RSA

Let a and b be positive integers.\
The extended Euclidean algorithm is an efficient way to find integers u, v such that ``` a * u + b * v = gcd(a,b) ```\
To decrypt RSA, we will need this algorithm to calculate the modular inverse of the public exponent.

### Greatest Common Divisor

```python
def gcd(a, b):
    if (b == 0):
        return a
    return gcd(b, (a % b))

print(gcd(12,8))
print(gcd(66528,52920))

OR

import math
print(math.gcd(66528, 52920))
```

### Extended Euclidean Algorithm

Using the two primes p = 26513, q = 32321, find the integers u, v such that ```p * u + q * v = gcd(p,q)```

```python
def extended_gcd(p,q):
    if p == 0:
        return (q, 0, 1)
    else:
        (gcd, u, v) = extended_gcd(q % p, p)
        return (gcd, v - (q // p) * u, u)

p = 26513
q = 32321

gcd, u, v = extended_gcd(p, q)
print("[+] GCD: {}".format(gcd))
print("[+] u,v: {},{}".format(u,v))
print("\n[*] FLAG: crypto{{{},{}}}".format(u,v))
```
