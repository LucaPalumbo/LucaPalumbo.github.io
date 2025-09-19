---
title: "DefCamp Quals"
date: 2025-09-12T12:00:00+00:00
categories:
  - writeup
tags:
  - writeup
  - reverse engineering
  - DefCamp Quals
author: "Luca"
excerpt: "Short write-ups of 2 challenges"

read_time: true
---


## Reverse Engineering - mach-triangle

> Flag: `DCTF{77cf682bd72ae03d3644c1f43b97020fcc6446b2c88c02757be0e46c40dcc90b}`


The file provided is a Mach-O 64-bit executable.

The executable reads a password from `argv` and validates it. If the password is correct it print 'Correct'.  

The algorithm used to validate the password works like this:
- the buffer `buffer_1` and `int_buffer` are filled in a way that does not depend on user input
- the input is padded to reach length multiple of 8
- a chunk of 8 bytes of the input gets XORed with a `xor_key` ( initially an initialization vector )
- this XORed value is passed to a `final` function that encrypts it, and the resulting chunk is saved in the output buffer
- the `xor_key` is updated with the output of the previous chunk
- a new chunk get xorred and passed to `final`, and so on...

This is basically a CBC block cipher

```c

  xor_key = *(byte (*) [8])IV;
  for (i = 0; i < (int)len_padded; i = i + 8) {
    for (j = 0; j < 8; j = j + 1) {
      xorred[j] = input_padded[i + j] ^ xor_key[j];
    }
    final(xorred,buffer_1,size,int_buffer,output + i);
    xor_key = *(byte (*) [8])(output + i);
  }
  return;

```

The reversed `final` function looks like this:

```c

void final(byte *xorred_input,byte *buffer_1,int size,int *int_buffer,undefined8 out)

{
  byte bVar1;
  int y;
  int k;
  byte scramble [8];
  byte byte;
  int j;
  uint integrer;
  int i;
  int m;
  byte result [8];
  byte *input;
  int div;
  
  result = *(byte (*) [8])xorred_input;
  for (m = 0; m < 8; m = m + 1) {
    div = 0;
    if (size != 0) {
      div = m / size;
    }
    result[m] = result[m] ^ buffer_1[m - div * size];
  }
  for (i = 0; i < 4; i = i + 1) {
    integrer = int_buffer[i];
    for (j = 0; j < 8; j = j + 1) {
      byte = (char)integrer + (char)j + (char)i;
      result[j] = (&sbox)[(int)(uint)(result[j] ^ byte)];
    }
    for (k = 0; k < 8; k = k + 1) {
      scramble[(k * 3 + i) % 8] = result[k];
    }
    result[0] = scramble[0];
    result[1] = scramble[1];
    result[2] = scramble[2];
    result[3] = scramble[3];
    result[4] = scramble[4];
    result[5] = scramble[5];
    result[6] = scramble[6];
    result[7] = scramble[7];
    for (y = 0; y < 8; y = y + 1) {
      result[y] = result[y] ^ (byte)(integrer >> (ulong)((y % 4) * 8 & 0x1f));
      bVar1 = rot_left(result[y],(i + 1) % 8);
      result[y] = bVar1;
    }
  }
  ___memcpy_chk(out,result,8,0xffffffffffffffff);
  return;
}
```

So I implemented a python script to reverse this process:

```python
#!/usr/bin/env python3
from pwn import xor

SBOX = [
    0xd7, 0xc7, 0x0c, 0x56, 0xa3, 0x3b, 0x60, 0x55, 0x2f, 0x88, 0x5d, 0x1d, 0x5e, 0x23, 0x08, 0x3d,
    0x32, 0x40, 0x5c, 0x46, 0x06, 0x0b, 0x21, 0x25, 0xc4, 0x3a, 0x04, 0x78, 0x2b, 0x11, 0x58, 0x0d,
    0x37, 0x35, 0xa5, 0x36, 0x6d, 0x2c, 0x00, 0x92, 0x2a, 0x4f, 0x13, 0x28, 0xdb, 0x64, 0x0f, 0x8a,
    0x1c, 0xc6, 0xd5, 0xb4, 0xa6, 0x9c, 0x47, 0x82, 0x3f, 0x1f, 0x83, 0x39, 0x48, 0x93, 0x9b, 0x7a,
    0x22, 0x07, 0x77, 0xe4, 0x63, 0xb7, 0xa0, 0x72, 0x73, 0x4e, 0x6f, 0x09, 0x42, 0x5a, 0x8b, 0x6a,
    0x81, 0x33, 0x67, 0xfd, 0xbd, 0x4b, 0xe1, 0x62, 0x1a, 0xb8, 0x5f, 0x7e, 0xeb, 0x26, 0x79, 0x98,
    0x85, 0x70, 0x65, 0x10, 0x96, 0x1b, 0xf3, 0xb0, 0xee, 0xae, 0x7d, 0x6e, 0x19, 0xba, 0xa9, 0xc8,
    0x12, 0x05, 0x3c, 0x91, 0x9d, 0xa7, 0xe3, 0xe0, 0x03, 0x44, 0xad, 0x45, 0xb2, 0x94, 0x38, 0xf8,
    0xd1, 0x84, 0x8c, 0x61, 0x9a, 0x1e, 0xd3, 0xc1, 0x0a, 0xcb, 0x34, 0x95, 0xde, 0x9f, 0x7c, 0x69,
    0x76, 0x17, 0x6b, 0x20, 0x71, 0x50, 0x30, 0x66, 0x7b, 0xbe, 0xd8, 0xe5, 0x2e, 0xca, 0x4c, 0xb9,
    0x02, 0xc3, 0xc0, 0x01, 0xed, 0x5b, 0x57, 0xd6, 0xe9, 0xcf, 0xa8, 0x52, 0x97, 0x16, 0xb5, 0x8e,
    0x43, 0x54, 0x90, 0xdd, 0xaf, 0xd2, 0x8d, 0xb1, 0xbf, 0xbb, 0xff, 0xcc, 0xf2, 0x8f, 0xec, 0x2d,
    0xe6, 0xf6, 0xf7, 0xfa, 0x41, 0x31, 0xd4, 0x15, 0xc9, 0xce, 0xef, 0xfc, 0xc2, 0xda, 0xbc, 0xea,
    0xb6, 0xb3, 0xe7, 0x68, 0xaa, 0x0e, 0xa4, 0xe2, 0x9e, 0xac, 0xdf, 0x59, 0xf5, 0x89, 0x18, 0xf9,
    0x86, 0x27, 0x6c, 0xcd, 0xd9, 0x51, 0x74, 0xa1, 0xdc, 0xab, 0x14, 0x29, 0x80, 0x7f, 0x75, 0x49,
    0x24, 0x53, 0xd0, 0xf4, 0x4a, 0xf0, 0x4d, 0xf1, 0x3e, 0xfb, 0xfe, 0xc5, 0x87, 0xe8, 0xa2, 0x99
]

INV_SBOX = [0] * 256

data = bytes([ 0x84, 0x52, 0x5f, 0x9c, 0xf0, 0xa8, 0x5a, 0x21 ])


for i, val in enumerate(SBOX):
    INV_SBOX[val] = i

def rot_left(byte_val, amount):
    byte_val &= 0xFF
    amount = amount % 8
    return ((byte_val << amount) | (byte_val >> (8 - amount))) & 0xFF

def rot_right(byte_val, amount):
    byte_val &= 0xFF
    amount = amount % 8
    return ((byte_val >> amount) | (byte_val << (8 - amount))) & 0xFF

def undo_final(encrypted_block, bufferozzo, integer_buffer):
    hash_copy = list(encrypted_block)
    
    for j in range(3, -1, -1):  # j = 3, 2, 1, 0
        int_element = integer_buffer[j]
        
        for k in range(8):
            hash_copy[k] = rot_right(hash_copy[k], (j + 1) % 8)
            hash_copy[k] ^= (int_element >> ((k % 4) * 8)) & 0xFF
        
        temp = [0] * 8
        for ii in range(8):
            original_pos = (ii * 3 + j) % 8
            temp[ii] = hash_copy[original_pos]
        hash_copy = temp
        
        for jj in range(8):
            chiave = (int_element + jj + j) & 0xFF
            hash_copy[jj] = INV_SBOX[hash_copy[jj]]
            hash_copy[jj] ^= chiave
    
    for i in range(8):
        hash_copy[i] ^= bufferozzo[i % len(bufferozzo)]
    
    return bytes(hash_copy)




def final_test(hash_block, bufferozzo, integer_buffer):
    hash_copy = list(hash_block)
    for i in range(8):
        hash_copy[i] ^= bufferozzo[i % len(bufferozzo)]
    for j in range(4):
        int_element = integer_buffer[j]
        for jj in range(8):
            chiave = (int_element + jj + j) & 0xFF
            hash_copy[jj] = SBOX[hash_copy[jj] ^ chiave]
        temp = [0] * 8
        for ii in range(8):
            temp[(ii * 3 + j) % 8] = hash_copy[ii]
        hash_copy = temp
        for k in range(8):
            hash_copy[k] ^= (int_element >> ((k % 4) * 8)) & 0xFF
            hash_copy[k] = rot_left(hash_copy[k], (j + 1) % 8)
    return bytes(hash_copy)



if __name__ == "__main__":
    flag_cipher = [ 0x93, 0x25, 0x4b, 0x0d, 0x8f, 0x3b, 0x61, 0x44, 0x41, 0x51, 0x54, 0x8b, 0xc4, 0x39, 0x88, 0x41, 0x53, 0xe1, 0xa5, 0xc8, 0x35, 0xd2, 0x3b, 0x55, 0x1c, 0xca, 0x38, 0x53, 0x6d, 0x9c, 0xb2, 0x77, 0xd6, 0x2d, 0xad, 0x89, 0xea, 0xba, 0xbe, 0x35, 0x5e, 0x00, 0x3d, 0xca, 0xfa, 0x54, 0x87, 0x6e, 0xa6, 0x95, 0xac, 0xef, 0xeb, 0x13, 0xe5, 0x94, 0x04, 0xaa, 0x93, 0xbc, 0x3c, 0x99, 0x7e, 0xdd, 0xc0, 0x3e, 0x38, 0xea, 0x82, 0xf1, 0x1b, 0x06 ]

    bufferozzo =  b'\xb4\x05\x99\xa2\xf1Q%\xea\xb4\x05\x99\xa2\xf1Q%\xea'
    integer_buffer =  [119599210, 3228966940, 2162966584, 2412172536]

    for i in range(0, len(flag_cipher), 8):
        enc_block = bytes(flag_cipher[i:i+8])
        decrypted_block = undo_final(enc_block, bufferozzo, integer_buffer)

        plain = xor(decrypted_block, data)
        data = enc_block
        print(plain.decode('utf-8', errors='ignore'), end='')

```

Note: the values contained in the buffer were found using partial static analysis and a debugger on macOS




## Reverse Engineering - burnt-out

> Flag: `DCTF{n0w_y0Ur3_7h1nk1n6_w17h_d4t4}`


The challenge accepts a JSON input which describes actions to be executed by the binary. The goal is to craft a JSON that triggers the code path that prints the flag.

The challenge provides the following example input:

```json
{
  "on_start": [
    {
      "$type": "log_action_t",
      "message": "Hello World!"
    }
  ]
}
```

The `log_action_t` string is associated with a function that prints the `message` field, so running the binary with the example prints Hello World!.


The binary does not map `$type` strings to functions directly by name. Instead, it computes a simple hash of the string and compares the result against saved hash values. The hash function (reimplemented in Python) is:


```python
# hash function implemented in python
def calculate_hash(string):
    hash_value = 0
    for position, char in enumerate(string, 1):
        hash_value += ord(char) * position
    return hash_value

```
This hashing function is not secure: collisions are easy to find, also by hand.


When a function is called using this mechanism, the first parameter is always a pointer to a struct (I refer to it as player_t). After investigating I found out that the first two integer of this struct are the position coordinates of the player and the byte located at offset 9 of this struct control whether or not the flag must be printed. If that value is not zero, then the flag is printed.


So i started searching for a function that writes at that specific offset, and found this:

```c

undefined8 maybe_win(player_t *player,uint *mappa,int *move_direction)

{
  uint uVar1;
  undefined8 uVar2;
  uint next_x;
  uint next_y;
  uint x_coord;
  uint y_coord;
  
  uVar1 = *move_direction - 1;
  if (3 < uVar1) {
    __printf_chk(1,"Assertion failed: ");
    __printf_chk(1,"dir cannot be none");
    __printf_chk(1,&DAT_0010a9f7);
    __printf_chk(1,&DAT_0010a9f7);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  x_coord = player->x_coord;
  y_coord = player->y_coord;
  next_y = y_coord;
  next_x = x_coord;
  switch(*move_direction) {
  case 1:
    next_y = y_coord - 1;
    break;
  case 2:
    next_y = y_coord + 1;
    break;
  case 3:
    next_x = x_coord - 1;
    break;
  case 4:
    next_x = x_coord + 1;
  }
  uVar2 = CONCAT71((int7)((ulong)((long)&switchD_00101804::switchdataD_0010a84c +
                                 (long)(int)(&switchD_00101804::switchdataD_0010a84c)[uVar1]) >> 8),
                   1);
  if ((next_y < 0x1e) && (next_x < 0x1e)) {
    if (mappa[(ulong)next_x * 0x1e + (ulong)next_y + 2] == 0) {
      if (mappa[(ulong)next_x * 0x1e + (ulong)next_y + 0x386] != 0) {
        return 0;
      }
      mappa[(long)(int)x_coord * 0x1e + (long)(int)y_coord + 2] = 1;
      player->x_coord = next_x;
      player->y_coord = next_y;
      if ((next_x == mappa[0x70a]) && (next_y == mappa[0x70b])) {
        player->flag_ = 1;
        return uVar2;
      }
    }
  }
  return uVar2;
}
```
This funciton allows the player to move in a direction specified by the `move_direction` parameter.

As you can see at the very end of this function `player->flag_` is set to 1 only if the next position of the player is the correct one. Via debugger I found out that the desired position is only one step away, but its coordinates are randomized.




To trigger the win path we need two things:

- Call this function — this requires providing a `$type` string whose hash matches that function’s saved hash (0x527e).

- Ensure `move_direction` is valid; otherwise the function asserts ("dir cannot be none").


The `move_direction` parameter is resolved from a `dir` string in the input using the same weak hashing scheme as `$type`. Therefore we can craft both a `$type` and a `dir` string that map to the required hashes.



```json
{
  "on_start": [
    {
      "$type": "mzzzzzzzzzzzzzzzzae",
      "dir": "fvmmmmaA"
    }
  ]
}
```

With this JSON the binary executes the target function, moves the player and sets `player->flag_ = 1` 25% of the times.

Bonus: There was also a format-string vulnerability in the code that could be triggered simply by:
```json
{
  "on_start": [
    {
      "$type": "log_action_t",
      "message": "%d"
    }
  ]
}
```