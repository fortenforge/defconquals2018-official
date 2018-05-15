# DEF CON Quals 2018: `official` - 194 pts - 15 solves

Server: 3aef2bbc.quals2018.oooverflow.io:31337
Binary: [official](official)

## Writeup

TL;DR: a 1 byte overflow allows you to induce a small bias in the nonce used in the DSA signing algorithm. Use LLL to exploit this bias to find the private key.

### Files

* [official](official) - the binary
* [official.i64](official.i64) - IDA database
* [get_data.py](get_data.py) - pwntools script to collect data
* [solve.sage](solve.sage) - sage script to calculate private key
* [rs_pairs.txt](rs_pairs.txt) - collected data from one run

### Reversing

The binary is pretty simple; it lets you sign messages starting with `ls`, `du` or `stat` (but not `cat` or anything else) and execute signed messages starting with `ls`, `stat`, `du`, or `cat`. It uses the [GMP](https://gmplib.org/) library to handle the signing and verifying stages.

In order to generate `k`, the nonce, it reads 20 bytes from `/dev/urandom` and then (curiously), reverses these bytes right before signing the command.

It uses `fread` to read the command to sign into a buffer of size 256. It does this one byte at a time and stops reading when it encounters a newline or when it's read 256 bytes. It replaces the newline with a null terminator, but also appends a null terminator right after the last character read if it never encountered a newline.

```
__int64 __fastcall fread_stuff(__int64 a1, unsigned int a2)
{
  signed int i; // [rsp+18h] [rbp-8h]@1

  for ( i = 0; i < a2; ++i )
  {
    if ( (unsigned int)fread((void *)(i + a1), 1uLL, 1uLL, stdin) != 1 )
    {
      fwrite("fread fail\n", 1uLL, 0xBuLL, stderr);
      exit(1);
    }
    if ( *(_BYTE *)(i + a1) == 10 )
    {
      *(_BYTE *)(i + a1) = 0;
      return (unsigned int)i;
    }
  }
  *(_BYTE *)(i + a1) = 0;
  return (unsigned int)i;
}
```

This gives us our 1 byte overflow: if we send 256 bytes, none of which contain a newline, it will set the byte immediately after our buffer to null. As it turns out, this byte is the most-significant byte of `k`, our nonce. Of course, after the reversal, this will become the least-significant byte.

### The Exploit

We have a DSA signing oracle which we can induce to sign messages with a biased nonce. The bias is small (only 8 bits), but it's enough to cause a full break. The attack is described pretty well in [this stackexchange answer](https://crypto.stackexchange.com/questions/44644/how-does-the-biased-k-attack-on-ecdsa-work).

The attack uses the [LLL algorithm](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm) which is quite possibly the biggest cryptographic hammer out there. It can be used to break a dizzying array of cryptographic algorithms, and it shows up in CTFs [all the time](https://ctftime.org/writeups?tags=coppersmith&hidden-tags=LLL%2Ccoppersmith) these days.


### Flag

```
(env) [defconquals2018-official]> python get_data.py interact
[+] Opening connection to 3aef2bbc.quals2018.oooverflow.io on port 31337: Done
[*] POW Challenge: 7rVwoiN0yN 22
[*] POW Solution: 890897
[*] Switching to interactive mode

------------------- OFFICIAL MENU -------------------
(S) sign
(X) execute
(E) exit
> $ X
cmd:$ cat
r:$ 175672136897532857177216578242788547073729326124
s:$ 301997289336897032672653458915890188389476020087
OK
OOO{wh0_n33d5_l34k5_wh3n_y0u_c4n_f4ul7_1nj3c7?}
------------------- OFFICIAL MENU -------------------
(S) sign
(X) execute
(E) exit
> $ E
Offical bye bye.
[*] Got EOF while reading in interactive
$
$
[*] Closed connection to 3aef2bbc.quals2018.oooverflow.io port 31337
[*] Got EOF while sending in interactive
```
