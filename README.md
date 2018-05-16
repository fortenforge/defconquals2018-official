# DEF CON Quals 2018: official (194 pts, 15 solves)

* Server: 3aef2bbc.quals2018.oooverflow.io:31337
* Binary: [official](official)

## Writeup

TL;DR: a 1 byte overflow allows you to induce a small bias in the nonce used in the DSA signing algorithm. Use LLL to exploit this bias to find the private key.

Read my writeup [here](https://fortenf.org/e/ctfs/pwn/crypto/2018/05/07/defconquals2018-official.html).

## Files

* [official](official) - the binary
* [official.i64](official.i64) - IDA database
* [get_data.py](get_data.py) - pwntools script to collect data
* [solve.sage](solve.sage) - sage script to calculate private key
* [rs_pairs.txt](rs_pairs.txt) - collected data from one run
* [privkey](privkey) - private key file (needed if you want to run the binary yourself)
* [official_msb](official_msb) - patched binary with nonce reversal code nopped out
* [rs_pairs_msb.txt](rs_pairs_msb.txt) - collected data from the above binary

## The Flag

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
```
