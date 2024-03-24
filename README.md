# CTF-Writeups
1. [rfc-meta - Misc](#rfc-meta2)

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

Use RsaCtfTool to attack extract the private component:
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

## rfc-meta

### Flag proof

### Summary

### Details
