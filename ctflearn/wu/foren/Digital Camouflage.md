# Digital Camouflage

We need to gain access to some routers. Let's try and see if we can find the password in the captured network data: https://mega.nz/#!XDBDRAQD!4jRcJvAhMkaVaZCOT3z3zkyHre2KHfmkbCN5lYpiEoY Hint 1: It looks like someone logged in with their password earlier. Where would log in data be located in a network capture?<br /> Hint 2: If you think you found the flag, but it doesn't work, consider that the data may be encrypted.

Credit: picoCTF 2017

## Solution

open file that given (`data.pcap`) using wireshark.
search filter =  `tcp`

![dig](/ctflearn/assets/dig.PNG)

then select one data then follow tcp stream

![dig2](/ctflearn/assets/dig2.PNG)

We can alter streams by changing the counter in bottom right corner. As I reached 3rd stream, I observed some credentials there.

![dig3](/ctflearn/assets/dig3.PNG)

`Credentials: userid=hardawayn&pswrd=UEFwZHNqUlRhZQ%3D%3D`

So, it is clear that password is Base64 encrypted and in web URLs, %3D is to be replaced by =.

```
$ echo "UEFwZHNqUlRhZQ==" | base64 -d
PApdsjRTae
```

## Flag
    CTFLearn{PApdsjRTae}
