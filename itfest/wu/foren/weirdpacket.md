# weird packet

Hmm, this looks weird! This PCAP file contains data from a strange device. Each packet is hiding something. Take a look, troubleshoot, and find out.

## Solusi

dikasi file .pcap

setelah dibuka isinya usb protocol semua paketnya

ok, usb parsing ini mah..

pake script dari github

```
python3 Usb_Keyboard_Parser.py chall.pcap
[-] Found Modifier in 2492 packets [-]

[+] Using filter "usb.capdata" Retrived HID Data is :

:e part1.txt
iX<esc>rI<esc>aX<esc>rT<esc>aX<esc>rF<esc>aX<esc>rE<esc>aX<esc>rS<esc>aX<esc>rT<esc>aX<esc>r2<esc>aX<esc>r5<esc>aX<esc>r{<esc>aX<esc>rk<esc>aX<esc>re<esc>aX<esc>ry<esc>aX<esc>rb<esc>aX<esc>ro<esc>aX<esc>ra<esc>aX<esc>rr<esc>aX<esc>rd<esc>aX<esc>r_<esc>aX<esc>rn<esc>aX<esc>rg<esc>aX<esc>ra<esc>aX<esc>rs<esc>aX<esc>ri<esc>aX<esc>rh<esc>aX<esc>r_<esc>aX<esc>rc<esc>aX<esc>rl<esc>aX<esc>ru<esc>aX<esc>re<esc>aX<esc>r_<esc>aX<esc>rk<esc>aX<esc>re<esc>aX<esc>rh<esc>aX<esc>ri<esc>aX<esc>rd<esc>aX<esc>ru<esc>aX<esc>rp<esc>aX<esc>ra<esc>aX<esc>rn<esc>aX<esc>r_<esc>0:s/X//g<enter>
```

setelah di clear dapet ini

```
part1.txt

ITFEST25{keyboard_ngasih_clue_kehidupan_

```

![alt text](<WhatsApp Image 2025-07-24 at 14.24.56_0760169b.jpg>)

ok itu part 2 nya

## Flag
    ITFEST25{keyboard_ngasih_clue_kehidupan_mouse_ngasih_click_keputusan}