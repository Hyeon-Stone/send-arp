# HW3 | send-arp

| Sender : Victim IP (Not Always)<br>
| Target : Gateway IP<br>
1. 나의 MAC 주소 가져오기<br>
2. Sender IP에 ARP Request을 보내 MAC 주소 GET<br>
3. Sender에게 ARP Reply를 통해 Sender의 ARP-Table 조작

---
## Execute
```
comandline : ./send-arp <interface> <sender ip> <target ip>
ex) ./send-arp wlan0 172.20.10.3 172,20,10,1
```
---
### Check Infect another Computer
![image](https://user-images.githubusercontent.com/79035672/183304121-0e09a533-50e0-4d51-a991-c362b4b18dcd.png)

---
## Result
![image](https://user-images.githubusercontent.com/79035672/183304512-179ab12f-9de9-4a62-8588-14d6bf56b43e.png)

---
| BoB11 Hyeon Seak hun

| Reference : gilgil

