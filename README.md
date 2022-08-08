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
ex) ./send-arp wlan0 172.20.10.3 172.20.10.1
```
---
### Check Infect another Computer
_*VM에 있던 MAC이 HOST PC를 통해 나가기 때문에 Sender PC의 게이트웨이 맥주소가 VM이 아닌 HOST의 MAC주소와 같아진다.*_

![image](https://user-images.githubusercontent.com/79035672/183304121-0e09a533-50e0-4d51-a991-c362b4b18dcd.png)

---
## Result
![image](https://user-images.githubusercontent.com/79035672/183365465-4bf8f2be-1cbc-4148-b59a-7cb6f94d2faf.png)

---
| BoB11 Hyeon Seak hun

| Reference : gilgil

