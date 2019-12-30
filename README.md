# PCAP

1. 可在command option使用-r pcap_file，從pcap_file中讀取封包。

2. 對每個讀進來的封包，顯示其時間戳記(timestamp, 以年、月、日、時、分、秒為單PL)、來源的MAC位址與目的MAC位址。

3. 若封包是IP封包，還可以顯示來源IP位址與目的IP位址。

4. 若封包是TCP/UDP封包，還可以顯示TCP/UDP的port號碼(含顯示是TCP還是UDP)

5. 可統計每對(來源IP,目的IP)的封包數量(若不是IP封包則略過不計)，並顯示出來。

參考網站:http://qbsuranalang.blogspot.com/2016/11/libpcap-dump-ethernet-frame8.html
