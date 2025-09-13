Overview

This lab focused on working with Suricata (IDS/IPS) and Zeek (network analysis framework) within Kali Purple.
I practised reading logs, creating custom rules, and understanding the difference between high-level alerts and detailed metadata.

Commands Used
View last 20 Suricata alerts
sudo tail -n 20 /var/log/suricata/fast.log

Follow Suricata logs in real-time
sudo tail -f /var/log/suricata/fast.log

Stop Suricata process
sudo pkill suricata

Key Learnings

Suricata is primarily used as an Intrusion Detection System (IDS).

It raises high-level alerts such as:

Nmap scan detected

CUSTOM: ChatCura IP contacted

Zeek provides detailed metadata logs, making it complementary to Suricata.

Example logs:

conn.log → connection details

http.log → HTTP headers

dns.log → DNS lookups

weird.log → unusual activity

Custom Suricata rules tested in this lab:

# Alert on TLS SNI
alert tls any any -> any any (msg:"CUSTOM: TLS SNI chatcura.com"; tls.sni; content:"chatcura.com"; nocase; sid:1000001; rev:1;)
alert tls any any -> any any (msg:"CUSTOM: TLS SNI www.chatcura.com"; tls.sni; content:"www.chatcura.com"; nocase; sid:1000002; rev:1;)

# Alert on DNS query
alert dns any any -> any any (msg:"CUSTOM: DNS query for chatcura.com"; dns.query; content:"chatcura.com"; nocase; sid:1000003; rev:1;)

# Alert on direct IP contact
alert ip any any -> 76.76.21.21 any (msg:"CUSTOM: ChatCura IP contacted"; sid:1000004; rev:1;)

Why Documentation Matters

Career portfolio → proof of hands-on work for recruiters & hiring managers.

Learning aid → lets me revisit concepts later to refresh my memory.

Professional practice → in SOCs/pentest jobs, documentation is essential for compliance, reporting, and evidence.

Reflection

This lab helped me understand:

The practical use of Suricata alerts versus Zeek metadata.

How to write and test custom Suricata rules.

The importance of clearing/rotating logs in training versus preserving them in real-world environments.
