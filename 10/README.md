
## 10 -Install and set up SIEM Wazuh syslog and agents
https://youtu.be/80q0pnLjnG4

Guidline to install wazuh : 
https://www.alldiscoveries.com/install-wazuh-open-source-xdr-siem-on-ubuntu-22-04/

ubuntu : 
https://ubuntu.com/download/alternative-downloads


commands : 

WAZUH Server :
```
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```
windows agent : 
```
.\agent-auth.exe -m <WAZUH IP>
NET START Wazuh
```
ossec.conf :
```
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>10.22.7.0/24</allowed-ips>
    <local_ip>10.22.7.110</local_ip>
  </remote>
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>
```

change admin password : 
https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html


Remove wazuh agent from windows : 
```
Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "Wazuh" }
msiexec.exe /x "IdentifyingNumber" /qn

```
