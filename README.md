# update 1401-11-12:
- add important defense on packet-replay (when GFW request contain valid path but have no UUID , we redirect it to nginx)
- make code cleaner and readable
- add ip log analyzer

# TO DO next:
- thread pool (make app stable , use less ram on server with 1000+ users)
- upload "nginx proxy-pass" help + Django backend to be used with pyprox

# IP Log Analyzer:
- just run the script to analyze all ip log files in IP_Log folder and summary them into a tiny excel sheet
- it list all unique IPs connecting to your server , counting num request to xray/nginx , first seen time , last seen time , percent of malicious probe
- output IP list sorted by percent of malicious probe , which we assume that they are GFW prober
- if some of us publish prober list and aggregate data with each others , we can identify prober IPs with 100% confidence
- so we able to block these IP in firewall (sudo ufw deny from $IP to any)
- obtain ip info from https://www.showmyip.com/ip-whois-lookup/

![Alt text](/instruction/ip_analyze.png?raw=true "ip_analyze")

# gfw_resist_http_proxy
knock up gfw active-probe by redirecting it to nginx



- nginx reverse proxy is not compatible with xray packet , it drop payload of http header (because xray http header is not standard)
- we build a custom http proxy to manually route traffic to each nginx/xray backend
- we log all ip+time+req_header so we clearly observing active-probe IPs !
- it prolong blocking duration but we need more investigation ( we guess some blocking is from pure passive traffic analysis )


# how it work:

- all http request examined , if it xray-valid redirect it to xray(n3) else redirect it to nginx(n2)
- so gfw prober alwayse see nginx and cannot talk to xray directly 
- if all other things ok (dynamic-page website, serve on port 80, other ports closed,...) the prober classifiy you as a legitimate web-server


# the system consist of a these module:

1-custom http proxy to identify xray/v2ray request (port n1=80)

2-nginx and backend web server that mimic a real website (local port n2)

3-xray/v2ray that serve tcp+http protocol on local port  (local port n3)

4- ufw block all ports except port 80 which is open for everyone

# Suggestion:
 - is not guarantee to prevent blocking but it prolong (we still working on!)
 - some blocking is by passive analysis so limit your traffic below 10MB/s or even lower
 - pyprox is a platform to hide xray behind
 - its customizable , you can use it for any path or any other protocol like websocket. 
 - you just need to watch network packet in wireshark and design your own routing decision.
 - you can analysis ip log and block gfw prober ip in ufw (soon we publish this module)

# help
![Alt text](/instruction/pyprox.png?raw=true "pyprox")
![Alt text](/instruction/config0.png?raw=true "config0")
![Alt text](/instruction/config1.png?raw=true "config1")
![Alt text](/instruction/config2.png?raw=true "config2")
![Alt text](/instruction/traffic.png?raw=true "traffic")

# typical config:

vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogInB5cHJveCIsDQogICJhZGQiOiAiMjE2LjIzOS4zOC4xMjAiLA0KICAicG9ydCI6ICI0NzgxNyIsDQogICJpZCI6ICIzNDM4NTJjYy1hZDRjLTRiYzMtOTY3Zi1hNDY1YTc3NzYyMzUiLA0KICAiYWlkIjogIjAiLA0KICAic2N5IjogImF1dG8iLA0KICAibmV0IjogInRjcCIsDQogICJ0eXBlIjogImh0dHAiLA0KICAiaG9zdCI6ICJmdHAubW96aWxsYS5vcmciLA0KICAicGF0aCI6ICIvcHViL2ZpcmVmb3gvcmVsZWFzZXMvbGF0ZXN0L3dpbjY0L2VuLVVTL0ZpcmVmb3gtU2V0dXAuZXhlLyIsDQogICJ0bHMiOiAiIiwNCiAgInNuaSI6ICIiLA0KICAiYWxwbiI6ICJodHRwLzEuMSINCn0=


you can set to any url path you want but dont forget to also set path in pyprox and nginx

- path :

  /pub/firefox/releases/latest/win64/en-US/Firefox-Setup.exe/

- Request header :
  
  Host : ftp.mozilla.org

  Location : /pub/firefox/releases/latest/win64/en-US/Firefox-Setup.exe/

  Referer : http://ftp.mozilla.org/pub/firefox/releases/latest/win64/en-US/

  Accept-Language : en-US,en;q=0.9

  Content-Type : application/octet-stream


- Response header :
  
  Content-Type : application/octet-stream

  Server : nginx

  Via : 1.1 google, 1.1 google

  Cache-Control : max-age=15552000



# run python script:
- set the premission

  add   [#!/usr/bin/env python3]     to first line of pyprox.py

  chmod +x pyprox.py

- to run in forground

  python pyprox.py

- to run in background:

  nohup python pyprox.py &

- to stop script:

  pkill -f pyprox.py



