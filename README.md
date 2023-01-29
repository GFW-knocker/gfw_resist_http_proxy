# update 1401-11-9:
- add important defense on packet-replay (when GFW request contain valid path but have no UUID , we redirect it to nginx)
- make code cleaner and readable

# TO DO next:
- python pandas analyser of ip log (used to extract GFW prober ip & usefull statistics about users ip)
- thread pool (make app stable , use less ram on server with 1000+ users)
- upload "nginx proxy-pass" help + Django backend to be used with pyprox



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
![Alt text](/instruction/config1.png?raw=true "config1")
![Alt text](/instruction/config2.png?raw=true "config2")
![Alt text](/instruction/traffic.png?raw=true "traffic")


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



