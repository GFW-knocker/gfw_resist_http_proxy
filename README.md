# gfw_resist_http_proxy
knock up gfw active-probe by redirecting it to nginx



-nginx reverse proxy is not compatible with xray packet , it drop payload of http header (because xray http header is not standard)

-we build a custom http proxy to manually route traffic to each nginx/xray backend

-we log all ip+time+req_header so we clearly observing active-probe IPs !

-it prolong blocking duration but we need more investigation ( we guess some blocking is from pure passive traffic analysis )


# how it work:

-all http request examined , if it xray-valid redirect it to xray(n3) else redirect it to nginx(n2)

-so gfw prober alwayse see nginx and cannot talk to xray directly 

-if all other things ok (dynamic-page website, serve on port 80, other ports closed,...) the prober classifiy you as a legitimate web-server


# the system consist of a these module:

1-custom http proxy to identify xray/v2ray request (port n1=80)

2-nginx and backend web server that mimic a real website (local port n2)

3-xray/v2ray that serve tcp+http protocol on local port  (local port n3)

4- ufw block all ports except port 80 which is open for everyone






