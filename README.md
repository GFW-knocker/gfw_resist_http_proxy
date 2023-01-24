# gfw_resist_http_router
knock up gfw active-probe by redirecting to nginx


# the system consist of a these module:

1-custom http proxy to identify xray/v2ray request (port n1=80)

2-nginx and backend web server that mimic a real website (local port n2)

3-xray/v2ray that serve tcp+http protocol on local port  (local port n3)

4- ufw block all ports except port 80 which is open for everyone


# how it work:

-all http request examined , if it xray-valid redirect it to xray(n3) else redirect it to nginx(n2)

-so gfw prober alwayse see nginx and cannot talk to xray directly 

-if all other things ok (dynamic-page website, serve on port 80, other ports closed,...) the prober classifiy you as a legitimate web-server





