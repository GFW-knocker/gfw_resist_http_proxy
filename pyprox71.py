#!/usr/bin/env python3

import socket
import threading
from pathlib import Path
import os
import copy
import time
import datetime
import logging
from logging.handlers import TimedRotatingFileHandler


if os.name == 'posix':
    print('os is linux')
    import resource   # ( -> pip install python-resources )
    # set linux max_num_open_socket from 1024 to 128k
    resource.setrlimit(resource.RLIMIT_NOFILE, (127000, 128000))



my_PORT = 80
PORT_XRAY = 47817
PORT_NGINX = 8080
url_path = b'GET /pub/firefox/releases/latest/win64/en-US/Firefox-Setup.exe/'

XRAY_400_response = b'HTTP/1.1 40'  # catch any 400~499 response


XRAY_max_wait = 4 # wait maximum 4 sec to get response from xray otherwise switch to nginx
my_socket_timeout = 60 # default for google is ~21 sec , recommend 60 sec unless you have low ram and need close soon
first_time_sleep = 0.1 # speed control , avoid server crash if huge number of users flooding


url_length = len(url_path)
XRAY_resp_length = len(XRAY_400_response)
BASE_DIR = Path(__file__).resolve().parent
log_file_directory = os.path.join(BASE_DIR,'IP_Log')
log_file_path = os.path.join(log_file_directory,"my_ip_access_log.txt")


if not os.path.exists(log_file_directory):
    os.makedirs(log_file_directory)


logger = logging.getLogger('log')
logger.setLevel(logging.INFO)

#   save log backup every -> when ={'S','M','H','D','midnight','W0','W6'}
ch = TimedRotatingFileHandler( filename=log_file_path , when='H', interval=1, backupCount=90, delay=False)
ch.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(ch)


class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)  # up to 5 concurrent unaccepted socket queued , the more is refused untill accepting those.
        while True:
            client_sock , client_addr = self.sock.accept()                    
            client_sock.settimeout(my_socket_timeout)
            
            #print('someone connected')                 
            threading.Thread(target = self.my_upstream , args =(client_sock,client_addr) ).start()
            

    def my_upstream(self, client_sock , client_addr):
        first_flag = True
        backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_sock.settimeout(my_socket_timeout)
        while True:
            try:
                if( first_flag == True ):                        
                    first_flag = False

                    time.sleep(first_time_sleep)   # speed control + waiting for packet to fully recieve
                    data = client_sock.recv(16384)
                    #print('len data -> ',str(len(data)))                
                    #print('user talk :')
                
                    if data:                    
                        my_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                        
                        if( data[:url_length]==url_path):
                            #self.write_ip_access_log([client_addr[0],'XRAY',my_time,data[60:200].decode("utf-8").replace('\n',' ').replace('\r','')])
                            self.write_ip_access_log([client_addr[0],'XRAY',my_time])                            
                            backend_sock.connect(('127.0.0.1',PORT_XRAY))
                            threading.Thread(target = self.my_downstream , args = (backend_sock , client_sock , 'xray' , client_addr[0] , my_time , data) ).start()
                            backend_sock.sendall(data)
                        else:                                                    
                            self.write_ip_access_log([client_addr[0],'NGINX',my_time,str(data[:500])])                            
                            backend_sock.connect(('127.0.0.1',PORT_NGINX))
                            threading.Thread(target = self.my_downstream , args = (backend_sock , client_sock , 'nginx' , '' , '' , '' ) ).start()
                            backend_sock.sendall(data)                                               
                    else:                   
                        raise Exception('cli syn close')

                else:
                    data = client_sock.recv(4096)
                    if data:
                        backend_sock.sendall(data)
                    else:
                        raise Exception('cli pipe close')
                    
            except Exception as e:
                #print('upstream : '+ repr(e) )
                time.sleep(2) # wait two second for another thread to flush
                client_sock.close()
                backend_sock.close()
                return False



            
    def my_downstream(self, backend_sock , client_sock , backend_name , cli_ip , req_time , cli_request ):
        first_flag = True
        while True:
            try:
                if( first_flag == True ):
                    first_flag = False
                    if( backend_name =='xray' ):
                        try:                            
                            time.sleep(first_time_sleep)   # speed control + waiting for packet to fully recieve
                            backend_sock.settimeout(XRAY_max_wait)     # set timeout to 4 sec , if xray didnt response , we switch to nginx
                            data = backend_sock.recv(16384)
                            #backend_sock.settimeout(my_socket_timeout)  # set timeout to its original
                        except Exception as e:
                            # xray didnt recognize user UUID and become silent -> we quickly change backend to nginx -> prevent packet-replay attack of GFW prober
                            #print('xray 4 second timeout happend')
                            data = copy.copy(XRAY_400_response)                            
                    
                        if( data[:XRAY_resp_length]==XRAY_400_response):
                            # xray didnt recognize user and send 400X -> we quickly change backend to nginx -> prevent fingerprint attack of GFW prober                            
                            #print('change backend to nginx (possible attack on xray with packet-replay or fingerprinting!)')
                            self.write_ip_access_log([cli_ip,'NG-PR',req_time,str(cli_request[:1500])])
                            backend_name = 'nginx'
                            backend_sock.close()
                            backend_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                            backend_sock.settimeout(my_socket_timeout)
                            backend_sock.connect(('127.0.0.1',PORT_NGINX))
                            backend_sock.sendall(cli_request)
                            time.sleep(first_time_sleep)   # speed control + waiting for packet to fully recieve
                            data = backend_sock.recv(16384)
                    
                        if data:
                            client_sock.sendall(data)
                        else:
                            raise Exception('xray syn close')
                    
                    else:
                        data = backend_sock.recv(16384)
                        if data:
                            client_sock.sendall(data)
                        else:
                            raise Exception('nginx syn close')
                        
                else:
                    data = backend_sock.recv(4096)
                    if data:
                        client_sock.sendall(data)
                    else:
                        raise Exception('backend pipe close')
            
            except Exception as e:
                #print('downstream '+backend_name +' : '+ repr(e)) 
                time.sleep(2) # wait two second for another thread to flush
                backend_sock.close()
                client_sock.close()
                return False



    def write_ip_access_log(self,custom_data):
        logger.info("\t, ".join(custom_data))        
        return True            

print ("Now serving at: "+str(my_PORT))
ThreadedServer('',my_PORT).listen()



    
