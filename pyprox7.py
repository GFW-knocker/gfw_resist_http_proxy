#!/usr/bin/env python3

import socket
import threading
from pathlib import Path
import os
import datetime
import logging
from logging.handlers import TimedRotatingFileHandler
import resource

# set linux max_num_open_socket from 1024 to 128k
resource.setrlimit(resource.RLIMIT_NOFILE, (127000, 128000))



my_PORT = 80
PORT_XRAY = 47817
PORT_NGINX = 8080
url_path = b'GET /pub/firefox/releases/latest/win64/en-US/Firefox-Setup.exe/'

XRAY_400_response = b'HTTP/1.1 40'  # catch any 400~499 response

my_socket_timeout = 10 # default for google is ~21 sec



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
        self.sock.listen(32)  # up to 32 concurrent unaccepted socket queued , the more is refused upon accepting those.
        while True:
            src_sock , src_addr = self.sock.accept()                    
            
            #print('someone connected') 
            src_sock.settimeout(my_socket_timeout)            
            threading.Thread(target = self.my_upstream , args =(src_sock,src_addr) ).start()
            

    def my_upstream(self, my_src , src_addr):
        first_flag = True
        my_dest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        my_dest.settimeout(my_socket_timeout)
        while True:
            try:
                data = my_src.recv(16384)
                #print('user talk :')
                #print(data)
                #print('\n\n\n')
                if data:
                    if( first_flag == True ):                        
                        first_flag = False
                        my_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")                        
                        if( data[:url_length]==url_path):
                            #self.write_ip_access_log([src_addr[0],'XRAY',my_time,data[60:200].decode("utf-8").replace('\n',' ').replace('\r','')])
                            self.write_ip_access_log([src_addr[0],'XRAY',my_time])                            
                            my_dest.connect(('127.0.0.1',PORT_XRAY))
                            threading.Thread(target = self.my_downstream , args = (my_dest , my_src , 'xray' , src_addr[0] , my_time , data) ).start()
                        else:                                                    
                            self.write_ip_access_log([src_addr[0],'NGINX',my_time,str(data[:1500])])                            
                            my_dest.connect(('127.0.0.1',PORT_NGINX))
                            threading.Thread(target = self.my_downstream , args = (my_dest , my_src , 'nginx' , '' , '' , '' ) ).start()
                       
                    my_dest.sendall(data)
                else:                    
                    raise Exception('UL closed')
            except Exception as e:
                #print(repr(e))
                my_src.close()
                my_dest.close()
                return False



            
    def my_downstream(self, my_dest , my_src , backend_name , cli_ip , req_time , cli_request ):
        first_flag = True
        while True:
            try:
                data = my_dest.recv(16384)
                #print(backend_name+' talk :')
                #print(data)
                #print('\n\n\n')
                if data:
                    if( first_flag == True ):
                        first_flag = False
                        if( backend_name =='xray' ):
                            if( data[:XRAY_resp_length]==XRAY_400_response):
                                #print('im calling nginx for fake page in case of packet-replay to xray!')
                                self.write_ip_access_log([cli_ip,'NG-PR',req_time,str(cli_request[:1500])])
                                temp_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                                temp_sock.settimeout(my_socket_timeout)
                                temp_sock.connect(('127.0.0.1',PORT_NGINX))
                                temp_sock.sendall(b'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n\r\n')
                                data = temp_sock.recv(16384)
                                #print(data)
                                temp_sock.close()
                    my_src.sendall(data)
                else:                    
                    raise Exception('DL closed')
            except Exception as e:
                #print(repr(e))              
                my_dest.close()
                my_src.close()
                return False



    def write_ip_access_log(self,custom_data):
        logger.info("\t, ".join(custom_data))        
        return True            

print ("Now serving at: "+str(my_PORT))
ThreadedServer('',my_PORT).listen()


    
