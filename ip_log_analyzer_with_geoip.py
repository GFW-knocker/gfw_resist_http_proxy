import os
from datetime import datetime
import pandas as pd     # -> pip install pandas
import geoip2.database   # -> pip install geoip2
import csv
import logging
from scipy.spatial import cKDTree as KDTree



output_file_name = 'ip_summary.csv'
ip_log_folder_name = 'IP_Log'
geoip_folder_name = 'geolite2'


BASE_DIR = os.path.dirname(os.path.realpath(__file__))
ip_log_folder_path = os.path.join(BASE_DIR,ip_log_folder_name)
geoip_folder = os.path.join(BASE_DIR,geoip_folder_name)

date_max = datetime.strptime('3000-01-01 00:00:00', "%Y-%m-%d %H:%M:%S" )
date_min = datetime.strptime('1900-01-01 00:00:00', "%Y-%m-%d %H:%M:%S" )

#df = pd.DataFrame(columns=['ip','xray','nginx','ngpr','total','probe_percent','first_seen','last_seen','nginx_req','ngpr_req'])
Dict_list = []


def read_ip_log(file_name):
    print('opening '+file_name)
    with open(file_name, "r") as f:
        count = 0
        while True:
            count += 1
            line = f.readline().replace('\n','').replace('\r','')
            if line:
                X = parse_line(line)
                add_line_to_dataframe(X)                
            else:
                break
        
    print('-> total line read : '+str(count))

    return True




def parse_line(mystr):
    x = mystr.split('\t, ')
    if( len(x)==4):
        return {'ip':x[0] , 'access':x[1] , 'time':x[2] , 'req':x[3][:11]}
    elif( len(x)==3):
        return {'ip':x[0] , 'access':x[1] , 'time':x[2] , 'req':''}
    else:
        raise Exception('line parse err. invalid log file?')




def add_line_to_dataframe(X):
    id_bool = [ (s['ip']==X['ip']) for s in Dict_list]
    n = sum(id_bool)
    if ( n==1 ):
        D = convert_line_to_dict(X , Dict_list[ id_bool.index(True) ] )
    elif( n==0 ):    
        D = convert_line_to_dict(X , None)
        Dict_list.append(D)
    else:
        raise Exception('err in algorithm!')

    



def convert_line_to_dict(X , old_dict=None):
    
    if(old_dict == None):
        D = {'ip':X['ip'],'xray':0,'nginx':0,'ngpr':0,'total':0,'probe_percent':0,'first_seen':date_max,'last_seen':date_min,'nginx_req':'','ngpr_req':''}
    else :
        D = old_dict

    if( X['access'] == 'XRAY'):
        D['xray'] = D['xray'] + 1
    elif( X['access'] == 'NGINX' ):
        D['nginx'] = D['nginx'] + 1 
        D['nginx_req'] = X['req']       
    elif( X['access'] == 'NG-PR' ):
        D['ngpr'] = D['ngpr'] + 1    
        D['ngpr_req'] = X['req']  
    else:
        raise Exception('err in line')

    D['total'] = D['xray']+D['nginx']+D['ngpr']

    D['probe_percent'] = (D['nginx']+D['ngpr'])/(D['total']+1e-8)    

    this_time = datetime.strptime(X['time'], "%Y-%m-%d %H:%M:%S" )
    if( this_time < D['first_seen'] ):
        D['first_seen'] = this_time

    if( this_time > D['last_seen'] ):
        D['last_seen'] = this_time
    
    return D









def relative_path(filename):
    return os.path.join(geoip_folder, filename)




class GeocodeData:

    def __init__(self, geocode_filename='geocode.csv', country_filename='countries.csv'):
        coordinates, self.__locations = self.__extract(relative_path(geocode_filename))
        self.__tree = KDTree(coordinates)
        self.__load_countries(relative_path(country_filename))

    def __load_countries(self, country_filename):
        """Load a map of country code to name
        """
        self.__countries = {}
        with open(country_filename, 'r') as handler:
            for code, name in csv.reader(handler):
                self.__countries[code] = name

    def query(self, coordinates):
        """Find closest match to this list of coordinates
        """
        try:
            distances, indices = self.__tree.query(coordinates, k=1)
        except ValueError as e:
            logging.info('Unable to parse coordinates: {}'.format(coordinates))
            raise e
        else:
            results = [self.__locations[index] for index in indices]
            for result in results:
                result['country'] = self.__countries.get(result['country_code'], '')
            return results



    def __extract(self, local_filename):

        if os.path.exists(local_filename):
            rows = csv.reader(open(local_filename,'r',encoding='utf8'))
        else:
            raise Exception('unable to find data -> geocode.csv')

        # load a list of known coordinates and corresponding __locations
        coordinates, __locations = [], []
        for latitude, longitude, country_code, city in rows:
            coordinates.append((latitude, longitude))
            __locations.append(dict(country_code=country_code, city=city))
        return coordinates, __locations





def query_geodata(ip_str_list):

    #myip = '164.215.193.18'
    
    result = []
    reader1 = geoip2.database.Reader(relative_path("GeoLite2-City.mmdb"))
    reader2 = geoip2.database.Reader(relative_path('GeoLite2-ASN.mmdb'))
    geo_reverse = GeocodeData()

    if(type(ip_str_list) == str):
        ip_str_list = [ip_str_list]
    
    for myip in ip_str_list:
        ip_info_dict = {'IP':'','country':'','city':'','ISP':'','Accurate':'Yes','iso':'','Latitude':'','Longitude':''}
        
        try:
            response1 = reader1.city(myip)
            
            ip_info_dict['IP'] = myip
            ip_info_dict['iso'] = response1.country.iso_code
            ip_info_dict['country'] = response1.country.name
            ip_info_dict['city'] = response1.city.name
            ip_info_dict['Latitude'] = response1.location.latitude
            ip_info_dict['Longitude'] = response1.location.longitude

            response2 = reader2.asn(myip)
            ip_info_dict['ISP'] = response2.autonomous_system_organization

            if(ip_info_dict['city']==None):
                #print('city not known , maybe inaccurate')
                ip_info_dict['Accurate'] = 'NO'
                coordinates = [(ip_info_dict['Latitude'],ip_info_dict['Longitude'])]
                new_info = geo_reverse.query(coordinates)[0]
                ip_info_dict['city'] = new_info['city']
        except Exception as e:
            #print('address not found in database')
            ip_info_dict['IP'] = myip

        result.append(ip_info_dict)

    return result
    #print(response.country.iso_code)
    #print(response.country.name)
    #print(response.subdivisions.most_specific.name)
    #print(response.subdivisions.most_specific.iso_code)
    #print(response.city.name)
    #print(response.postal.code)
    #print(response.location.latitude)
    #print(response.location.longitude)
    #print(response.traits.network)
    #print('---------------------------')
    #print(response2.autonomous_system_number)
    #print(response2.autonomous_system_organization)
    #print(response2.ip_address)
    #print(response2.network)



if __name__ == "__main__":

    file_list = [f for f in os.listdir(ip_log_folder_path) if os.path.isfile(os.path.join(ip_log_folder_path, f))]

    for f in file_list :
        # open only txt file or log file generated by pyprox
        if( f[-4:]=='.txt') or (f[-3]=='_'):
            myfile = os.path.join(ip_log_folder_path,f)        
            read_ip_log(myfile)
    
    ip_list = [x['ip'] for x in Dict_list]
    
    city_list = query_geodata(ip_list)

    for i,x in enumerate(Dict_list):
        x.update(city_list[i])
            
    df = pd.DataFrame(Dict_list)
    new_df = df.sort_values('probe_percent',ascending=False)
    new_df.to_csv(os.path.join(BASE_DIR,output_file_name))

    print('summary writed to '+ os.path.join(BASE_DIR,output_file_name) )

