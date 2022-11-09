'''
file: virustotal.py
auth: rafer cooley, taylor mccampbell
desc: functions to interact with the virustotal api. stripped version specifically for vtotal -> stix framework
Imported from virdb repo on UWYO CEDAR gitlab
'''
import variables

import requests

def search_by_hash(api_key,file_hash):
    '''
    query the virustotal interface for a report of the file by using the provided hash(any hash type) 
    INPUT:
        - api_key(str): virustotal api key
        - file_hash(str): hash of file, can be md5, sha256
    RETURN:
        - if successful: 1, JSON report
        - if file not found: 0, "NOTFOUND"
        - if API request exception: -1, APIError
    '''
    try:
        res = requests.get(f"{variables.API_VTOTAL_BASE_URL_V3}/files/{file_hash}",headers={'x-apikey':api_key})
        # print(f">>>result code={res.status_code}")
        if res.status_code == 200:
            return 1, res.json()
        else:
            print(f">>>>not a good request\n{res.text}")
            if res.json()['error']['code']=='NotFoundError':
                print(">>>>>file not found in vtotal")
                #lgr("INFO",1,f"{file_hash} not found in virustotal")
                return 0, "NOTFOUND"
            elif res.json()['error']['code']=='QuotaExceededError':
                print(">>>>>Quota exceeded")
                return 0, "QUOTA EXCEEDED"
    except Exception as e:
        print(f'ERROR Virustotal API request exception: {str(e)} || file_hash={file_hash}')
        return -1, str(e)