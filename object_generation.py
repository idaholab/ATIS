#file: object_generation.py
#auth: taylor mccampbell
#purpose: File contians functions to build specific stix objects 


from stix2.v21 import IPv4Address, Relationship, Indicator, DomainName, AttackPattern, Campaign, Malware
from utilities import sandBoxIDParser
import requests, variables

#Generate IPv4 Address Objects (SCO), an Indicator (SDO), and relationships for all IPv4 Addresses related to a file and returns a list of objects
#Input: sha256 and STIX object of file being translated
def generate_ipv4(file_id, main_malware_obj):
    url = f"https://virustotal.com/api/v3/files/{file_id}/relationships/contacted_ips"

    #Get list of IPs
    try: 
        response = requests.get(url, headers ={'x-apikey':variables.API_KEY}) #2
        response = response.json()
    except Exception as e: 
        print(str(e))

    #Declare list for indicator pattern
    ipList = [] 

    #Declare list for STIX Objects to return
    stixList = []

    #If there are IP Addresses associated with the file add them to the list
    if response['data']: 
        for address in response['data']:
            if address['type'] == 'ip_address':
                ipaddr = address['id']
                ipList.append(ipaddr)

                ipv4add = IPv4Address( 
                    value = ipaddr
                )
                
                stixList.append(ipv4add) #Add ipv4 address to the list

                #Create a relationship to the malware obj
                stixList.append(Relationship(
                    relationship_type="related-to",
                    source_ref=ipv4add.id,
                    target_ref=main_malware_obj.id
                ))

        #Create Indicator and add it to the list          
        iPattern = ""
        for ipaddr in ipList: 
            if not iPattern: 
                iPattern += f"[ ipv4-addr:value = '{ipaddr}'"
            else: 
                iPattern += f" OR ipv4-addr:value = '{ipaddr}'"
        iPattern += " ]"
        ip_indicator = Indicator(name="IPv4 Addresses", indicator_types=["anamolous-activity"], pattern=iPattern, pattern_type="stix")
        stixList.append(ip_indicator)

        #Create relationship for indicator 
        stixList.append(Relationship(
            relationship_type="indicates",
            source_ref=ip_indicator.id,
            target_ref=main_malware_obj.id
        ))

        #Return list of objects
        print("IPv4 Objects Successfully Added")
        return stixList
    else: 
        print("No IPv4 Addresses Associated with this file.")
        return 


#Generate domain objects (SCO) and relationships related to a file and returns a list of STIX objects
#Input: sha256 and STIX object of file being translated 
def generate_domains(file_id, main_malware_obj): 
    url = f"https://virustotal.com/api/v3/files/{file_id}/contacted_domains"

    #Declaring list to store STIX objects
    stixList = []

    try: 
        res = requests.get(url, headers={'x-apikey':variables.API_KEY})
        res = res.json()
    except Exception as e: 
        print(str(e))
    
    domains = [] #List to handle duplicates
    try:
        for idx in range(len(res['data'])):
            for d in range(len(res['data'][idx]['attributes']['last_dns_records'])):
                domain = res['data'][idx]['attributes']['last_dns_records'][d]['value']
                if domain in domains: #Handling duplicate relationships
                    continue
                elif res['data'][idx]['attributes']['last_dns_records'][d]['type']=='TXT':
                    continue
                elif res['data'][idx]['attributes']['last_dns_records'][d]['type']=='AAAA':
                    continue #Ignore these for now because the bundles arent validating because of the ipv6 getting put in the domain objects
                else:
                    domainName = DomainName(
                        value = domain
                    )
                    stixList.append(domainName)
                    stixList.append(Relationship(
                        relationship_type='communicates-with',
                        source_ref=main_malware_obj.id,
                        target_ref=domainName.id
                        ))
                    domains.append(domain)
    except KeyError: 
        pass   

    if stixList:
        print("Domain Objects Successfully Added")
        return stixList
    else:
        print("No Domains Associated with File")
        return

#Generate attack patterns (SDO) related to a file and returns a list of STIX objects
#Input: sha256 and STIX object of file being translated
def generate_ap(file_id, main_malware_obj):
    url = f"https://virustotal.com/api/v3/files/{file_id}/behaviours"

    #Get sandbox ID to be able to recieve attack patterns
    try: 
        res = requests.get(url, headers={'x-apikey':variables.API_KEY})
        res = res.json()
    except Exception as e: 
        print(str(e))

    #SandboxID parsing here
    #For now, save them to a list and pass the list to sandbox parser function
    sandbox_ids = []
    if res['data']:
        for s in range(len(res['data'])): 
            sandbox_ids.append(res['data'][s]['id'])

        #Pass the list of sandbox IDs to the parser function who will return the first one that has attack patterns. If there are no attack patterns, return false
        goodID = sandBoxIDParser(sandbox_ids)

        #If there are attack patterns, get them, create STIX objects, add them to a list, and then return the list
        if goodID: 
            url = f"https://virustotal.com/api/v3/file_behaviours/{goodID}/attack_techniques" 

            try: 
                res = requests.get(url, headers={'x-apikey':variables.API_KEY})
                res = res.json()
            except Exception as e: 
                print(str(e))

            stixList = []
            for s in range(len(res['data'])): #[1]['attributes']
                name = res['data'][s]['attributes']['name']
                ref = res['data'][s]['attributes']['link']
                id = ref.split('/')[4]
                description = res['data'][s]['attributes']['description']
                ap = AttackPattern(
                    name = name + " MITRE " + id, 
                    description = description, 
                    external_references = [
                        { 
                            "url" : ref,
                            "source_name" : "MITRE ATT&CK",
                        },
                    ],
                )
                stixList.append(ap)
                stixList.append(Relationship(
                    relationship_type="uses",
                    source_ref=main_malware_obj.id,
                    target_ref=ap.id
                    ))
            print("Attack Patterns Successfully Added")
            return stixList

        else: 
            print("No sanbox IDs with attack patterns") 
            return

    else: 
        print("File's behaviour has not been analyzed, therefore there are no attack patterns to add")
        return

#Generates indicators (SDO) for each yara ruleset associated with a file
#Input: report and STIX object associated with the file being translated
def generate_yara_indicator(report, main_malware_obj):

    #Declare list for STIX objects 
    stixList = []
    #Check to see if there are crowdsourced YARA results 
    try:
        if report[1]['data']['attributes']['crowdsourced_yara_results'] != None:
            
            for s in range(len(report[1]['data']['attributes']['crowdsourced_yara_results'])):
                url = f"https://www.virustotal.com/api/v3/yara_rulesets/{report[1]['data']['attributes']['crowdsourced_yara_results'][s]['ruleset_id']}"

                try: 
                    res = requests.get(url, headers={'x-apikey':variables.API_KEY})
                    res = res.json()
                except Exception as e:
                    print(str(e))
                name = res['data']['attributes']['name']
                ref =  res['data']['attributes']['source']
                pattern = ""
                for s in range(len(res['data']['attributes']['rules'])):
                    pattern += res['data']['attributes']['rules'][s]
                yaraInd = Indicator(
                    name = name, 
                    indicator_types = ["anamolous_activity"],
                    pattern = pattern,
                    pattern_type="yara",
                    external_references = [
                            { 
                                "url" : ref,
                                "source_name" : "Github",
                            },
                        ],
                )
                stixList.append(yaraInd)
                stixList.append(Relationship(
                    relationship_type="indicates",
                    source_ref=yaraInd.id,
                    target_ref=main_malware_obj.id
                ))
            print("YARA Inidcators Successfully Added")
            return stixList
    except KeyError: 
        print("No Yara Rules Associated with this file")
        return

def generate_campaign_obj(campaign_name, obj_list): 

    campList = []

    #Generate campign SDO 
    camp = Campaign(
        name = campaign_name
    )
    campList.append(camp)

    #Generate relationships from list 
    for obj in obj_list:
        if isinstance(obj, Malware):
            campList.append(Relationship(
                relationship_type='uses',
                source_ref=camp.id,
                target_ref=obj.id
            ))

    return campList
    