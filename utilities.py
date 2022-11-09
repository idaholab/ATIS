'''
file: utilities.py
auth: rafer cooley, taylor mccampbell
desc: miscellaneous functions for the generator system
'''

import stix2

from stix2.v21 import Bundle
from stix2 import MemoryStore, AttackPattern, ExternalReference, DomainName
from open_vocabulary import malware_type_ov
import operator, requests, variables, os

def malware_type_majority_vote(scan_results):
    '''
    Determine the type of a malware from the names determined by the AV engines provided in Virustotal report. Returns majority vote/most popular.
    INPUT:
        - scan_results(dict): {<AV_Name>:{"detected":bool,"version":str,"result":str,"update":str}}
    RETURN:
        - most_popular(str): the malware type with the most occurences in AV results
    '''

    scan_names = [scan_results[x]['result'].lower() for x in scan_results if scan_results[x]['result'] != None]
    name_counter = {}
    for mtype in malware_type_ov:
        name_counter[mtype]=0
        for name in scan_names:
            if mtype in name:
                name_counter[mtype]+=1
    return max(name_counter.items(), key=operator.itemgetter(1))[0]

#Function takes a list of virustotal sandbox API ids and returns the first one that has attack patterns, if there are none, returns false
#Input: list of virus total API sandbox ids
def sandBoxIDParser(sandbox_ids):

    for id in sandbox_ids:
        url = f"https://virustotal.com/api/v3/file_behaviours/{id}/attack_techniques"
        try: 
            res = requests.get(url, headers={'x-apikey':variables.API_KEY})
            res = res.json()
        except Exception as e: 
            print(str(e))

        try: 
            if res['data']:
                return id
        except KeyError:
            print(f"{id} Has no attack patterns") 

    return False

#Function used to write STIX bundles to a file. Takes a list of objs, converts it to a bundle, then writes it to a file
#Input: list of stix objects, filename, and the output directory   
def writeToFile(list, fileName, output_directory):
    fileName = fileName.strip()
    list = Bundle(
        objects = list
    )
    print("Bundle successfully created, writing to file")
    with open(os.path.join(output_directory, f"stix_{fileName}.json"), 'w') as outfl:
               outfl.write(list.serialize(pretty=True))

def json_to_stixList(file_path):
    #Create stix memory store object
    mem = MemoryStore()

    #Loading JSON and querying all objects into a list
    try: 
        mem.load_from_file(file_path) #Load the json data into a stix memorystore object
        stixList = mem.query() #Get all the stix objects from the memorystore object
    except Exception as e:
        print(e)

    try:
        if stixList: #If there are objects in the list, return it
            #print("Objects successfully loaded")
            return stixList
        else:
            print("No STIX Objects in JSON file")
            return
    except Exception as e:
        print('Comparing invalid thigns')
        return

def truncate_list(fileNames):

    newList = []
    for name in fileNames:
        temp = name.split('_')[1]
        temp = temp[:7]
        temp += '...'
        newList.append(temp) 

    return newList

def generate_weights_from_stix(path_to_json_bundle):

    stixList = json_to_stixList(path_to_json_bundle)
    #Assigning the default weights dict and then iterating through to see if anything isnt covered
    WEIGHTS = {
    "attack-pattern": {
        "name": (30, stix2.equivalence.object.partial_string_based),
        "external_references": (70, stix2.equivalence.object.partial_external_reference_based),
    },
    "campaign": {
        "name": (60, stix2.equivalence.object.partial_string_based),
        "aliases": (40, stix2.equivalence.object.partial_list_based),
    },
    "course-of-action": {
        "name": (60, stix2.equivalence.object.partial_string_based),
        "external_references": (40, stix2.equivalence.object.partial_external_reference_based),
    },
    "grouping": {
        "name": (20, stix2.equivalence.object.partial_string_based),
        "context": (20, stix2.equivalence.object.partial_string_based),
        "object_refs": (60, stix2.equivalence.object.list_reference_check),
    },
    "identity": {
        "name": (60, stix2.equivalence.object.partial_string_based),
        "identity_class": (20, stix2.equivalence.object.exact_match),
        "sectors": (20, stix2.equivalence.object.partial_list_based),
    },
    "incident": {
        "name": (30, stix2.equivalence.object.partial_string_based),
        "external_references": (70, stix2.equivalence.object.partial_external_reference_based),
    },
    "indicator": {
        "indicator_types": (15, stix2.equivalence.object.partial_list_based),
        "pattern": (80, stix2.equivalence.object.custom_pattern_based),
        "valid_from": (5, stix2.equivalence.object.partial_timestamp_based),
        "tdelta": 1,  # One day interval
    },
    "intrusion-set": {
        "name": (20, stix2.equivalence.object.partial_string_based),
        "external_references": (60, stix2.equivalence.object.partial_external_reference_based),
        "aliases": (20, stix2.equivalence.object.partial_list_based),
    },
    "location": {
        "longitude_latitude": (34, stix2.equivalence.object.partial_location_distance),
        "region": (33, stix2.equivalence.object.exact_match),
        "country": (33, stix2.equivalence.object.exact_match),
        "threshold": 1000.0,
    },
    "malware": {
        "malware_types": (20, stix2.equivalence.object.partial_list_based),
        "name": (80, stix2.equivalence.object.partial_string_based),
    },
    "marking-definition": {
        "name": (20, stix2.equivalence.object.exact_match),
        "definition": (60, stix2.equivalence.object.exact_match),
        "definition_type": (20, stix2.equivalence.object.exact_match),
    },
    "relationship": {
        "relationship_type": (20, stix2.equivalence.object.exact_match),
        "source_ref": (40, stix2.equivalence.object.reference_check),
        "target_ref": (40, stix2.equivalence.object.reference_check),
    },
    "report": {
        "name": (30, stix2.equivalence.object.partial_string_based),
        "published": (10, stix2.equivalence.object.partial_timestamp_based),
        "object_refs": (60, stix2.equivalence.object.list_reference_check),
        "tdelta": 1,  # One day interval
    },
    "sighting": {
        "first_seen": (5, stix2.equivalence.object.partial_timestamp_based),
        "last_seen": (5, stix2.equivalence.object.partial_timestamp_based),
        "sighting_of_ref": (40, stix2.equivalence.object.reference_check),
        "observed_data_refs": (20, stix2.equivalence.object.list_reference_check),
        "where_sighted_refs": (20, stix2.equivalence.object.list_reference_check),
        "summary": (10, stix2.equivalence.object.exact_match),
    },
    "threat-actor": {
        "name": (60, stix2.equivalence.object.partial_string_based),
        "threat_actor_types": (20, stix2.equivalence.object.partial_list_based),
        "aliases": (20, stix2.equivalence.object.partial_list_based),
    },
    "tool": {
        "tool_types": (20, stix2.equivalence.object.partial_list_based),
        "name": (80, stix2.equivalence.object.partial_string_based),
    },
    "vulnerability": {
        "name": (30, stix2.equivalence.object.partial_string_based),
        "external_references": (70, stix2.equivalence.object.partial_external_reference_based),
    },
    "ipv4-addr": {
        "value": (100, stix2.equivalence.object.exact_match)
    },
    "domain-name": {
        "value": (100, stix2.equivalence.object.exact_match)
    },
    "malware-analysis": {
        "product": (30, stix2.equivalence.object.exact_match),
        "result": (50, stix2.equivalence.object.exact_match),
        "analysis_engine_version": (10, stix2.equivalence.object.exact_match),
        "submitted": (10, stix2.equivalence.object.partial_timestamp_based),
        "tdelta" : 1
        }   
    }
    for obj in stixList: # For each object
        if obj.type in WEIGHTS: #If its in the weights dict, make sure all of its properties are 
            for key in obj: #For all the properties of an obj
                if key in WEIGHTS[obj.type]: #If the property is in the comparison, continue
                    continue
                else: #If a property isnt in the dict
                    if key == 'id' or key =='created' or key =='modified': #Make sure its one we want to compare
                        continue
                    WEIGHTS[obj.type][key] = (0, stix2.equivalence.object.exact_match) #Add the property to the dict
                    for otherKey in WEIGHTS[obj.type]: #Reset all of the weight values
                        if otherKey == 'tdelta': # tdelta key isnt a tuple, therefore we need to skip it
                            continue 
                        tempList = list(WEIGHTS[obj.type][otherKey])
                        tempList[0] = round(100/len(WEIGHTS[obj.type]))
                        tempTuple = tuple(tempList)
                        WEIGHTS[obj.type][otherKey] = tempTuple
        else: #If it isnt,add a dict for the obj and then add all of its properties
            WEIGHTS[obj.type] = {} 
            for key in obj:
                if key=='id' or key=='created' or key=='modified': #Make sure its a key we want
                    continue
                elif key =='tdelta': #Handle the tdelta key here
                    WEIGHTS[obj.type][key] = 1 
                    continue
                WEIGHTS[obj.type][key] = (round(100/len(obj)), stix2.equivalence.object.exact_match)#Add property to the dict
    return WEIGHTS

def scrape_list(json_path): 
    objDict = {}
    file =  open(json_path, 'r')
    for line in file: 
        if line[0]=='{':
            objDict = eval(line)

    for key in objDict: 
        print(key)
        if key == 100: 
            for item in objDict[100]:
                print(item)
