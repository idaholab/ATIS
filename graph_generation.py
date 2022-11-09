#file: graph_generation.py
#auth: rafer cooley, taylor mccampbell
#desc: Main logic for creating a STIX graph from a virustotal report. Calls object_generation.py functions to generate the individual objects which are then pieced together and written out in this file.
#moved this to its own file since it contains a large amount of the logic
#specify stix version: https://stix2.readthedocs.io/en/latest/guide/ts_support.html

from variables import API_KEY #, MA, YARA
from utilities import malware_type_majority_vote
from stix2.v21 import Malware, Relationship, Indicator, MalwareAnalysis, Report, File, WindowsPEBinaryExt, WindowsPESection
from virustotal import search_by_hash
from object_generation import generate_ap, generate_domains, generate_ipv4, generate_yara_indicator, generate_campaign_obj
import os
import json

import  datetime

def generate_graph(file_hash, yara, MA):
    '''
    Entry function that consumes a file hash and writes out a STIX graph based off of it's virustotal report.
    INPUT:
        - file_hash: hash of the file being analyzed
    RETURN:
        - 1, None(int, None) on success
        - 0, error(int, str) on error
    '''
    try: 
        report_data = search_by_hash(API_KEY, file_hash) #1
        #print(report_data)
    except Exception as e: 
        print(str(e))

    if report_data[0] == 0:
        if report_data[1] == "NOTFOUND":
            print("Either an invalid hash or no virustotal report has been made for this file")
            return
        elif report_data[1] == "QUOTA EXCEEDED":
            print("The api quota has been exceeded. Try again later.")
            exit()
            
    

    #generate main malware object
    guessed_malware_type = malware_type_majority_vote(report_data[1]['data']['attributes']['last_analysis_results'])

    # Generate file object
    file_obj = generate_file(report_data[1]['data']['attributes'])

    #report_time = datetime.datetime.now().strftime('%Y-%m-%d %I:%M:%S')+"Z"
    main_malware_obj = Malware(
        name=file_hash, #report_data[1]['data']['attributes']['popular_threat_classification']['suggested_threat_label'],
        is_family=False,#we won't know whether it is a family at this point(i dont think) so set this to a single instance
        malware_types=guessed_malware_type,
        sample_refs=[file_obj.id]
    )
    objects = []
    objects.append(main_malware_obj)
    objects.append(file_obj)

    #add indicators for md5, sha256, sha1, ssdeep, vhash, submission names and corresponding relationships
    try:
        if report_data[1]['data']['attributes']['md5'] != None:
            md5_indicator = Indicator(name="MD5 Hash", indicator_types=["anamolous-activity"], pattern=f"[file:hashes.md5 = '{report_data[1]['data']['attributes']['md5']}']", pattern_type="stix")
            objects.append(md5_indicator)
            objects.append(Relationship(relationship_type='indicates',source_ref=md5_indicator.id,target_ref=main_malware_obj.id))
            print("MD5 Hash Added")
    except KeyError: 
        print("No MD5 Hash given in report")
        pass

    try: 
        if report_data[1]['data']['attributes']['sha1'] != None:
            sha1_indicator = Indicator(name="SHA1 Hash", indicator_types=["anamolous-activity"], pattern=f"[file:hashes.sha1 = '{report_data[1]['data']['attributes']['sha1']}']", pattern_type="stix")
            objects.append(sha1_indicator)
            objects.append(Relationship(relationship_type='indicates',source_ref=sha1_indicator.id,target_ref=main_malware_obj.id))
            print("SHA1 Hash Added")
    except KeyError: 
        print("No SHA1 Hash given in report")
        pass

    try:
        if report_data[1]['data']['attributes']['sha256'] != None:
            sha256_indicator = Indicator(name="SHA256 Hash", indicator_types=["anamolous-activity"], pattern=f"[file:hashes.sha256 = '{report_data[1]['data']['attributes']['sha256']}']", pattern_type="stix")
            objects.append(sha256_indicator)
            objects.append(Relationship(relationship_type='indicates',source_ref=sha256_indicator.id,target_ref=main_malware_obj.id))
            print("SHA256 Hash Added")
    except KeyError: 
        print("No SHA256 Hash given in report")
        pass

    try:
        if report_data[1]['data']['attributes']['vhash'] != None:
            vhash_indicator = Indicator(name="Vhash", indicator_types=["anamolous-activity"], pattern=f"[file:hashes.vhash = '{report_data[1]['data']['attributes']['vhash']}']", pattern_type="stix")
            objects.append(vhash_indicator)
            objects.append(Relationship(relationship_type='indicates',source_ref=vhash_indicator.id,target_ref=main_malware_obj.id))
            print("VHASH Hash Added")
    except KeyError: 
        print("No VHASH Given in report")
        pass

    try:
        if report_data[1]['data']['attributes']['ssdeep'] != None:
            ssdeep_indicator = Indicator(name="ssdeep", indicator_types=["anamolous-activity"], pattern=f"[file:hashes.ssdeep = '{report_data[1]['data']['attributes']['ssdeep']}']", pattern_type="stix")
            objects.append(ssdeep_indicator)
            objects.append(Relationship(
                relationship_type='indicates',
                source_ref=ssdeep_indicator.id,
                target_ref=main_malware_obj.id
            ))
            print("SSDeep Hash Added")
    except KeyError:
        print("No SSDeep Hash given in report")
        pass

    #add virustotal report
    #Formatting time stamp to be kosher just the way daddy stix man likes it
    #Vtotal gives us the time in seconds since the epoch or whatever that is and so we convert to UTC, add Z at the end, and then fill the space with T 
    #Oh my god seconds since the epoch is so lame! Why cant we be normal?
    new_time = ""
    try:
        report_time = datetime.datetime.fromtimestamp(report_data[1]['data']['attributes']['last_analysis_date']).strftime('%Y-%m-%d %I:%M:%S')+"Z"
        for idx in range(len(report_time)): 
            if report_time[idx] == " ": 
                new_time+='T'
            else: 
                new_time+=report_time[idx]
    except TypeError as e:
        for idx in range(len(report_time)): 
            if report_time[idx] == " ": 
                new_time+='T'
            else: 
                new_time+=report_time[idx]
        print("No time associated with report so time of first object generated used")
    robj = Report(
        name="VirusTotal",
        report_types=["malware"],
        published=new_time,
        object_refs=[main_malware_obj.id]
    )
    objects.append(robj)

    #create malware_analysis objects for each scan result (and relationships) IF configured
    if MA: 
        for scan in report_data[1]['data']['attributes']['last_analysis_results']:
            time_submitted= ""
            try:
                time_submitted = datetime.datetime.strptime(
                    report_data[1]['data']['attributes']['last_analysis_results'][scan]['engine_update'],
                    "%Y%m%d"
                ).isoformat('T')+"Z"
                result = "unknown"
            except TypeError as e:
                time_submitted= "1900-01-01T23:59:59.59Z" #Bogus time
                print("No time associated with analysis")
                
            if report_data[1]['data']['attributes']['last_analysis_results'][scan]["category"] == "malicious":
                result = "malicious"

            objects.append(MalwareAnalysis(
                product=scan,
                result=result,
                analysis_engine_version = report_data[1]['data']['attributes']['last_analysis_results'][scan]['engine_version'],
                submitted = time_submitted
            ))
            objects.append(Relationship(
                relationship_type="av-analysis-of",
                source_ref=objects[-1].id,
                target_ref=main_malware_obj.id
            ))

    #Get IPv4 Addresses and add them to the graph
    ipList = generate_ipv4(report_data[1]['data']['attributes']['sha256'], main_malware_obj)
    if ipList:
        for ip in ipList: 
            objects.append(ip)
    
    #Get domain names and add them to the graph
    domainList = generate_domains(report_data[1]['data']['attributes']['sha256'], main_malware_obj)
    if domainList: 
        for domain in domainList: 
            objects.append(domain)
    
    #Get attack patterns and add them to the graph
    apList = generate_ap(report_data[1]['data']['attributes']['sha256'], main_malware_obj)
    if apList:
        for ap in apList: 
            objects.append(ap)
    
    if yara: #YARA makes comparisons fail, adding functionality to forgo adding yara indicators to the graphs for the sake of comparisons
        yaraList = generate_yara_indicator(report_data, main_malware_obj)
        if yaraList:
            for yara in yaraList:
                objects.append(yara)
    #print("5th API call. Must pause because the gods are generous, but not that generous. All hail the pheonix, may he blaze for eternity and forevermore.")
    #The pheonix was generous, and gave us a more powerful key, thus eliminating the need to waste time. All hail the pheonix, may he blaze for eternity and forevermore.
    #Create relationship between report and all the objects in the list that were gotten from it
    for obj in objects: 
        #print(type(obj))
        if not isinstance(obj, Relationship):
            if not isinstance(obj, Malware) and not isinstance(obj, Report):
                objects.append(Relationship( 
                    relationship_type='derived-from',
                    source_ref=obj.id,
                    target_ref=robj.id
                ))
    #Creating relationship for malware obj 
    objects.append(Relationship(
        relationship_type='related-to',
        source_ref=robj.id,
        target_ref=main_malware_obj.id
    ))

    print("File succesfully analyzed")
    return objects
        
def generate_campaign(campaign_name, hash_list, yara, ma):
    #Generate Graphs for each hash associated with the campaign and add all the objects to a big list
    campaignList = []
    for hash in hash_list:
        singleBundle = generate_graph(hash, yara, ma)
        if singleBundle:
            for obj in singleBundle:
                campaignList.append(obj)
    
    #Create campaign object and relationships
    campObj = generate_campaign_obj(campaign_name, campaignList)
    for obj in campObj:
        campaignList.append(obj)

    return campaignList

# Generate a STIX File SCO, with a Windows PE Extension if available
def generate_file(data):
    # Get the file name. Default will be "malware sample"
    filename = "malware sample"
    if 'meaningful_name' in data.keys():
        filename = data['meaningful_name']
    elif len(data['names']) > 0:
        filename = data['names'][0]

    # Get the malware hashes
    hashes = {}
    hashKeys = ["md5", "sha1", "sha256", "ssdeep"]
    for key in hashKeys:
        if key in data.keys():
            hashes[key] = data[key]
    
    try:
        extensions = {}

        # pe_info contains data about a Windows PE binary. We can add an extension to the file object with this information.
        if 'pe_info' in data.keys():
            pe_type = data["type_extension"]
            imphash = ""
            # Find the imphash
            if "imphash" in data["pe_info"].keys():
                imphash = data["pe_info"]["imphash"]
            # Find the number of sections
            number_of_sections = 0
            if "sections" in data["pe_info"].keys():
                number_of_sections = len(data["pe_info"]["sections"])

            # Extract the timestamp
            time_date_stamp = ""
            if "timestamp" in data["pe_info"].keys():
                time_date_stamp = datetime.datetime.fromtimestamp(data["pe_info"]["timestamp"]).strftime('%Y-%m-%d %I:%M:%S')+"Z"
                time_date_stamp = time_date_stamp.replace(' ', 'T', 1)

            # Loop through each section
            sections = []
            for section in data["pe_info"]["sections"]:
                name = section["name"]
                size = section["raw_size"]
                entropy = section["entropy"]
                section_hashes = {}
                hash_keys = ["md5", "sha1", "sha256", "ssdeep", "vhash"]
                for key in hash_keys:
                    if key in section.keys():
                        section_hashes[key] = section[key]
                sections.append(WindowsPESection(
                    name=name, 
                    size=size, 
                    entropy=entropy, 
                    hashes=section_hashes))

            # Create the extension
            extensions["windows-pebinary-ext"] = WindowsPEBinaryExt(
                pe_type=pe_type, 
                imphash=imphash,
                number_of_sections=number_of_sections,
                time_date_stamp=time_date_stamp,
                sections=sections
                )

            # Return the file with the extension object
            return File(name=filename, hashes=hashes, extensions=extensions)
    except:
        print("PE Binary info found, but was incomplete.")

    # If we get here, the extension could not be made.
    # Return the file with just the name and the hashes.
    return File(name=filename, hashes=hashes)
    
    