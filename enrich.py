# Author: Caleb Georgeson
# Take a bundle generated with VTAGS and enrich it with weaknesses and mitigations.

import os
import requests
import stix2
from bs4 import BeautifulSoup
import sys
import json
import math
import time

# NVD CVE API options
API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0/"
resultsPerPage = 1000

# Takes a filename of a STIX bundle and adds more data to it, then saves the new bundle as FILENAME__enriched.json in the specified output directory
def enrichFile(filename, output_dir, include_cve=False):
    file = open(filename)

    jsonBundle = file.read()

    file.close()

    # Parse bundle
    bundle = stix2.parse(jsonBundle)

    numObjects = len(bundle.objects)

    # Loop through each object in the bundle
    for obj in bundle.objects:

        # We are only interested in the attack patterns
        if obj.type == "attack-pattern":

            URL = ""

            # Look for the URL in external_references
            if hasattr(obj, "external_references"):
                for ref in obj.external_references:
                    # We are looking for links to MITRE ATT&CK
                    if ref.url.find("attack.mitre.org") != -1:
                        URL = ref.url

            print(URL)

            # Skip this object if there isn't a URL
            if URL == "":
                break

            # Get the page
            page = None
            try:
                page = requests.get(URL)
            except:
                print(f"Error while loading page {URL}")
                continue

            soup = BeautifulSoup(page.content, "html.parser")

            index = 0

            #######################################################
            # This section has been commented because some sub-techniques may not be related to the malware.
            # It has been left here in case it is useful later.
            # # Get any sub-techniques from the page and create attack patterns
            # spans = soup.find_all("span")
            # subTechs = None
            # for s in spans:
            #     if "Sub-techniques:" in s.text:
            #         subTechs = s
            #         break

            # if subTechs != None:
            #     links = subTechs.parent.find_all("a")

            #     for a in links:
            #         link = f"https://attack.mitre.org{a['href']}"
            #         id = a.text
            #         # print(link)
            #         print("Sub-technique: ", id)

            #         apPage = requests.get(link)
            #         apSoup = BeautifulSoup(apPage.content, "html.parser")

            #         title = "" 
            #         for string in apSoup.find("h1").stripped_strings:
            #             title += string

            #         description = apSoup.find("p").text

            #         ref = stix2.ExternalReference(source_name="MITRE ATT&CK", external_id=id, url=link)
            #         ap = stix2.AttackPattern(name=f"{title} - MITRE {id}", description=description, external_references=[ref])
            #         bundle.objects.append(ap)
            #         bundle.objects.append(stix2.Relationship(relationship_type="related-to",source_ref=ap.id,target_ref=obj.id))
            ###########################################################

            # Get Mitigations from the page
            mitigations = soup.find(id="mitigations")
            if mitigations != None:
                table = mitigations.next_sibling.next_sibling

                if table != None and table.tbody != None:
                    
                    for row in table.tbody.children:
                        if hasattr(row, "contents"):
                            mid = row.contents[1].a.text
                            name = f"{mid} - {row.contents[3].a.text}"
                            desc = row.contents[5].p.text

                            link = f"https://attack.mitre.org/mitigations/{mid.strip()}"

                            # Check if the CoA already exists in the bundle
                            uuid = ""
                            for objCheck in bundle.objects:
                                if hasattr(objCheck, "name"):
                                    if objCheck.name == name:
                                        uuid = objCheck.id
                                        break

                            if uuid == "":
                                #CoA doesn't already exist in the bundle. Add it here.
                                ref = stix2.ExternalReference(source_name="MITRE ATT&CK", external_id=mid, url=link)

                                coa = stix2.CourseOfAction(name=name, description=desc, external_references=[ref])
                                bundle.objects.append(coa)
                                bundle.objects.append(stix2.Relationship(relationship_type="mitigates",source_ref=coa.id,target_ref=obj.id))
                            else:
                                #CoA already exists. Create a relationship 
                                bundle.objects.append(stix2.Relationship(relationship_type="mitigates",source_ref=uuid,target_ref=obj.id))




            while index != -1:
                # Find the next occurence of a capec URL
                index = page.text.find("https://capec.mitre.org/data/definitions", index)
                if index != -1:

                    endUrlIndex = page.text.find('"', index)

                    # Extract the URL
                    capecUrl = page.text[index:endUrlIndex]
                    
                    # Load the capec page
                    capecPage = None
                    try:
                        capecPage = requests.get(capecUrl)
                    except: 
                        print(f"Error while loading {capecUrl}")
                        continue
                    

                    # Find the CWEs related to the attack pattern
                    cweIndex = 0
                    while cweIndex != -1:
                        # Find the next occurence of a CWE URL
                        cweIndex = capecPage.text.find("http://cwe.mitre.org/data/definitions", cweIndex)

                        if cweIndex != -1:
                            endCweIndex = capecPage.text.find('"', cweIndex)

                            # Extract the URL
                            cweUrl = capecPage.text[cweIndex:endCweIndex]

                            # Get the ID from the URL
                            cweId = "CWE-" + cweUrl.split('/')[-1].split('.')[0]

                            print(cweId)

                            # Check if the CWE already exists in the bundle
                            uuid = ""
                            for objCheck in bundle.objects:
                                if hasattr(objCheck, "name"):
                                    if objCheck.name == cweId:
                                        uuid = objCheck.id
                                        break

                            if uuid == "":
                                # Create a new CWE and add it to the bundle
                                ext_ref = stix2.ExternalReference(source_name="CWE", external_id=cweId, url=cweUrl)
                                cwe = stix2.Vulnerability(name=cweId, external_references=[ext_ref])
                                uuid = cwe.id
                                bundle.objects.append(cwe)
                                bundle.objects.append(stix2.Relationship(relationship_type="related-to", 
                                                                        source_ref=obj.id, 
                                                                        target_ref=uuid))
                                # This is disabled by default
                                # Each CWE is potentially related to thousands of CVEs.
                                # Including every CVE will bloat the graph, and only
                                # a small percentage are likely to be relevant to the malware.
                                if include_cve:

                                    print("Finding CVEs...")

                                    # Get every CVE related to this CWE
                                    res = requests.get(f"{API_URL}?cweId={cweId}&resultsPerPage={1}")
                                    data = json.loads(res.content)
                                    totalResults = data["totalResults"]
                                    print(totalResults)

                                    totalPages = math.ceil(totalResults / resultsPerPage)
                                    print(f"Total pages: {totalPages}")

                                    cvePage = 1
                                    curVuln = 0
                                    while curVuln < totalResults:
                                        
                                        # Retrieve the next page
                                        cveResponse = None
                                        cveUrl = f"{API_URL}?cweId={cweId}&resultsPerPage={resultsPerPage}&startIndex={curVuln}"
                                        try:
                                            cveResponse = requests.get(cveUrl)
                                        except Exception as e:
                                            print(f"Error while fetching {cveUrl} -- {str(e)}")
                                            continue

                                        try:
                                            cveData = json.loads(cveResponse.content)
                                        except Exception as e:
                                            print(f"Error loading cve response content: {str(e)}")
                                            print("---------------------------------------------------------------")
                                            print(cveResponse.content)
                                        
                                        print(f"Processing page {cvePage} out of {totalPages}")

                                        for cve in cveData["result"]["CVE_Items"]:
                                            curVuln += 1
                                            cveId = cve["cve"]["CVE_data_meta"]["ID"]
                                            # print(id)

                                            cveExists = False
                                            for objCheck in bundle.objects:
                                                if hasattr(objCheck, "name"):
                                                    if objCheck.name == cveId:
                                                        cveExists = True
                                                        break

                                            if not cveExists:
                                                # Vuln doesn't exist. Create it
                                                description = cve["cve"]["description"]["description_data"][0]["value"]

                                                refs = []
                                                refs.append(stix2.ExternalReference(source_name="cve", external_id=cveId))

                                                # Some urls returned from nvd are not valid according to the STIX spec. 
                                                # This is commented to keep the bundles valid. If the urls can be validated, 
                                                # this can be uncommented.
                                                # for r in cve["cve"]["references"]["reference_data"]:
                                                #     refs.append(stix2.ExternalReference(source_name=r["name"], url=r["url"]))

                                                stixVuln = stix2.Vulnerability(name=cveId, description=description, external_references=refs)
                                                bundle.objects.append(stixVuln)
                                                bundle.objects.append(stix2.Relationship(relationship_type="related-to", source_ref=stixVuln.id, target_ref=cwe.id))
                                            else:
                                                #Vuln exists. Create the relationship to the CWE
                                                bundle.objects.append(stix2.Relationship(relationship_type="related-to", source_ref=objCheck.id, target_ref=cwe.id))

                                        # Sleep 6 seconds minimum to prevent any firewall blocks, src: <https://nvd.nist.gov/general/news/API-Key-Announcement>
                                        time.sleep(6)

                                        cvePage += 1

                                    print(f"Processed {curVuln} out of {totalResults} vulnerabilities")


                            else:
                                # Check if the CWE is already related to the current attack pattern
                                exists = False
                                for objCheck in bundle.objects:
                                    if objCheck.type == "relationship":
                                        if objCheck.source_ref == obj.id and objCheck.target_ref == uuid:
                                            exists = True
                                            break
                                if not exists:
                                    # Create a new relationship
                                    bundle.objects.append(stix2.Relationship(relationship_type="related-to", 
                                                                            source_ref=obj.id, 
                                                                            target_ref=uuid))
                            cweIndex += 1
                        else:
                            break
                    
                    # Find the CoAs from the CAPEC page
                    soup = BeautifulSoup(capecPage.content, "html.parser")

                    mitigationDiv = soup.find(id="Mitigations")
                    if mitigationDiv != None:
                        mitigations = mitigationDiv.find_all("td")
                        capecId = capecUrl.split("/")[-1].split(".")[0]
                        for mit in mitigations:
                            # Create a new COA
                            ext_ref = stix2.ExternalReference(source_name="capec", url=capecUrl, external_id=f"CAPEC-{capecId}")
                            coa = stix2.CourseOfAction(name=mit.text, external_references=[ext_ref])
                            bundle.objects.append(coa)
                            bundle.objects.append(stix2.Relationship(relationship_type="mitigates", source_ref=coa.id, target_ref=obj.id))

                    index += 1
    

    # Check to see if anything was added to the bundle
    if numObjects == len(bundle.objects):
        # No objects were added.
        print("No links found to Mitre ATT&CK. Nothing to enrich.")
    else:
        print(f"Saving bundle with {len(bundle.objects)} objects...")
        jsonBundle = bundle.serialize(pretty=False)

        # Get the filename without directory paths
        baseFilename = filename.strip().split("/")[-1]

        # Save the enriched bundle
        saveFilename = os.path.join(output_dir, baseFilename.split(".")[0] + "__enriched.json")

        file = open(saveFilename, "w")
        file.write(jsonBundle)
        file.close()
