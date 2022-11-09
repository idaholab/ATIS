"""Any Threat Intelligence to STIX

Usage:
    main.py generate single <file_hash> <output_directory> [--YARA] [--MA]
    main.py generate many <report_file> <output_directory> [--YARA] [--MA]
    main.py generate campaign <campaign_name> <report_file> <output_directory> [--YARA] [--MA]
    main.py generate family <family_name> <output_directory> [--YARA] [--MA]
    main.py compare <json_path_1> <json_path_2> <output_directory>
    main.py heatmap <title> <bundle_directory_path_1> <bundle_directory_path_2> <output_directory>
    main.py weights <json_path>
    main.py clean <json_path>
    main.py enrich single <json_path> <output_directory> [--CVE]
    main.py enrich many <bundle_directory_path> <output_directory> [--CVE]
    main.py (-h | --help)
    main.py --version

Options:
    file_hash               SHA256 Hash of file being translated.
    report_file             Path to a text file that contains SHA256 hashes of files to be translated.
    campaign_name           Name of the campaign that connects the samples together.
    output_directory        Path to location where STIX graphs will be saved. If directory doesn't exist, then it will be created. 
    --YARA                  Optional flag to include any YARA indicators contained in the VirusTotal reports
    --MA                    Optional flag to add a Malware Analysis object to the STIX bundle
    title                   Title of the heatmap generated.
    json_path*              Path to json file containing the STIX bundle you wish to interact with.
    bundle_directory_path*  Path to a directory containing multiple JSON bundles to be compared.
    weights                 Generates a STIX weight comparison dictionary based off the given bundle
    clean                   Grabs objects that are a 100% match from a generated comparison .json file
    --CVE                     If included, tells the enrichment script to include CVEs. Warning: this will potentially add thousands of CVEs to the bundle and take a while. The default is False.
    -h --help               Show this screen.
    --version               Show version.
"""

#Auth: Rafer Cooley, Taylor McCampbell
#Main entrypoint into the Virustotal -> STIX program

from docopt import docopt
import os, sys
from time import sleep
from enrich import enrichFile

from graph_generation import generate_graph, generate_campaign
from malware_bazaar import generate_graph_from_signature
from object_generation import generate_domains
from stix2 import Malware
from utilities import generate_weights_from_stix, writeToFile, scrape_list
from analysis import analyze, stix_comp
from variables import API_PREMIUM

DEBUG=os.getenv("VTOTAL_STIX_DEBUG",True)
DEBUG_LVL=os.getenv("VTOTAL_STIX_DEBUG_LEVEL",5) #5(verbose),1(limited)

YARA = False #Configuration variables
MA = False

def dprint(lvl,msg):
    '''
    Helper function to print messages when in debug mode and the certain verbosity level is met.
    INPUT:
        - lvl(int): the verbosity level(1-5) with 5 being the most verbose
        - msg(str): the message to be printed to STDOUT
    RETURN:
        - n/a
    '''
    if DEBUG and lvl<=DEBUG_LVL:
        print(msg)

if __name__=="__main__":
    arguments = docopt(__doc__, version='Any Threat Intelligence to STIX V1.0')
    dprint(5,arguments)
    
    #set optional arguments used by many different functions of this program
    YARA = arguments['--YARA']
    MA = arguments['--MA']

    #argument parsing and sanity checks
    if arguments['generate']:
        
        #ensure the output directory exists, otherwise create it
        if os.path.isdir(arguments['<output_directory>']):
            dprint(1,'> Output directory exists')
        else:
            try:
                os.mkdir(arguments['<output_directory>'])
                dprint(1,'> Output directory created')
            except Exception as e:
                dprint(2,f">> Error creating directory: {str(e)}")
        
        #generate graph for single report
        if arguments['single']:
            bundle = generate_graph(arguments['<file_hash>'], YARA, MA)
            if bundle:
                writeToFile(bundle, arguments['<file_hash>'], arguments['<output_directory>']) 
        #generate many reports
        elif arguments['many']:
            if os.path.isfile(arguments['<report_file>']):
                file = open(arguments['<report_file>'], 'r')
                lines = file.readlines()
                for line in lines: 
                    bundle = generate_graph(line, YARA, MA)
                    writeToFile(bundle, line, arguments['<output_directory>'])
                    if not API_PREMIUM:
                        print("Using free API. Sleeping to avoid hitting quota")
                        sleep(15.5)

            else:
                print(f"Provided file is not a file: <{arguments['<report_file>']}>")
        #Generate a campaign for multiple malware objects
        elif arguments['campaign']:
            if os.path.isfile(arguments['<report_file>']):
                file = open(arguments['<report_file>'], 'r')
                lines = file.readlines()
                hashList = []
                for line in lines: 
                    hashList.append(line)
                bundle = generate_campaign(arguments['<campaign_name>'], hashList, YARA, MA)
                writeToFile(bundle, arguments['<campaign_name>'], arguments['<output_directory>'])
            else: 
                print(f"Provided file is not a file: {arguments['<report_file>']}")
        elif arguments['family']:
            generate_graph_from_signature(arguments["<family_name>"], YARA, MA, arguments["<output_directory>"])
        else:
            print("Unknown argument for generate command. Must be 'single', 'many', 'campaign', or 'family'")
            sys.exit(-1)
    elif arguments['compare']:
        analyze.analyze(arguments['<json_path_1>'], arguments['<json_path_2>'], arguments['<output_directory>'])
    elif arguments['heatmap']:
        analyze.generate_graph_comparison_heatmap(arguments['<title>'], arguments['<bundle_directory_path_1>'], arguments['<bundle_directory_path_2>'], arguments['<output_directory>'])
    elif arguments['weights']:
        weights = generate_weights_from_stix(arguments['<json_path>'])
        print(weights)
    elif arguments['clean']: 
        scrape_list(arguments['<json_path>'])
    elif arguments['enrich']:

        #ensure the output directory exists, otherwise create it
        if os.path.isdir(arguments['<output_directory>']):
            dprint(1,'> Output directory exists')
        else:
            try:
                os.mkdir(arguments['<output_directory>'])
                dprint(1,'> Output directory created')
            except Exception as e:
                dprint(2,f">> Error creating directory: {str(e)}")

        if arguments["single"]:
            enrichFile(arguments['<json_path>'], arguments['<output_directory>'], arguments["--CVE"])
        elif arguments["many"]:
            bundleDir = arguments["<bundle_directory_path>"]
            bundles = os.listdir(bundleDir)
            for file in bundles:
                if os.path.isfile(os.path.join(bundleDir, file)):
                    enrichFile(os.path.join(bundleDir, file), arguments['<output_directory>'], arguments["--CVE"])
    else:
        print('There was a problem parsing the arguments, quitting.')
