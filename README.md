# Any Threat Intelligence to STIX (ATIS)

The purpose of this project is to generate stix graphs from the information contained within a VirusTotal report.

The program takes a single sha-256 hash or a text file of sha-256 hashes and generates STIX graphs from the virustotal reports associated with the hash. If the hash does not have a virustotal report associated with it the propram will skip the file.  

NOTE: If using the campaign or generate many functionality the text file must contain one sha-256 hash per line and there MUST BE no whitespace at the beginning or end of the hash. In the future, we will look into handling whitespace or what type of format works best for this feature.

- [Any Threat Intelligence to STIX](#any-threat-intelligence-to-stix)
  - [Installation](#installation)
    - [Anaconda Installation](#anaconda-installation)
    - [Variables & API Key Setup](#variables--api-key-setup)
  - [Usage](#usage)
  - [STIX Graph Generation](#stix-graph-generation)
    - [Graph From Single Malware Sample](#graph-from-single-malware-sample)
    - [Graph From Multiple Malware Samples](#graph-from-multiple-malware-samples)
    - [Generate Campaign Graph](#generate-campaign-graph)
    - [Generate Family Graph](#generate-family-graph)
    - [Compare STIX Graphs](#compare-stix-graphs)
    - [Generate Heatmap of STIX Graph Comparison](#generate-heatmap-of-stix-graph-comparison)
    - [Enrich Existing STIX Graph](#enrich-existing-stix-graph)
    - [Enrich Multiple Existing STIX Graphs](#enrich-multiple-existing-stix-graphs)
  - [Troubleshooting](#troubleshooting)
  - [Peer Reviews](#peer-reviews)

## Installation

This project is developed using the python programming language and is targeted at Python3.8. Development of this project utilized the Anaconda virtual environment system but Poetry/pyenv can also be used for creating virtual environments.

### Anaconda Installation

```
conda create -n atis python=3.8
conda activate atis
pip install -r requirements.txt
```

### Variables & API Key Setup

Change the name of the variables.TEMPLATE file to variables.py

Change the API_KEY variable to your personal virustotal API key. If you do not already have a key then read [this guide](https://developers.virustotal.com/reference/getting-started) for info on how to obtain one for free.

Specify whether the API key is public or premium by changing the API_PREMIUM variable to True (if using the premium API) or False (if using the public API). This will tell VTAGS to wait between requests to avoid the 4 requests/minute quota imposed on the public API.

## Usage

```bash
Any Threat Intelligence to STIX

Usage:
    main.py generate single <file_hash> <output_directory>
    main.py generate many <report_file> <output_directory>
    main.py generate campaign <campaign_name> <report_file> <output_directory>
    main.py generate family <family_name> <output_directory>
    main.py compare <json_path_1> <json_path_2> <output_directory>
    main.py heatmap <title> <bundle_directory_path_1> <bundle_directory_path_2> <output_directory>
    main.py weights <json_path>
    main.py clean <json_path>
    main.py configure (yara|ma) (yes|no)
    main.py enrich single <json_path> <output_directory> [cve]
    main.py enrich many <bundle_directory_path> <output_directory> [cve]
    main.py (-h | --help)
    main.py --version

Options:
    yara|noYara             Generate the graphs with or without YARA indicators. Comparison functionality will fail if trying to compare YARA indicators with each other.
    file_hash               SHA256 Hash of file being translated.
    report_file             Path to a text file that contains SHA256 hashes of files to be translated.
    campaign_name           Name of the campaign that connects the samples together.
    output_directory        Path to location where STIX graphs will be saved. If directory doesn't exist, then it will be created. 
    title                   Title of the heatmap generated.
    json_path*              Path to json file containing the STIX bundle you wish to interact with.
    bundle_directory_path*  Path to a directory containing multiple JSON bundles to be compared.
    weights                 Generates a STIX weight comparison dictionary based off the given bundle
    clean                   Grabs objects that are a 100% match from a generated comparison .json file
    configure               Configure the generator to generate graphs with or without certain objects 
    yara|ma                 Used in conjuction with the configure command. Determines whether you are configuring the generator to include or leave out YARA Indicators(yara) or Malware Analysis(ma) objects 
    yes|no                  Yes configures the selected option to generate graphs with the feature, no turns the feature off **NOTE** Default state is off for both YARA and MA
    cve                     If included, tells the enrichment script to include CVEs. Warning: this will potentially add thousands of CVEs to the bundle and take a while. The default is False.
    -h --help               Show this screen.
    --version               Show version.
```

## STIX Graph Generation

### Graph From Single Malware Sample

Scenario: You have a single malware sample that needs to be analyzed and results stored in a STIX graph.

1. To generate a stix graph bundle for a single malware object run the following command. Here the example 754fa... hash used as input is the **sha256 hash** of an [eternal blue](https://www.virustotal.com/gui/file/754fa28e342c991d11404cde13845f8737994ef06652997f08eb0fa74cb6f71b) sample. `python main.py generate single 754fa28e342c991d11404cde13845f8737994ef06652997f08eb0fa74cb6f71b output_tests/` (change the hash value and output directory to match your needs)
2. Look in the output folder for a file with a name such as "stix_754fa28e342c991d11404cde13845f8737994ef06652997f08eb0fa74cb6f71b.json" for example. This is the stix file generated by the program.
3. Open this file in your [preferred STIX viewer application](https://github.com/idaholab/STIG/releases/tag/2.0.1.alpha) to see the different indicator, report, file, and malware objects generated for this single malware sample.

Optional arguments: Include YARA indicators and/or include malware indicator object. Adding the flag `--YARA` to the command will add indicator objects containing any YARA rules defined by the VirusTotal Report. Adding the flag `--MA` to the command will add a Malware Analysis object to the graph.

### Graph From Multiple Malware Samples

Scenario: You have multiple malware samples that you need to analyze and combine into a single STIX graph.

1. Create a file that contains multiple **SHA256 hashes** of malware samples, one hash per line.
2. Run the command to generate a STIX file with multiple malware samples: `python main.py generate many hash_file.txt output_tests/` (replace the filename and output directory values to correspond with your needs).
3. In the output directory will exist three new json files, each of which is a properly formatted STIX graph containing information from VirusTotal in the appropriate indicator objects.

Optional arguments: Include YARA indicators and/or include malware indicator object. Adding the flag `--YARA` to the command will add indicator objects containing any YARA rules defined by the VirusTotal Report. Adding the flag `--MA` to the command will add a Malware Analysis object to the graph.

### Generate Campaign Graph

Scenario: You have multiple malware samples that have been used in the same campaign and want to create a STIX graph representative of the campaign and containing information on all the malware samples.

1. Create a file that contains multiple **SHA256 hashes** of malware samples, one hash per line.
2. Run `python main.py generate campaign test_campaign1 hash_file.txt output_tests/ --YARA --MA`

Optional arguments: Include YARA indicators and/or include malware indicator object. Adding the flag `--YARA` to the command will add indicator objects containing any YARA rules defined by the VirusTotal Report. Adding the flag `--MA` to the command will add a Malware Analysis object to the graph.

### Generate Family Graph

Scenario: You want to generate a graph for a family of malware but do not have a list of hashes for all samples tagged under that family. This functionality will query Malware Bazaar for all malware samples grouped under a family name tag (i.e. TrickBot) and generate one STIX graph per malware sample containing the relevant information from both VirusTotal and Malware Bazaar.

Optional arguments: Include YARA indicators and/or include malware indicator object. Adding the flag `--YARA` to the command will add indicator objects containing any YARA rules defined by the VirusTotal Report. Adding the flag `--MA` to the command will add a Malware Analysis object to the graph.

1. Run `python main.py generate family test_family1 output_tests/`
2. One graph for each sample associated with the given family will be generated using the information from MalwareBazaar and saved in the designated output directory.

NOTE: currently works by querying [MalBazaar signatures](https://bazaar.abuse.ch/api/#siginfo) and not [MalBazaar tags](https://bazaar.abuse.ch/api/#taginfo).

### Compare STIX Graphs

Scenario: You want to compare two different STIX graphs in order to determine a similarity score between the graphs.

1. Run `python main.py compare stix1.json stix2.json output_tests/`
   1. e.g. `python main.py compare output_tests/old/withMA/wannacry_individuals/stix_1be0b96d502c268cb40da97a16952d89674a9329cb60bac81a96e01cf7356830.json output_tests/old/withMA/wannacry_individuals/stix_2ca2d550e603d74dedda03156023135b38da3630cb014e3d00b1263358c5f00d.json output_tests/`
2. Results will be stored in a file in the output directory that is named in the following format: `{file1}V{file2}.json`
   1. This file contains an overall score of how similar the graphs are, a comparison score for each object in the graph, and a percentage score of similar nodes in the graph

- NOTE: Comparison functionality will fail if trying to compare YARA indicators with each other.
- NOTE: If you receive an error message such as `'file' type has no 'weights' dict specified` then there is an object within one of the STIX graphs being compared (i.e. file object) that does not have a definition for how to compare that object outlined in the variables.py:WEIGHTS dictionary.

### Generate Heatmap of STIX Graph Comparison

Scenario: You have two directories each containing multiple STIX graphs and you want to visualize the comparison score between each graph in each directory. For example, each of these directories was populated with the “Family Generation” functionality.

1. Run `python main.py heatmap TestTitle graphdir1/ graphdir2/ output_tests/`
2. A matplotlib heatmap will be generated and displayed with the default controls allowing the heatmap to be save as an image file. Also, a matrix file containing the raw data of the heatmap will be saved to the designated output directory.

- NOTE: the two directories being compared must be distinct directories, it is currently not possible to generate a heatmap comparison on a single directory of graphs.
- NOTE: this process may take a long time as it is an O^2 operation.

### Enrich Existing STIX Graph

Scenario: You have a single STIX graph containing malware objects and you wish to enrich the graph with additional information, possibly including CVE information from the [National Vulnerability Database](https://nvd.nist.gov/developers/vulnerabilities).

Optional arguments: Adding the flag `--CVE` to the command will query the NVD NIST API endpoint

1. Run `python main.py enrich single graph1.json output_tests/`
2. IF an attack pattern object is found in the original graph AND it contains a link to the MITRE ATT&CK listing, then any CWE and Mitigations associated with this listing will be downloaded from the NVD and added to the new graph as the appropriate objects and relationships.
   1. The resulting graph file can be found in the designated output directory and named `{filename}__enriched.json`
3. Otherwise the program will print that no attack patterns were found and enrichment will not occur.
4. Additionally, if the `--CVE` flag was defined then all of the CVE information for each CWE found will be downloaded and linked appropriately.

- NOTE: Each CWE is potentially related to thousands of CVEs which could severely bloat the graph. Only a small percentage of these CVEs are likely to be relevant to the malware.

### Enrich Multiple Existing STIX Graphs

Scenario: You have multiple STIX graphs, each containing at least one malware object and you wish to enrich them all additional information, possibly including CVE information from the [National Vulnerability Database](https://nvd.nist.gov/developers/vulnerabilities).

Optional arguments: Adding the flag `--CVE` to the command will query the NVD NIST API endpoint

1. Run `python main.py enrich many samples_directory output_tests`
2. Each file found in the `samples_directory` will be fed into the same process used by the `enrich single` command and the enriched files can be found in the designated output directory and named `{filename}__enriched.json`.

## Troubleshooting

> The program is not retrieving reports from VirusTotal.

Check your API key and the limitations associated with your account. Have you requested more than the maximum daily limit? The program will rate limit itself so that 4 requests/second are sent which complies with the maximum minute rate limit but does not account for daily limits.

> The program is unable to compare two graphs.

Check whether there exists YARA objects within either graph. The program is unable to compare these objects. If a message saying an entry for an object is not found in the weights dictionary then that object does not have a method for comparison but can be custom made if necessary.

> The program is not finding a family of samples on MalwareBazaar even though manual search through the web interface shows the samples exist.

This is a weird occurance that has been attributed to the fact that the general query on the website of `tag:Sandworm` will search by tag name but the `sandworm` input to our program will search by signature. It is not currently well defined the difference between the two terms as determined by the MalwareBazaar API documentation of [tag search](https://bazaar.abuse.ch/api/#taginfo) versus [signature search](https://bazaar.abuse.ch/api/#siginfo).

## Peer Reviews

- Secure Code Review completed on 10/25/2021, all issues have been resolved.
- Secure Code Review completed on 08/05/2022
- Full functionality testing completed on 8/30/2022
