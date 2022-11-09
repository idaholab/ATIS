'''
Author: Taylor McCampbell
File: analyze.py
Purpose: This script combines the networkx and stix comparisons and outputs them to a file
'''

import sys, os
from . import networkx_comp, stix_comp
import utilities, seaborn
import matplotlib.pyplot as plt
from stix2 import MemoryStore, Environment

def analyze(path_to_g1, path_to_g2, output_directory):
    #G1 = networkx_comp.stix_to_networkx(path_to_g1)
    #G2 = networkx_comp.stix_to_networkx(path_to_g2) 

    file1Name = path_to_g1.split('/')[-1]
    file1Name = file1Name.split('.')[0]

    file2Name = path_to_g2.split('/')[-1]
    file2Name = file2Name.split('.')[0]

    original_stdout = sys.stdout

    with open(os.path.join(output_directory, f"{file1Name}VS{file2Name}.json"), 'w') as f: 
        sys.stdout = f
        print(f"Comparing {path_to_g1.split('/')[-1]} to {path_to_g2.split('/')[-1]}")
        # Networkx comparisons 
        # try: 
        #     networkx_comp.isomorphix(G1, G2)
        # except Exception as e: 
        #     print(str(e))

        # try: 
        #     networkx_comp.graph_edit_dist(G1, G2)
        # except Exception as e: 
        #     print(str(e))

        # # try: 
        # #     networkx_comp.optimal_edit(G1, G2)
        # # except Exception as e: 
        # #     print(str(e))

        # try: 
        #     dictionaryThing, malwareScores = networkx_comp.simrank(G1, G2)
        # except Exception as e: 
        #     print(str(e))
    
        # sum = 0
        # for score in malwareScores: 
        #     sum += score

        # if sum > 0:
        #     avg_malware_score = len(malwareScores) / sum
        # else:
        #     avg_malware_score = 0
        # print(f'The average malware score is {avg_malware_score}')

        #STIX Comparisons
        #Problem here is the indicators patterns for yara rules aren't parsing through whatever STIX uses to parse patterns in graph comparison
        #My solution is to omit them for the time being with the yara|noYara option when generating graphs
        try:
            stix_comp.stix_graph_sim(path_to_g1, path_to_g2)
        except Exception as e:
            print(str(e))

        try: 
            stix_comp.stix_sim_objects(path_to_g1, path_to_g2)
        except Exception as e:
            print(str(e))

        sys.stdout = original_stdout
        print(f"Analysis for {path_to_g1.split('/')[-1]} compared to {path_to_g2.split('/')[-1]} completed")

def generate_graph_comparison_heatmap(title, path_to_d1, path_to_d2, output_directory):
    comparisons = []
    filesX = []
    filesY = []
    for name in os.listdir(path_to_d1):
        filesY.append(name)
    
    filesY = utilities.truncate_list(filesX)

    for name in os.listdir(path_to_d2):
        filesX.append(name) 

    filesX = utilities.truncate_list(filesY)
   
    i = 0   
    for file in os.listdir(path_to_d1):
        comparisons.append([])
        comparisons[i] = []
        for file2 in os.listdir(path_to_d2):
            comparisons[i].append(stix_comp.stix_graph_sim(os.path.join(path_to_d1, file), os.path.join(path_to_d2, file2)))
        i += 1

    original_stdout = sys.stdout
    with open(os.path.join(output_directory, f"{title}Matrix.txt"), 'w') as f: 
        sys.stdout = f
        for thing in comparisons:
            print(thing)
    
    sys.stdout = original_stdout   
    ax = plt.axes()
    seaborn.heatmap(comparisons, ax=ax, vmin=0, vmax=100, xticklabels=filesX, yticklabels=filesY)
    ax.set_title(title)
    plt.show()
    print("Heatmap Generated")
    return comparisons