'''
Author: Taylor McCampbell, Shaya Wolf
File: networkx_comp.py
Purpose: The purpose of this script is to draw comparisons by putting stix data in networkx graphs
'''

import networkx as nx
from stix2 import Relationship
from utilities import json_to_stixList

def stix_to_networkx(file_path): 
    #Getting STIX List
    stixList = json_to_stixList(file_path)

    #Create networkx graph 
    G = nx.DiGraph()

    #Iterate through all STIX nodes and add them to the networkx graph with proper labels
    for obj in stixList:
        #print(type(obj))
        d = obj
        if not isinstance(obj, Relationship):
            G.add_node(obj.id, **d)
        else: 
            G.add_edge(obj.source_ref, obj.target_ref) 

    if G:
        nx.draw(G)
        return G
    else:
        print("Networkx graph has no data")
        return


def isomorphix(G1, G2): 
    if nx.algorithms.isomorphism.is_isomorphic(G1, G2):
        print("The graphs are isomorphic")
        return True
    else:
        print("The graphs are not isomorphic")
        return False

def graph_edit_dist(G1, G2): 
    edit_distance = nx.algorithms.similarity.graph_edit_distance(G1, G2) 
    print(f"Graphs require {edit_distance} edits to be equivalent")
    return edit_distance 

def optimal_edit(G1, G2):
    print("Determining the optimal edit paths of the graphs")
    opti = nx.algorithms.similarity.optimal_edit_paths(G1, G2)
    print(f"The optimal edit paths of the graphs created and returned, printing dict on next line: ")
    print(opti)
    return opti

def simrank(G1, G2): 
    print("Determing how similar the nodes are to each other in the respective graphs")
    print("AKA: Comparing G1 nodes to other nodes in G1")
    bigGraph = nx.compose(G1, G2)
    sim = nx.algorithms.similarity.simrank_similarity(bigGraph)
    malware_scores = [] 
    #Auth Shaya Wolf
    for s in sim.items(): 
        if "malware--" in s[0]:
            for d in s[1].items():
                if "malware--" in d[0] and s[0] != d[0]:
                    malware_scores.append(d[1]) 
    print(f"Malware objects simrank scores: {malware_scores}")
    print("Sim rank comparison may be useless -- we shall see ^^")
    return sim, malware_scores