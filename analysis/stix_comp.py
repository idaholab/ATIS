'''
Author: Taylor McCampbell
File: stix_comp.py 
Purpose: Utilize the stix2 python equivalance and similarity functions to do analysis on auto generated stix from vtotal -> stix INL repo
'''

from networkx.algorithms import similarity
from stix2 import MemoryStore, Environment, Relationship
from utilities import json_to_stixList

import variables

#Function takes the path to two json files containing stix bundles and determines how similar the graphs are
def stix_graph_sim(g1_path, g2_path):
    #Function takes two JSON files and compares them based off of a certain threshold 
    env = Environment(store=MemoryStore())

    g1 = json_to_stixList(g1_path)
    g2 = json_to_stixList(g2_path)

    #Generating memorystore objects with the stix graphs stored in them
    ms1 = MemoryStore(g1)
    ms2 = MemoryStore(g2)
   
    #Defining our weight dictionaries
    weight_dict = variables.WEIGHTS
    

    prop_scores = {} 
    similarity_result = env.graph_similarity(ms1, ms2, prop_scores, ignore_spec_version=False, versioning_checks=False, max_depth=1, **weight_dict)
    print(f"Graphs are {similarity_result} percent similar")
    return similarity_result

#Function takes the path to two json files containing stix bundles and determines if any of the objects are over 70% similar. Returns a dictionary with all objects that are over 70% similar. 
def stix_sim_objects(g1_path, g2_path):

    env = Environment(store=MemoryStore())

    g1 = json_to_stixList(g1_path)
    g2 = json_to_stixList(g2_path)

    weight_dict = variables.WEIGHTS

    same_obj_list = {}
    counter = 0
    totalComp = 0
    for obj in g1: #For each obj in g1 compared to each obj in g2
        if isinstance(obj, Relationship):
            continue
        for obj2 in g2:     
            if isinstance(obj2, Relationship): #If they are relationships we dont care
                continue

            #Create memory store object for each stix obj because that's what their comparison functions use
            ms1 = MemoryStore(obj)
            ms2 = MemoryStore(obj2)

            #Declare prop store dict for sim functions
            prop_scores = {} 

            #Try to run the sim function on the objs
            try: 
                sim_score = env.object_similarity(ms1.query()[0], ms2.query()[0], prop_scores, ds1=None, ds2=None, ignore_spec_version=False, versioning_checks=False, max_depth=1, **weight_dict)
                totalComp += 1
                sim_score = round(sim_score)
            except Exception as e: 
                #print(str(e))
                continue
            
            #If the objects are the same, add it to the dict indexed by the score
            if sim_score >= 70:
                counter += 1
                if sim_score in same_obj_list:
                    same_obj_list[sim_score].append(ms1.query()[0])
                    same_obj_list[sim_score].append(ms2.query()[0])    
                else: 
                    same_obj_list[sim_score] = []
                    same_obj_list[sim_score].append(ms1.query()[0])
                    same_obj_list[sim_score].append(ms2.query()[0])
    # for obj in same_obj_list[100]: Deduping code here -- this only works for certain nodes in the list i.e. ones that have a name property. When the code is cleaned up this functinality should be added
    #     #print(obj)
    #     for obj2 in same_obj_list[100]:
    #         if obj.name == obj2.name and obj.id != obj2.id:
    #             same_obj_list.remove(obj2)
    print(f"Objects successfuly analyed and added to a list:")
    print(same_obj_list)
    print(f"Ignoring relationships, the percentage of similar nodes in the graph is {counter / totalComp}")
    return same_obj_list, counter / totalComp * 100

def generate_object_comparison_matrix(path_to_json_bundle): 
    stixList = json_to_stixList(path_to_json_bundle) 
    env = Environment(store=MemoryStore())
    weight_dict = variables.WEIGHTS
    comparisons = []
    objects = []
    i = 0

    for obj in stixList:
        if isinstance(obj, Relationship):
            continue
        objects.append(obj)
        comparisons[i] = []
        for obj2 in stixList:     
            if isinstance(obj2, Relationship): 
                continue
            
            #Create memory store object for each stix obj because that's what their comparison functions use
            ms1 = MemoryStore(obj)
            ms2 = MemoryStore(obj2)

            #Declare prop store dict for sim functions
            prop_scores = {} 

            #Try to run the sim function on the objs
            try: 
                comparisons[i].append(sim_score = env.object_similarity(ms1.query()[0], ms2.query()[0], prop_scores, ds1=None, ds2=None, ignore_spec_version=False, versioning_checks=False, max_depth=1, **weight_dict))
                i += 1
            except Exception as e: 
                #print(str(e))
                continue

    return objects, comparisons