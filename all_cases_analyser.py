from cmath import sqrt
import csv
import math
from re import A
import numpy as np
from numpy import loadtxt
import os
from matplotlib import pyplot as plt
from datetime import datetime
from all_cases_analyser import *
from configAH import get_labeling_of_case

# Function for per value per node array (with 5 cases per node)
def return_cases_split_by_node(highest_case, array):

    #This case: 5 nodes, with following percentages:
    percentages = [0.2, 0.4, 0.6, 0.8, 1]

    #Defensive Programming do not allow this if cases != 25
    if(not highest_case == 25):
        print("Problem: we don't have 25 cases, adjust the code please!")
        return
    else:
        all_healthy = array[0]
        artifical_array_healthy = [all_healthy, all_healthy, all_healthy, all_healthy, all_healthy]
        value_one_node = array[1:6]
        value_two_nodes = array[6:11]
        value_three_nodes = array[11:16]
        value_four_nodes = array[16:21]
        value_five_nodes = array[21:26]
        return_array = [artifical_array_healthy, value_one_node, value_two_nodes, value_three_nodes, value_four_nodes, value_five_nodes]

        return return_array, percentages


# Function for after all cases ran through to create the the overview of everything
def all_cases_analysis(folder_for_csv, highest_case, update_rounds,n_nodes):
    
    ####################
    #These are graphs of loss, accuracy, weights min/max/last value between cases
    ####################

    ###### Maximum Accuracy ######

    # Create File Path & Array for accuracy
    accuracy_csv = os.path.join(folder_for_csv, 'accuracy.csv')

    with open(accuracy_csv, 'r') as csv:
        all_accuracys = loadtxt(csv ,delimiter = ",")
        csv.close()

    # Hardcode for 25 cases the data for the different nodes
    accuracy_array, percentages = return_cases_split_by_node(highest_case, all_accuracys)
    
    # Plot maximum Accuracy
    accuracy_graph = os.path.join(folder_for_csv, 'accuracys_graph_cases')
    # here I want to split by 5, always 5 datas at once!
    for i in range(0, n_nodes + 1):
        #this_label = str(i) + " nodes malicious" OLD
        this_label = str(round((i/n_nodes)*100, 0)) + "% of nodes malicious" 
        plt.plot(percentages, accuracy_array[i], label = this_label)
    plt.suptitle("Maximum accuracy in FL system", fontsize = 'large')
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 'medium')
    plt.xlabel("Percentage of Malicious Data")
    plt.ylabel("Accuracy")
    plt.legend(loc = "best")
    plt.grid(axis="y", linewidth=0.5)
    plt.savefig(accuracy_graph)
    plt.clf() # flushes plt

    ###### Minimum Loss ######

    # Create File Path & Array for loss
    loss_csv = os.path.join(folder_for_csv, 'loss.csv')

    with open(loss_csv, 'r') as csv:
        all_losses = loadtxt(csv ,delimiter = ",")
        csv.close()

    # Hardcode for 25 cases the data for the different nodes
    loss_array, percentages = return_cases_split_by_node(highest_case, all_losses)
    
    # Plot minimum Loss
    loss_graph = os.path.join(folder_for_csv, 'loss_graph_cases')
    # here I want to split by 5, always 5 datas at once!
    for i in range(0, n_nodes + 1):
        #this_label = str(i) + " nodes malicious" OLD
        this_label = str(round((i/n_nodes)*100, 0)) + "% of nodes malicious" 
        plt.plot(percentages, loss_array[i], label = this_label)
    plt.suptitle("Minimum loss in FL system", fontsize = 'large')
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 'medium')
    plt.xlabel("Percentage of Malicious Data")
    plt.ylabel("Loss")
    plt.legend(loc = "best")
    plt.grid(axis="y", linewidth=0.5)
    plt.savefig(loss_graph)
    plt.clf() # flushes plt

    ###### Last Accuracy ######

    # Create File Path & Array for accuracy
    last_accuracy_csv = os.path.join(folder_for_csv, 'last_accuracy.csv')

    with open(last_accuracy_csv, 'r') as csv:
        last_all_accuracys = loadtxt(csv ,delimiter = ",")
        csv.close()

    # Hardcode for 25 cases the data for the different nodes
    last_accuracy_array, percentages = return_cases_split_by_node(highest_case, last_all_accuracys)
    
    # Plot maximum Accuracy
    last_accuracy_graph = os.path.join(folder_for_csv, 'last_accuracys_graph_cases')
    # here I want to split by 5, always 5 datas at once!
    for i in range(0, n_nodes + 1):
        #this_label = str(i) + " nodes malicious" OLD
        this_label = str(round((i/n_nodes)*100, 0)) + "% of nodes malicious" 
        plt.plot(percentages, last_accuracy_array[i], label = this_label)
    plt.suptitle("Last round accuracy in FL system", fontsize = 'large')
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 'medium')
    plt.xlabel("Percentage of Malicious Data")
    plt.ylabel("Accuracy")
    plt.legend(loc = "best")
    plt.grid(axis="y", linewidth=0.5)
    plt.savefig(last_accuracy_graph)
    plt.clf() # flushes plt


     ###### Last Loss ######

    # Create File Path & Array for loss
    last_loss_csv = os.path.join(folder_for_csv, 'last_loss.csv')

    with open(last_loss_csv, 'r') as csv:
        all_last_losses = loadtxt(csv ,delimiter = ",")
        csv.close()

    # Hardcode for 25 cases the data for the different nodes
    last_loss_array, percentages = return_cases_split_by_node(highest_case, all_last_losses)
    
    # Plot last Loss
    last_loss_graph = os.path.join(folder_for_csv, 'last_loss_graph_cases')
    # here I want to split by 5, always 5 datas at once!
    for i in range(0, n_nodes + 1):
        this_label = str(round((i/n_nodes)*100, 0)) + "% of nodes malicious" 
        #this_label = str(i) + " nodes malicious" OLD
        plt.plot(percentages, last_loss_array[i], label = this_label)
    plt.suptitle("Last round loss in FL system", fontsize = 'large')
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 'medium')
    plt.xlabel("Percentage of Malicious Data")
    plt.ylabel("Loss")
    plt.legend(loc = "best")
    plt.grid(axis="y", linewidth=0.5)
    plt.savefig(last_loss_graph)
    plt.clf() # flushes plt


    ###### Weight ######

    # Create File Path & Array for loss
    last_av_weight_csv = os.path.join(folder_for_csv, 'last_average_weight.csv')

    with open(last_av_weight_csv, 'r') as csv:
        all_last_av_weights = loadtxt(csv ,delimiter = ",")
        csv.close()

    # Hardcode for 25 cases the data for the different nodes
    last_av_weights_array, percentages = return_cases_split_by_node(highest_case, all_last_av_weights)
    
    # Plot weights
    av_weight_graph = os.path.join(folder_for_csv, 'avg_weight_graph')
    # here I want to split by 5, always 5 datas at once!
    for i in range(0, n_nodes + 1):
        this_label = str(round((i/n_nodes)*100, 0)) + "% of nodes malicious" 
        #this_label = str(i) + " nodes malicious" OLD
        plt.plot(percentages, last_av_weights_array[i], label = this_label)
    plt.suptitle("Average Weight in FL system", fontsize = 'large')
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 'medium')
    plt.xlabel("Percentage of Malicious Data")
    plt.ylabel("Average Weight")
    plt.legend(loc = "best")
    plt.grid(axis="y", linewidth=0.5)
    plt.savefig(av_weight_graph)
    plt.clf() # flushes plt


    ####################
    #These are graphs of loss, accuracy, weights min/max/last value between cases across time!
    ####################

    ##### These are weights for all cases! #### 

    # Read data for weights
    weights_csv = os.path.join(folder_for_csv, 'weights.csv')

    with open(weights_csv, 'r') as csv:
        all_weights = loadtxt(csv ,delimiter = ",")
        csv.close()

    # Create Graph for weights
    weights_graphs = os.path.join(folder_for_csv, 'weights_graph_cases')
    
    for i in range(0, len(all_weights)):
        case_label = get_labeling_of_case(i)
        #this_label = "Case " + str(i) + ": " + case_label
        plt.plot(all_weights[i], label = case_label)
    plt.xlabel("Percentage of Malicious Data")
    plt.ylabel("Average Model Parameter")
    lgd = plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05), fancybox=True, shadow=True, ncol=3)
    plt.grid(axis="y", linewidth=0.5)
    plt.savefig(weights_graphs, bbox_extra_artists=(lgd, ), bbox_inches='tight')
    plt.clf() # flushes plt

    ### Now choose cases from all_weights: ###

    # *** Comparing all 100% malicious datas ***
    cases_we_want_to_show = [0, 5, 10, 15, 20, 25]

    # Create Graph for weights
    weights_graphs = os.path.join(folder_for_csv, 'weights_dev_graph_(100%)cases')
    for element in cases_we_want_to_show:
        case_label = get_labeling_of_case(element)
        #this_label = "Case " + str(element) + ": " + case_label
        plt.plot(all_weights[element], label = case_label)
    plt.xlabel("Update Rounds")
    plt.ylabel("Average Model Parameter")
    lgd = plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05), fancybox=True, shadow=True, ncol=3)
    plt.grid(axis="y", linewidth=0.5)
    plt.savefig(weights_graphs, bbox_extra_artists=(lgd,), bbox_inches='tight')
    plt.clf() # flushes plt

    # *** comparing all 80% malicious data ***
    cases_we_want_to_show = [0, 4, 9, 14, 19, 24]

    # Create Graph for weights
    weights_graphs = os.path.join(folder_for_csv, 'weights_dev_graph_(80%)cases')
    for element in cases_we_want_to_show:
        case_label = get_labeling_of_case(element)
        #this_label = "Case " + str(element) + ": " + case_label
        plt.plot(all_weights[element], label = case_label)
    plt.xlabel("Update Rounds")
    plt.ylabel("Average Model Parameter")
    lgd = plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05), fancybox=True, shadow=True, ncol=3)
    plt.grid(axis="y", linewidth=0.5)
    plt.savefig(weights_graphs, bbox_extra_artists=(lgd,), bbox_inches='tight')
    plt.clf() # flushes plt

    # *** comparing cases with 2 malicious nodes with all different %s of malicious data ***
    cases_we_want_to_show = [0, 6, 7, 8, 9, 10]

    # Create Graph for weights
    weights_graphs = os.path.join(folder_for_csv, 'weights_dev_graph_(2_nodes_malicious)cases')
    for element in cases_we_want_to_show:
        case_label = get_labeling_of_case(element)
        #this_label = "Case " + str(element) + ": " + case_label
        plt.plot(all_weights[element], label = case_label)
    plt.xlabel("Update Rounds")
    plt.ylabel("Average Model Parameter")
    lgd = plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05), fancybox=True, shadow=True, ncol=3)
    plt.grid(axis="y", linewidth=0.5)
    plt.savefig(weights_graphs, bbox_extra_artists=(lgd,), bbox_inches='tight')
    plt.clf() # flushes plt

    #******
    # Kins Graph, comparing same node in multple cases // THIS IS MANUAL!
    #******
    
    node_weights_csv = os.path.join(folder_for_csv, 'weights_per_node.csv')

    with open(node_weights_csv, 'r') as csv:
        all_nodes_weights = loadtxt(csv ,delimiter = ",")
        csv.close()

    # *** comparing Node number 5 (which is malicious) in case 1-5 and healthy in case 0 --- compare the weights of it! ***
    cases_we_want_to_show = [0, 4, 5]
    label_cases_we_want_to_show = ["Node 5 healthy", "Node 5 malicious (80%)", "Node 5 malicious (100%)"]
    node_we_want_to_show = 4 #node 5 is malicious

    case = [value * n_nodes for value in cases_we_want_to_show]
    # as all nodes are written underneath each other, fast forward 
    array_in_2d_list_show = [value * n_nodes for value in cases_we_want_to_show]
    array_node_5_2d_list_show = [value + node_we_want_to_show for value in array_in_2d_list_show]

    print("these are the two weights we are showing, the numbers", array_node_5_2d_list_show)

    # Create Folder
    weights_per_node_graphs = os.path.join(folder_for_csv, 'weights_node_5_malicious_not_malicious_szenario')

    # Create Graph for weights
    for i in range(0, len(cases_we_want_to_show)): # this is still labeling!
        case_label = label_cases_we_want_to_show[i]
        #this_label = "Case " + str(element) + ": " + case_label
        plt.plot(all_nodes_weights[i], label = case_label)
    plt.xlabel("Update Rounds")
    plt.ylabel("Average Model Parameter")
    lgd = plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05), fancybox=True, shadow=True, ncol=3)
    plt.grid(axis="y", linewidth=0.5)
    plt.savefig(weights_per_node_graphs, bbox_extra_artists=(lgd,), bbox_inches='tight')
    plt.clf() # flushes plt



    

    return



# PYTHON MAIN!!
if __name__ == "__main__":
    highest_case = 25
    current_directory = os. getcwd() 
    day_time = (datetime.today().strftime('%Y-%m-%d') + ': ' + str(highest_case) +' cases/')
    folder_for_csv = os.path.join(current_directory, 'analysis_results/' + day_time)
    rounds = 250
    n_nodes = 5
    #path = '/Users/Anso/Code/Imperial_College/IndividualProject/adaptive-federated-learning/analysis_results/2022-07-12: 25 cases/'
    path = '/Users/Anso/Code/Imperial_College/IndividualProject/adaptive-federated-learning/analysis_results/2022-07-18: 25 cases -- 2 -CASENUM 0/overall_analysis'
    all_cases_analysis(path, highest_case, rounds, n_nodes)