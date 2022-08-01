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
from configAH import get_labeling_of_case, list_percentages_data_cases, list_percentages_node_cases, highest_case, percentage_round_where_clients_turn_malicious, percentage_round_where_clients_turn_healthy_again

# Function for per value per node array (with 5 cases per node)
def return_cases_split_by_node(input_highest_case, array, n_nodes):

    #This case: 5 nodes, with following percentages:
    number_cases_different_mali_data = len(list_percentages_data_cases)
    number_cases_different_mali_nodes = len(list_percentages_node_cases)
    given_highest_case = highest_case

    #percentages_for_graphs = list_percentages_data_cases[1:number_cases_different_mali_data]

    #Defensive Programming do not allow this if cases != 25
    if(not input_highest_case == given_highest_case):
        print("Problem: we don't have 25 cases, adjust the code please!")
        return
    else:
        #make for loop, which is flexible in how many arrays it needs depending on the the number of nodes given! Therefore, input n_nodes and then take the length for it!
        # all_healthy is always one case!
        all_healthy = array[0]
        artifical_array_healthy = [all_healthy, all_healthy, all_healthy, all_healthy, all_healthy]

        return_array = [artifical_array_healthy]
        row_to_insert = 1
        for i in range(1, number_cases_different_mali_nodes):
            row_until = row_to_insert + number_cases_different_mali_data
            value = array[row_to_insert:row_until]
            row_to_insert = row_until
            return_array.append(value)

        return return_array

# Function for after all cases ran through to create the the overview of everything
def all_cases_analysis(folder_for_csv, highest_case, update_rounds,n_nodes):

    number_cases_different_no_mali_nodes = len(list_percentages_node_cases)
    this_list_percentages_data_cases = list_percentages_data_cases # from config

    #-----------------------------------------------------------------------#
    #These are graphs of loss, accuracy, weights min/max/last value between cases

    ############ Maximum Accuracy ############

    # Load Data & create Array for accuracy
    accuracy_csv = os.path.join(folder_for_csv, 'max_accuracy.csv')

    with open(accuracy_csv, 'r') as csv:
        all_accuracys = loadtxt(csv ,delimiter = ",")
        csv.close()

    # Assign for 25 cases (HARDCODED) the data to the different nodes
    accuracy_array = return_cases_split_by_node(highest_case, all_accuracys, n_nodes)
    
    # Create path for Graph 
    max_accuracy_graph = os.path.join(folder_for_csv, 'max_accuracy_all_cases')
    
    # Plot maximum Accuracy
    # here I want to split by 5, always 5 datas at once!
    for i in range(0, number_cases_different_no_mali_nodes):
        this_label = str(round((i/n_nodes)*100, 0)) + "%" 
        plt.plot(this_list_percentages_data_cases, accuracy_array[i], "-o",label = this_label)
        #TITLE
    plt.suptitle("Maximum accuracy in FL system", fontsize = 18, fontweight="bold")
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 16)
        #LABLE
    plt.xlabel("Share of Malicious Data (in %)", fontsize = 14)
    plt.ylabel("Accuracy", fontsize = 14)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
        #LEGEND
    plt.legend(title='% of malicious nodes',title_fontsize=16,loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":14}, frameon = False)
        #ADJUST GENERAL
    plt.subplots_adjust(top=0.85)
    plt.savefig(max_accuracy_graph, bbox_inches='tight',pad_inches=0.1)

    plt.clf() # flushes plt

    ############ Minimum Loss ############

    # Load Data & create Array for Loss
    loss_csv = os.path.join(folder_for_csv, 'min_loss.csv')

    with open(loss_csv, 'r') as csv:
        all_losses = loadtxt(csv ,delimiter = ",")
        csv.close()

    # Assign for 25 cases (HARDCODED) the data to the different nodes
    loss_array = return_cases_split_by_node(highest_case, all_losses, n_nodes)
    
    # Create path for Graph 
    min_loss_graph = os.path.join(folder_for_csv, 'min_loss_all_cases')
    
    # Plot minimum Loss
    # here I want to split by 5, always 5 datas at once!
    for i in range(0, number_cases_different_no_mali_nodes):
        #this_label = str(i) + " nodes malicious" OLD
        this_label = str(round((i/n_nodes)*100, 0)) + "%" 
        plt.plot(this_list_percentages_data_cases, loss_array[i], '-o',label = this_label)
        #TITLE
    plt.suptitle("Minimum loss in FL system", fontsize = 18, fontweight="bold")
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 16)
        #LABEL
    plt.xlabel("Share of Malicious Data (in %)", fontsize = 14)
    plt.ylabel("Loss", fontsize = 14)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
        #LEGEND
    plt.legend(title='% of malicious nodes',title_fontsize=16,loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":14}, frameon = False)
        #ADJUST GENERAL
    plt.subplots_adjust(top=0.85)
    plt.savefig(min_loss_graph, bbox_inches='tight',pad_inches=0.1)
    plt.clf() # flushes plt

    ############ Last Accuracy ############

    # Load Data & create Array for accuracy
    last_accuracy_csv = os.path.join(folder_for_csv, 'last_accuracy.csv')

    with open(last_accuracy_csv, 'r') as csv:
        last_all_accuracys = loadtxt(csv ,delimiter = ",")
        csv.close()

    # Assign for 25 cases (HARDCODED) the data to the different nodes
    last_accuracy_array = return_cases_split_by_node(highest_case, last_all_accuracys, n_nodes)
    
    # Create path for Graph 
    last_accuracy_graph = os.path.join(folder_for_csv, 'last_accuracy_all_cases')

    # Plot maximum Accuracy
    # here I want to split by 5, always 5 datas at once!
    for i in range(0, number_cases_different_no_mali_nodes):
        #this_label = str(i) + " nodes malicious" OLD
        this_label = str(round((i/n_nodes)*100, 0)) + "%" 
        plt.plot(this_list_percentages_data_cases, last_accuracy_array[i], '-o', label = this_label)
        #TITLE
    plt.suptitle("Last round accuracy in FL system", fontsize = 18, fontweight = "bold")
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 16)
        #LABELS
    plt.xlabel("Share of Malicious Data (in %)", fontsize = 14)
    plt.ylabel("Accuracy", fontsize = 14)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
        #LEGEND
    plt.legend(title='% of malicious nodes',title_fontsize=16,loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":14}, frameon = False)
        #ADJUST GENERAL
    plt.subplots_adjust(top=0.85)
    plt.savefig(last_accuracy_graph, bbox_inches='tight',pad_inches=0.1)
    plt.clf() # flushes plt


     ############ Last Loss ############

    # Load Data & create Array for loss
    last_loss_csv = os.path.join(folder_for_csv, 'last_loss.csv')
    with open(last_loss_csv, 'r') as csv:
        all_last_losses = loadtxt(csv ,delimiter = ",")
        csv.close()

    # Assign for 25 cases (HARDCODED) the data to the different nodes
    last_loss_array = return_cases_split_by_node(highest_case, all_last_losses, n_nodes)
    
    # Create path for Graph 
    last_loss_graph = os.path.join(folder_for_csv, 'last_loss_all_cases')
    
    # Plot last Loss
    # here I want to split by 5, always 5 datas at once!
    for i in range(0, number_cases_different_no_mali_nodes):
        this_label = str(round((i/n_nodes)*100, 0)) + "%" 
        #this_label = str(i) + " nodes malicious" OLD
        plt.plot(this_list_percentages_data_cases, last_loss_array[i], '-o', label = this_label)
        #TITLE
    plt.suptitle("Last round loss in FL system", fontsize = 18, fontweight = "bold")
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 16)
        #LABEL
    plt.xlabel("Share of Malicious Data (in %)", fontsize = 14)
    plt.ylabel("Loss", fontsize = 14)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
        #LEGEND
    plt.legend(title='% of malicious nodes',title_fontsize=16,loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":14}, frameon = False)
        #GENERAL
    plt.subplots_adjust(top=0.85)
    plt.savefig(last_loss_graph, bbox_inches='tight',pad_inches=0.1)

    plt.clf() # flushes plt


    ############ Weight ############

    # ***
    # Calculate temporary 
    round_turning_malicious = int(percentage_round_where_clients_turn_malicious * update_rounds)
    round_turning_healthy_again = int(percentage_round_where_clients_turn_healthy_again * update_rounds) 


    # Load Data & create Array for weight
    last_av_weight_csv = os.path.join(folder_for_csv, 'last_average_model_param.csv')

    with open(last_av_weight_csv, 'r') as csv:
        all_last_av_weights = loadtxt(csv ,delimiter = ",")
        csv.close()

    # Assign for 25 cases (HARDCODED) the data to the different nodes
    last_av_weights_array = return_cases_split_by_node(highest_case, all_last_av_weights, n_nodes)
    
    # Create path for Graph 
    av_weight_graph = os.path.join(folder_for_csv, 'last_avg_model_param_all_cases')
    
    #PLOT GRAPH 
        #LINES
    # here I want to split by 5, always 5 datas at once!
    for i in range(0, number_cases_different_no_mali_nodes):
        this_label = str(round((i/n_nodes)*100, 0)) + "%" 
        plt.plot(this_list_percentages_data_cases, last_av_weights_array[i], label = this_label)
    # Show temporary maliciousness as lines!
    if(round_turning_malicious != 0 and round_turning_malicious != -1):
        label_line ='malicious node starts to be malicious'
        plt.axvline(x = round_turning_malicious, label=label_line, color = 'black')
    if(round_turning_healthy_again != update_rounds and round_turning_healthy_again != -1):
        label_line ='malicious node turns healthy again'
        plt.axvline(x = round_turning_healthy_again, label=label_line, color = 'grey')
        #TITLE
    plt.suptitle("Average Model Parameter (in last round) in FL system", fontsize = 18, fontweight = "bold")
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 16)
        #LABLE
    plt.xlabel("Share of Malicious Data (in %)", fontsize = 14)
    plt.ylabel("Average Model Parameter", fontsize = 14)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
        #LEGEND
    plt.legend(title='% of malicious nodes',title_fontsize=16,loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":14}, frameon = False)
        #GENERAL
    plt.subplots_adjust(top=0.85)
    plt.savefig(av_weight_graph, bbox_inches='tight',pad_inches=0.1)

    plt.clf() # flushes plt


    #-----------------------------------------------------------------------#
    #These are graphs of loss, accuracy, weights min/max/last value between cases across time!

    ############ These are weights for all cases! ############ 

    # Read data for weights
    weights_csv = os.path.join(folder_for_csv, 'average_global_model_param_dev.csv')

    with open(weights_csv, 'r') as csv:
        all_weights = loadtxt(csv ,delimiter = ",")
        csv.close()

    # ******** Comparing all Cases ***********

    # Create Path for Graph
    weights_graphs = os.path.join(folder_for_csv,'model_param_rounds_all_cases')
    
    # Create Graph for weights
        #PLOTS
    for i in range(0, len(all_weights)):
        case_label = get_labeling_of_case(i)
        plt.plot(all_weights[i], label = case_label)
        # Show temporary maliciousness as lines!
    if(round_turning_malicious != 0 and round_turning_malicious != -1):
        label_line ='malicious node starts to be malicious'
        plt.axvline(x = round_turning_malicious, label=label_line, color = 'black')
    if(round_turning_healthy_again != update_rounds and round_turning_healthy_again != -1):
        label_line ='malicious node turns healthy again'
        plt.axvline(x = round_turning_healthy_again, label=label_line, color = 'grey')
        #TITLE
    plt.suptitle("Average Model Parameter in FL system", fontsize = 18, fontweight = "bold")
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 16)
        #LABLE
    plt.xlabel("Update Rounds", fontsize = 14)
    plt.ylabel("Average Model Parameter", fontsize = 14)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
        #LEGEND
    plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.15), prop={"size":14}, frameon = False, ncol=3, title='Cases', title_fontsize=16)
    #plt.legend(title='malicious nodes',title_fontsize=16,loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":14}, frameon = False)
        #GENERAL
    plt.subplots_adjust(top=0.85)
    plt.savefig(weights_graphs, bbox_inches='tight',pad_inches=0.1)
    plt.clf() # flushes plt

    ############ Now choose cases from all_weights: ############

    # ******** Comparing all 100% malicious datas ***********
    cases_we_want_to_show = [0, 5, 10, 15, 20, 25]
    #Use same data as before

    # Create Graph for weights
    weights_graphs_1 = os.path.join(folder_for_csv, 'model_param_rounds_(100%_mal_data)_cases')
        #LINES
    for element in cases_we_want_to_show:
        case_label = get_labeling_of_case(element)
        #this_label = "Case " + str(element) + ": " + case_label
        plt.plot(all_weights[element], label = case_label)
        # Show temporary maliciousness as lines!
    if(round_turning_malicious != 0 and round_turning_malicious != -1):
        label_line ='malicious node starts to be malicious'
        plt.axvline(x = round_turning_malicious, label=label_line, color = 'black')
    if(round_turning_healthy_again != update_rounds and round_turning_healthy_again != -1):
        label_line ='malicious node turns healthy again'
        plt.axvline(x = round_turning_healthy_again, label=label_line, color = 'grey')
        #TITLE
    plt.suptitle("Average Model Parameter in FL system", fontsize = 18, fontweight = "bold")
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 16)
        #LABEL
    plt.xlabel("Update Rounds", fontsize = 14)
    plt.ylabel("Average Model Parameter", fontsize = 14)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
        #LEGEND
    plt.legend(loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":14}, frameon = False, title='Cases', title_fontsize=16)
        #GENERAL
    plt.subplots_adjust(top=0.85)
    plt.savefig(weights_graphs_1, bbox_inches='tight',pad_inches=0.1)
    plt.clf() # flushes plt

    # ******** comparing all 80% malicious data ********
    cases_we_want_to_show = [0, 4, 9, 14, 19, 24]
    #Use same data as before

    # Create Graph for weights
    weights_graphs_2 = os.path.join(folder_for_csv, 'model_param_rounds_(80%_mal_data)_cases')
        #LINES
    for element in cases_we_want_to_show:
        case_label = get_labeling_of_case(element)
        #this_label = "Case " + str(element) + ": " + case_label
        plt.plot(all_weights[element], label = case_label)
        # Show temporary maliciousness as lines!
    if(round_turning_malicious != 0 and round_turning_malicious != -1):
        label_line ='malicious node starts to be malicious'
        plt.axvline(x = round_turning_malicious, label=label_line, color = 'black')
    if(round_turning_healthy_again != update_rounds and round_turning_healthy_again != -1):
        label_line ='malicious node turns healthy again'
        plt.axvline(x = round_turning_healthy_again, label=label_line, color = 'grey')
        #TITLE
    plt.suptitle("Average Model Parameter in FL system", fontsize = 18, fontweight = "bold")
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 16)
        #LABEL
    plt.xlabel("Update Rounds", fontsize = 14)
    plt.ylabel("Average Model Parameter", fontsize = 14)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
        #LEGEND
    plt.legend(loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":14}, frameon = False, title='Cases', title_fontsize=16)
        #GENERAL
    plt.subplots_adjust(top=0.85)
    plt.savefig(weights_graphs_2, bbox_inches='tight',pad_inches=0.1)
    plt.clf() # flushes plt

    # ******** comparing cases with 2 malicious nodes with all different %s of malicious data ********
    cases_we_want_to_show = [0, 6, 7, 8, 9, 10]
    #Use same data as before

    # Create Graph for weights
    weights_graphs_3 = os.path.join(folder_for_csv, 'model_param_rounds_(2_mal_nodes)_cases')
        #LINES
    for element in cases_we_want_to_show:
        case_label = get_labeling_of_case(element)
        #this_label = "Case " + str(element) + ": " + case_label
        plt.plot(all_weights[element], label = case_label)
        # Show temporary maliciousness as lines!
    if(round_turning_malicious != 0 and round_turning_malicious != -1):
        label_line ='malicious node starts to be malicious'
        plt.axvline(x = round_turning_malicious, label=label_line, color = 'black')
    if(round_turning_healthy_again != update_rounds and round_turning_healthy_again != -1):
        label_line ='malicious node turns healthy again'
        plt.axvline(x = round_turning_healthy_again, label=label_line, color = 'grey')
        #TITLE
    plt.suptitle("Average Model Parameter in FL system", fontsize = 18, fontweight = "bold")
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 16)
        #LABEL
    plt.xlabel("Update Rounds", fontsize = 14)
    plt.ylabel("Average Model Parameter", fontsize = 14)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
        #LEGEND
    plt.legend(loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":14}, frameon = False, title='Cases', title_fontsize=16)
        #GENERAL
    plt.subplots_adjust(top=0.85)
    plt.savefig(weights_graphs_3, bbox_inches='tight',pad_inches=0.1)
    plt.clf() # flushes plt

    #-----------------------------------------------------------------------#
    # Kins Graph, comparing same node in multple cases // THIS IS HARDCODED!
    
    node_weights_csv = os.path.join(folder_for_csv, 'average_model_param_per_node_dev.csv')

    with open(node_weights_csv, 'r') as csv:
        all_nodes_weights = loadtxt(csv ,delimiter = ",")
        csv.close()

    # *********** comparing Node number 5 (which is malicious) in case 1-5 and healthy in case 0 --- compare the weights of it! #***********

    cases_we_want_to_show = [0, 4, 5]
    label_cases_we_want_to_show = ["Node 5 healthy", "Node 5 malicious (80%)", "Node 5 malicious (100%)"]
    node_we_want_to_show = n_nodes - 1 #last node is malicious

    case = [value * n_nodes for value in cases_we_want_to_show]
    # as all nodes are written underneath each other, fast forward 
    array_in_2d_list_show = [value * n_nodes for value in cases_we_want_to_show]
    array_node_5_2d_list_show = [value + node_we_want_to_show for value in array_in_2d_list_show]

    print("these are the two weights we are showing, the numbers", array_node_5_2d_list_show)

    # Create Folder
    weights_per_node_graphs = os.path.join(folder_for_csv, 'model_param_node_5_malicious_vs_healthy_state')

    # Create Graph for weights
        #LINES
    for i in range(0, len(cases_we_want_to_show)): # this is still labeling!
        case_label = label_cases_we_want_to_show[i]
        #this_label = "Case " + str(element) + ": " + case_label
        plt.plot(all_nodes_weights[i], label = case_label)
        #TITLE
    plt.suptitle("Average Model Parameter of node \n in healthy and malicious state", fontsize = 18, fontweight = "bold")
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 16)
        #LABEL
    plt.xlabel("Update Rounds", fontsize = 14)
    plt.ylabel("Average Model Parameter", fontsize = 14)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
        #LEGEND
    plt.legend(loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":14}, frameon = False, title='Cases', title_fontsize=16)
        #GENERAL
    plt.subplots_adjust(top=0.8)
    plt.savefig(weights_per_node_graphs, bbox_inches='tight',pad_inches=0.1)
    plt.clf() # flushes plt

    #*********** Moving Average of 10! ***********
    average_out_of = 10

    #create moving average:
    #Take out rows we want to print:
    mov_ave_weights_all_nodes = np.zeros((n_nodes, update_rounds))

    #Make moving average depending on value (if there are 10 values available)
    for j in range(0, n_nodes):
        for i in range(0, update_rounds):
            if (i < average_out_of - 1):
                sum = 0
                for k in range(0, i+1):
                    sum += all_nodes_weights[j][k]
                div_by = i+1
                sum /= div_by
                mov_ave_weights_all_nodes[j][i] = sum
            else:
                sum = 0
                for k in range(i + 1 - average_out_of, i+1):
                    sum += all_nodes_weights[j][k]
                sum /= average_out_of
                mov_ave_weights_all_nodes[j][i] = sum

    # Create Path to Graph 
    weights_per_node_graphs = os.path.join(folder_for_csv, 'moving_average_model_param_node_5_malicious_vs_healthy_state')

    # Create Graph for weights
        #LINES
    for i in range(0, len(cases_we_want_to_show)): # this is still labeling!
        case_label = label_cases_we_want_to_show[i]
        #this_label = "Case " + str(element) + ": " + case_label
        plt.plot(mov_ave_weights_all_nodes[i], label = case_label)
        #TITLE
    plt.suptitle("Moving Average (10 values) Model Parameter of node \n in healthy and malicious state", fontsize = 18, fontweight = "bold")
    title =  str(n_nodes) + " nodes, " + str(update_rounds) + " update rounds"
    plt.title(title, fontsize = 16)
        #LABEL
    plt.xlabel("Update Rounds", fontsize = 14)
    plt.ylabel("Average Model Parameter", fontsize = 14)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
        #LEGEND
    plt.legend(loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":14}, frameon = False, title='Cases', title_fontsize=16)
        #GENERAL
    plt.subplots_adjust(top=0.8)
    plt.savefig(weights_per_node_graphs, bbox_inches='tight',pad_inches=0.1)
    plt.clf() # flushes plt

    return


# PYTHON MAIN!!
if __name__ == "__main__":
    highest_case = 25
    current_directory = os. getcwd() 
    day_time = (datetime.today().strftime('%Y-%m-%d') + ': ' + str(highest_case) +' cases/')
    folder_for_csv = os.path.join(current_directory, 'analysis_results/' + day_time)
    rounds = 200
    n_nodes = 5
    #path = '/Users/Anso/Code/Imperial_College/IndividualProject/adaptive-federated-learning/analysis_results/2022-07-12: 25 cases/'
    path = '/Users/Anso/Code/Imperial_College/IndividualProject/adaptive-federated-learning/analysis_results/2022-07-18: 25 cases -- 2 -CASENUM 0/overall_analysis'
    path_10_nodes = '/Users/Anso/Code/Imperial_College/IndividualProject/adaptive-federated-learning/analysis_results/2022-07-19: 25 cases -- 1/overall_analysis'
    pathy_nodes = '/Users/Anso/Code/Imperial_College/IndividualProject/adaptive-federated-learning/analysis_results/2022-07-30: 25 cases -- malicious round 75-120/overall_analysis'
    all_cases_analysis(pathy_nodes, highest_case, rounds, n_nodes)