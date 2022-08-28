from cmath import sqrt
import csv
import math
from re import T
import numpy as np
from numpy import loadtxt
import os
from matplotlib import pyplot as plt
from datetime import datetime, time
from all_cases_analyser import *
import time
from config import storing_type, moving_average_of, percentage_of_weights_concidered_lim_case
import textwrap

class Analayser:
    def __init__(self, n_nodes, number_of_parameters, max_rounds, case, number_of_malicious_nodes, percentage_malicious_data, total_run_through, highest_case, which_node_malicious_array, round_turning_malicious, round_turning_healthy_again):

        # general parameters
        self.number_of_parameters = number_of_parameters
        self.number_of_nodes = n_nodes
        self.max_rounds = max_rounds
        self.highest_case = highest_case #used to trigger final analysis!

        # Param related to malicious case 
        self.case = case
        self.number_of_malicious_nodes = number_of_malicious_nodes
        self.percentage_of_malicious_nodes = round((self.number_of_malicious_nodes/self.number_of_nodes), 2)*100
        self.percentage_malicious_data = percentage_malicious_data
        self.total_run_through = total_run_through
        self.which_node_malicious_array = which_node_malicious_array
        self.round_turning_malicious = round_turning_malicious
        self.round_turning_healthy_again = round_turning_healthy_again

        # Capturing Global Parameters
        self.global_weight = np.zeros((max_rounds, number_of_parameters))
        self.global_aggregated_weight = np.zeros((max_rounds))

        # Capturing node Parameters
        self.weights = np.zeros((n_nodes, max_rounds, number_of_parameters))
        self.aggregated_weights = np.zeros((n_nodes, max_rounds))
        
        # Analysis arrays
        self.mean_weight_per_round = np.zeros((max_rounds))
        self.std_per_round = np.zeros((max_rounds))
        
        # Capturing Loss and Accuracy
        self.loss_per_round = np.zeros((max_rounds))
        self.accuracy_per_round = np.zeros((max_rounds))

        # Capturing 
        self.minimum_loss = 1
        self.maximum_accuracy = 0
        self.round_of_min_loss = 0
        self.round_of_max_accuracy = 0

        # Saving the path
        self.folder_for_csv = ''
        #self.minimum_loss_w = np.zeros((number_of_parameters))

        #round update checks
        self.round_tracker = 0
        self.node_updates = np.empty((n_nodes))
        for i in range(0, n_nodes):
            self.node_updates[i] = False

        #DEPENDING ON IF I NEED TO RUN A MODEL OVERNIGHT - to be defined in config file!
        if storing_type == "date":
            current_directory = os. getcwd() 
            day_time = (datetime.today().strftime('%Y-%m-%d') + ': ' + str(self.highest_case) +' cases/')
            self.overall_folder_path = os.path.join(current_directory, 'analysis_results/' + day_time)
        
            # Create new folder if it does not exists (if in case 0)
            make_new_folder = False
            if (self.case == 0 and self.total_run_through == True):
                make_new_folder = True
            elif(self.total_run_through == False):
                make_new_folder = True

            # This creates a new Foder with the date stamp!
            if make_new_folder:
                if not os.path.exists(self.overall_folder_path):
                    os.makedirs(self.overall_folder_path)
                else:
                    folder_exists_already = True
                    iterator = 1
                    while(folder_exists_already):
                        new_day_time = (datetime.today().strftime('%Y-%m-%d') + ': ' + str(self.highest_case) +' cases -- ' + str(iterator) + '/')
                        self.overall_folder_path = os.path.join(current_directory, 'analysis_results/' + new_day_time)
                        if not os.path.exists(self.overall_folder_path):
                            os.makedirs(self.overall_folder_path)
                            folder_exists_already = False
                        else:
                            iterator += 1
            
            # in all other cases, assume no more than 15 folders per day:
            if (self.case != 0 and self.total_run_through == True):
                iterator = 15
                folder_exists = False
                while(folder_exists == False and iterator >= 0):
                    new_day_time = (datetime.today().strftime('%Y-%m-%d') + ': ' + str(self.highest_case) +' cases -- ' + str(iterator) + '/')
                    temp_overall_folder_path = os.path.join(current_directory, 'analysis_results/' + new_day_time)
                    
                    # if this exists take that folder
                    if os.path.exists(temp_overall_folder_path):
                        self.overall_folder_path = temp_overall_folder_path
                        folder_exists = True
                    else:
                        iterator -= 1
        else: 
            current_directory = os. getcwd() 
            name = storing_type + "/"
            self.overall_folder_path = os.path.join(current_directory, 'analysis_results/' + name)

            if ((self.case == 0 and self.total_run_through == True)) or self.total_run_through == False:
                if not os.path.exists(self.overall_folder_path):
                    os.makedirs(self.overall_folder_path)
                else:
                    print("ERROR: PATH ALREADY EXISTS REDO!", flush=True)

        
    def newData(self, weights, node_number):

        #if global model, then out of range! -> happens at the very last!
        if (node_number == self.number_of_nodes):
            self.global_weight[self.round_tracker] = weights
            aggregated_weight = sum(weights)/self.number_of_parameters
            self.global_aggregated_weight[self.round_tracker] = aggregated_weight

            # Update Round Tracker
            self.round_tracker += 1
            return

        #Update weight and that update came in 
        self.node_updates[node_number]= True
        self.weights[node_number][self.round_tracker] = weights

        # calculate average weight for this round for this node
        aggregated_weight = sum(weights)/self.number_of_parameters
        self.aggregated_weights[node_number][self.round_tracker] = aggregated_weight

        #check if this is the last weight missing
        for i in range(0, self.number_of_nodes):
            if (self.node_updates[i] == False):
                return 

        #if all data is included, calculate mean
        for i in range(0, self.number_of_nodes):
            self.mean_weight_per_round[self.round_tracker] += self.aggregated_weights[i][self.round_tracker]
        
        self.mean_weight_per_round[self.round_tracker] /= (self.number_of_nodes)

        # here create standard diviation
        temp_all_distances = 0
        for i in range(0, self.number_of_nodes):
            temp_all_distances += ((self.aggregated_weights[i][self.round_tracker] - self.mean_weight_per_round[self.round_tracker]) ** 2)
        std_this_round = math.sqrt(temp_all_distances / (self.number_of_nodes))
        self.std_per_round[self.round_tracker] = std_this_round
        
        #make all node_updates false again
        for i in range(0, self.number_of_nodes):
            self.node_updates[i] = False

        return

    def new_loss_accuracy(self, loss, accuracy):
        # Note: this is now one round ahead, because the round tracker already added one!

        self.loss_per_round[self.round_tracker - 1] = loss
        self.accuracy_per_round[self.round_tracker - 1] = accuracy

        #calculate conversion to check that we are approaching the end of learning
        conversion_rate = self.loss_per_round[self.round_tracker - 2] - loss

        if(loss < self.minimum_loss):
            self.minimum_loss = loss
            self.round_of_min_loss = self.round_tracker-1

        if(accuracy > self.maximum_accuracy):
            self.maximum_accuracy = accuracy
            self.round_of_max_accuracy = self.round_tracker-1

        return 

    def FinalAnalysis(self):

        # Create new sub folder (case) with all new information
        sub_folder_name = 'case-' + str(self.case) + '__' + str(self.percentage_of_malicious_nodes) + '%_malicious_nodes(' + str(self.percentage_malicious_data*100) + '%_malicious_data)'
        folder_path = os.path.join(self.overall_folder_path + sub_folder_name)

        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        # Print the minimum Accuracys & losses 
        print("Maximum Accuracy accurred in", self.round_of_max_accuracy, "and is ", self.maximum_accuracy)
        print("Minimum Loss accurred in", self.round_of_min_loss, "and is ", self.minimum_loss)

        #Creating file path for the csvs to store data
        self.folder_for_csv = os.path.join(self.overall_folder_path, 'overall_analysis/')
        if not os.path.exists(self.folder_for_csv):
            os.makedirs(self.folder_for_csv)

        ###############################################################
        # Plot graphs (loss, weights, accuracy) for this case
        ###############################################################

        ### Plot the different weights ###
        weights_graph = os.path.join(folder_path, 'average_model_param')
            #PLOT
        plt.figure(figsize=(8,6))
        #plt.rcParams.update({'front.size': 30})
        plt.plot(self.global_aggregated_weight,label = "Global Model")
        for i in range(0, self.number_of_nodes):
            if(self.which_node_malicious_array[i] == True):
                this_label = "Node " + str(i+1) + " (M)" #start counting by 1
            else:
                this_label = "Node " + str(i+1) + " (H)" #start counting by 1
            plt.plot(self.aggregated_weights[i], label = this_label)
        if(self.round_turning_malicious != 0 and self.round_turning_malicious != -1):
            label_line ='M starts'
            plt.axvline(x = self.round_turning_malicious, label=label_line, color = 'black')
        if(self.round_turning_healthy_again != self.max_rounds and self.round_turning_healthy_again != -1):
            label_line ='M ends'
            plt.axvline(x = self.round_turning_healthy_again, label=label_line, color = 'grey')        
            #TITLE
        #plt.title(str(self.percentage_of_malicious_nodes) + "% malicious nodes (" + str(self.percentage_malicious_data*100) + "% malicious data) - " +str(self.number_of_nodes) + " nodes", fontsize = 16)
        #plt.suptitle("Average model parameter of nodes (Case " + str(self.case) + ")", fontsize = 30, fontweight = 'bold') # (from 784 param)

            #Nullline
        plt.axhline(y=0, xmin=0, xmax=self.round_tracker, c = 'black')
            #LABLE
        plt.xlabel("Update Round", fontsize = 30)
        plt.ylabel("Average model \n parameter", fontsize = 30)
        plt.xticks(fontsize=30)
        plt.yticks(fontsize=30)
            #LEGEND
        plt.legend(loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":30}, frameon = False)
            #GENERAL
        plt.subplots_adjust(top=0.85)
        plt.savefig(weights_graph, bbox_inches='tight',pad_inches=0.1)
        #fig1.show()
        plt.clf() #flushes plt


        ### Plot loss ###
        loss_graph = os.path.join(folder_path, 'loss_graph')
        plt.figure(figsize=(8,6))
        plt.plot(self.loss_per_round, label = "Loss")
        #plt.scatter(self.round_of_min_loss, self.minimum_loss, label = "Minimum \n Loss", color='green') # add min loss
            # PLot Temporay maliciousness
        if(self.round_turning_malicious != 0 and self.round_turning_malicious != -1):
            label_line ='M starts'
            plt.axvline(x = self.round_turning_malicious, label=label_line, color = 'black')
        if(self.round_turning_healthy_again != self.max_rounds and self.round_turning_healthy_again != -1):
            label_line ='M ends'
            plt.axvline(x = self.round_turning_healthy_again, label=label_line, color = 'grey')  
            #TITLE
        #plt.title(str(self.percentage_of_malicious_nodes) + "% malicious nodes (" + str(self.percentage_malicious_data*100) + "% malicious data) - " +str(self.number_of_nodes) + " nodes", fontsize = 16)
        #plt.suptitle("Loss of global model over update rounds (Case " + str(self.case) + ")", fontsize = 30, fontweight = "bold")
            #LABLE
        plt.xlabel("Update Round", fontsize = 30)
        plt.ylabel("Loss", fontsize = 30)
        plt.yticks(fontsize=30)
        plt.xticks(fontsize=30)
            #LEGEND
        plt.legend(loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":30}, frameon = False)
            #GENERAL
        plt.subplots_adjust(top=0.85)
        plt.savefig(loss_graph, bbox_inches='tight',pad_inches=0.1)
        plt.clf() # flushes plt


        ### Plot Accuracy ###
        accuracy_graph = os.path.join(folder_path, 'accuracy_graph')
        plt.figure(figsize=(8,6))
        plt.plot(self.accuracy_per_round, label = "Accuracy")
        #plt.scatter(self.round_of_max_accuracy, self.maximum_accuracy, label = "Maximum \n Accuracy", color='green') # add max accuracy
            # Plot temporary maliciousnes
        if(self.round_turning_malicious != 0 and self.round_turning_malicious != -1):
            label_line ='M starts'
            plt.axvline(x = self.round_turning_malicious, label=label_line, color = 'black')
        if(self.round_turning_healthy_again != self.max_rounds and self.round_turning_healthy_again != -1):
            label_line ='M ends'
            plt.axvline(x = self.round_turning_healthy_again, label=label_line, color = 'grey')  
            #TITLE
        #plt.title(str(self.percentage_of_malicious_nodes) + "% malicious nodes (" + str(self.percentage_malicious_data*100) + "% malicious data) - " +str(self.number_of_nodes) + " nodes", fontsize = 16)
        #plt.suptitle("Accuracy of global model over update rounds (Case " + str(self.case) + ")", fontsize = 30, fontweight = "bold")
            #LABLES
        fig4 = plt.xlabel("Update Round", fontsize = 30)
        fig4 = plt.ylabel("Accuracy", fontsize = 30)
        plt.xticks(fontsize=30)
        plt.yticks(fontsize=30)
            #LEGEND
        plt.legend(loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":30}, frameon = False)
            #GENERAL
        plt.subplots_adjust(top=0.85)
        fig4 = plt.savefig(accuracy_graph, bbox_inches='tight',pad_inches=0.1)
        plt.clf() # flushes plt

        ###############################################################
        # relative MSE Calculation (divided by mean)
        ###############################################################

        time_all_weights = []
        time_all_weights.append(time.time()) #0

        ######################
        # Get the mean
        save_all_means = np.zeros((self.max_rounds, self.number_of_parameters))
        for i in range (0, self.max_rounds):
            means_per_round = np.zeros((self.number_of_parameters))
            for j in range(0, self.number_of_parameters):
                sum_of_parameter = 0
                for k in range(0, self.number_of_nodes):
                    sum_of_parameter += self.weights[k][i][j]
                sum_of_parameter /= self.number_of_nodes
                means_per_round[j] = sum_of_parameter
            save_all_means[i] = means_per_round

        time_all_weights.append(time.time()) #1
        print("-----------------------------------------")
        print("**Time for full model parameter considerations:**")
        print("Time calculated the means", time_all_weights[1]-time_all_weights[0])

        time_all_weights.append(time.time()) #2
        print("Time biggest indices (zero here):", time_all_weights[2]-time_all_weights[1])

        ######################
        # MSE

        array_with_mse = np.zeros((self.number_of_nodes, self.max_rounds, self.number_of_parameters))

        array_with_accum_mse = np.zeros((self.number_of_nodes, self.max_rounds))
            
        # Get the mse for each node for each round and parameter
        # sum all paramter mse per node together and give back one value
        for i in range(0, self.max_rounds):
            for k in range(0, self.number_of_nodes):
                intermediate_sum = 0
                for j in range(0,self.number_of_parameters):
                    array_with_mse[k][i][j] = (save_all_means[i][j] - self.weights[k][i][j]) ** 2
                    intermediate_sum +=  array_with_mse[k][i][j]
                intermediate_sum /= self.number_of_parameters
                array_with_accum_mse[k][i] += intermediate_sum

        time_all_weights.append(time.time()) #3
        print("Time calculated the mse", time_all_weights[3]-time_all_weights[2])

        ######################
        # Relative MSE

        #median version!
        array_median_error_all_nodes = np.zeros((self.max_rounds))
        array_median_error_all_nodes = np.median(array_with_accum_mse, axis = 0)

        array_median_relative_mse = np.zeros((self.number_of_nodes, self.max_rounds))

        # divide error by all errors to make it relative
        for i in range(0, self.max_rounds):
            sum_accross_nodes = 0
            for k in range(0, self.number_of_nodes):
                array_median_relative_mse[k][i] = array_with_accum_mse[k][i] / array_median_error_all_nodes[i]

        time_all_weights.append(time.time()) #4
        print("Time calculated for median relativ mse", time_all_weights[4]-time_all_weights[3])

        #Create Folder Path for mse median
        median_relative_mse_graph = os.path.join(folder_path, 'median_relative_mse_model_param')

        ######################
        # Plot Array with MSE 

        plt.figure(figsize=(8,6))
            #PLOTS
        for i in range(0, self.number_of_nodes):
            if(self.which_node_malicious_array[i] == True):
                this_label = str(i+1) + " (M)" #start counting by 1
            else:
                this_label = str(i+1) + " (H)" #start counting by 1
            fig1 = plt.plot(array_median_relative_mse[i], label = this_label)
                #plot information of maliciousness

        if(self.round_turning_malicious != 0 and self.round_turning_malicious != -1):
            label_line ='M starts'
            plt.axvline(x = self.round_turning_malicious, label=label_line, color = 'black')
        if(self.round_turning_healthy_again != self.max_rounds and self.round_turning_healthy_again != -1):
            label_line ='M starts'
            plt.axvline(x = self.round_turning_healthy_again, label=label_line, color = 'grey')
            #TITLE
        #plt.suptitle("Relative MSE of model parameters accross all nodes (Case " + str(self.case) + ")", fontsize = 30, fontweight = "bold")
        #plt.title(str(self.percentage_of_malicious_nodes) + "% malicious nodes (" + str(self.percentage_malicious_data*100) + "% malicious data) - " +str(self.number_of_nodes) + " nodes", fontsize = 16, pad = 20)
            #LABLE
        plt.xlabel("Update Round", fontsize = 30)
        y_label_text = "Relative average MSE of model parameters"
        y_label = textwrap.fill(y_label_text, width=22, break_long_words=False)
        plt.ylabel(y_label, fontsize = 30)
        #plt.ylim([0,0.0003])
        plt.xticks(fontsize=30)
        plt.yticks(fontsize=30)
            #LEGEND
        plt.legend(loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":30}, frameon = False, title='Node', title_fontsize=35)
            #GENERAL
        plt.subplots_adjust(top=0.8)
        plt.savefig(median_relative_mse_graph, bbox_inches='tight',pad_inches=0.1)
        plt.clf() # flushes plt

        time_all_weights.append(time.time()) #5
        print("Time calculated for printing median graph", time_all_weights[5]-time_all_weights[4])

        ######################
        # Calculate Array with relative average Accum mse (moving average!)

        average_median_relative_mse_accum = np.zeros((self.number_of_nodes, self.max_rounds))
        
        #Create Moving Averages
        for j in range(0, self.number_of_nodes):
            for i in range(0, self.max_rounds):
                if (i < moving_average_of - 1):
                    sum = 0
                    for k in range(0, i+1):
                        sum += array_median_relative_mse[j][k]
                    div_by = i+1
                    sum /= div_by
                    average_median_relative_mse_accum[j][i] = sum
                else:
                    sum = 0
                    for k in range(i + 1 - moving_average_of, i+1):
                        sum += array_median_relative_mse[j][k]
                    sum /= moving_average_of
                    average_median_relative_mse_accum[j][i] = sum

        # Cut the first X values (new try)
        y_achsis_array = []
        for i in range(0, len(average_median_relative_mse_accum[0][moving_average_of:])):
            y_achsis_array.append(i + moving_average_of)

        time_all_weights.append(time.time()) #6
        print("Time calculated for moving average of median mse", time_all_weights[6]-time_all_weights[5])

        # Create Path to Graph 
        median_moving_average_relative_mse_graph = os.path.join(folder_path,'median_moving_average_relative_mse_model_param')

        ######################
        #PLOT moving average of relative average MSE

        # Graph creation
        plt.figure(figsize=(8,6))
            #PLOT
        for i in range(0, self.number_of_nodes):
            if(self.which_node_malicious_array[i] == True):
                this_label = str(i+1) + " (M)" #start counting by 1
            else:
                this_label = str(i+1) + " (H)" #start counting by 1
            plt.plot(y_achsis_array, average_median_relative_mse_accum[i][moving_average_of:], label = this_label)
                #plot information of maliciousness
        if(self.round_turning_malicious != 0 and self.round_turning_malicious != -1):
            label_line ='M starts'
            plt.axvline(x = self.round_turning_malicious, label=label_line, color = 'black')
        if(self.round_turning_healthy_again != self.max_rounds and self.round_turning_healthy_again != -1):
            label_line ='M ends'
            plt.axvline(x = self.round_turning_healthy_again, label=label_line, color = 'grey')
            #TITLE
        #plt.suptitle("Moving Average (" +str(moving_average_of) + " values) relative MSE of model parameters \n accross all nodes (Case " + str(self.case) + ")", fontsize = 30, fontweight = "bold")
        #plt.title(str(self.percentage_of_malicious_nodes) + "% malicious nodes (" + str(self.percentage_malicious_data*100) + "% malicious data) - " +str(self.number_of_nodes) + " nodes", fontsize = 16, pad = 20)
            #LABLE
        plt.xlabel("Update Round", fontsize = 30)
        y_label_text = "Relative average MSE of model parameters"
        y_label = textwrap.fill(y_label_text, width=22, break_long_words=False)
        plt.ylabel(y_label, fontsize = 30)
        plt.xticks(fontsize=30)
        plt.yticks(fontsize=30)
            #LEGEND
        plt.legend(loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":30}, frameon = False, title='Node', title_fontsize=35)
            #GENERAL
        plt.subplots_adjust(top=0.75)
        plt.savefig(median_moving_average_relative_mse_graph, bbox_inches='tight',pad_inches=0.1)
        plt.clf() # flushes plt

        time_all_weights.append(time.time()) #7
        print("Time calculated for drawing mse moving average graph", time_all_weights[7]-time_all_weights[6])

        print("Total time all model params", time_all_weights[7]-time_all_weights[0])
        print("-----------------------------------------")

        ######################
        #Saving information of array 

        # Export standard diviation Development over rounds
        medianMSE = os.path.join(self.folder_for_csv, 'medianMSE.csv')
        with open(medianMSE, 'a') as csv:
            average_median_relative_mse_accum.tofile(csv, sep=',', format='%.30e')
            csv.write('\n')
            csv.close()   
        
        SUM_MSE_each_node = np.zeros((self.number_of_nodes))
        SUM_MSE_each_node = np.mean(average_median_relative_mse_accum, axis = 1)

        # Export standard diviation Development over rounds
        SUMmedianMSE = os.path.join(self.folder_for_csv, 'SUMmedianMSE.csv')
        with open(SUMmedianMSE, 'a') as csv:
            SUM_MSE_each_node.tofile(csv, sep=',', format='%.30e')
            csv.write('\n')
            csv.close() 


        ###############################################################
        #WITH LESS MODEL PARAMTERS ANALYSIS!!!
        ###############################################################

        print("**Time for limited model parameter considerations: **")

        time_lim_weights =[]
        time_lim_weights.append(time.time()) #0

        ######################
        # Get the mean
        save_all_means = np.zeros((self.max_rounds, self.number_of_parameters))
        for i in range (0, self.max_rounds):
            means_per_round = np.zeros((self.number_of_parameters))
            for j in range(0, self.number_of_parameters):
                sum_of_parameter = 0
                for k in range(0, self.number_of_nodes):
                    sum_of_parameter += self.weights[k][i][j]
                sum_of_parameter /= self.number_of_nodes
                means_per_round[j] = sum_of_parameter
            save_all_means[i] = means_per_round

        time_lim_weights.append(time.time()) #1
        print("Time to get means:",  time_lim_weights[1]-time_lim_weights[0])


        ######################
        # GET BIGGEST INDICIES

        number_of_weights_concidered = int(self.number_of_parameters * percentage_of_weights_concidered_lim_case)
        indicies_larges_weights = np.zeros((self.max_rounds,number_of_weights_concidered))
        indicies_sorted = np.zeros((self.max_rounds, self.number_of_parameters))

        for row in range(len(save_all_means)):
            #note ::-1 means: starts from the end towards the first taking each element.
    
            indicies_sorted[row] = save_all_means[row].argsort()[::-1]

            beginning_counter = 0 
            end_counter = self.number_of_parameters - 1 

            for i in range(0, number_of_weights_concidered):
                if(abs(save_all_means[row][int(indicies_sorted[row][beginning_counter])]) > abs(save_all_means[row][int(indicies_sorted[row][end_counter])])):
                    indicies_larges_weights[row][i] = indicies_sorted[row][beginning_counter]
                    beginning_counter += 1
                else:
                    indicies_larges_weights[row][i] = indicies_sorted[row][end_counter]
                    end_counter -= 1

        time_lim_weights.append(time.time()) #2
        print("Time biggest indices:", time_lim_weights[2]-time_lim_weights[1])

        ######################
        # GET MSE

        array_with_mse = np.zeros((self.number_of_nodes, self.max_rounds, number_of_weights_concidered))
        array_with_accum_mse = np.zeros((self.number_of_nodes, self.max_rounds))
            
        # Get the mse for each node for each round and parameter
        # sum all paramter mse per node together and give back one value
        for i in range(0, self.max_rounds):
            for k in range(0, self.number_of_nodes):
                intermediate_sum = 0
                for j in range(0, len(indicies_larges_weights[0])):
                    array_with_mse[k][i][j] = ((save_all_means[i][int(indicies_larges_weights[i][j])] - self.weights[k][i][int(indicies_larges_weights[i][j])]) ** 2)
                    intermediate_sum +=  array_with_mse[k][i][j]
                intermediate_sum /= number_of_weights_concidered
                array_with_accum_mse[k][i] += intermediate_sum

        time_lim_weights.append(time.time()) #3
        print("Time mse (just for the biggest indices)", time_lim_weights[3]-time_lim_weights[2])

        ######################
        # GET RELATIVE MSE

        #median version!
        array_median_error_all_nodes = np.zeros((self.max_rounds))
        array_median_error_all_nodes = np.median(array_with_accum_mse, axis = 0)

        array_median_relative_mse = np.zeros((self.number_of_nodes, self.max_rounds))
        
        # divide error by all errors to make it relative
        for i in range(0, self.max_rounds):
            sum_accross_nodes = 0
            for k in range(0, self.number_of_nodes):
                #if( abs(save_all_means[i][j]) < 1e-25): # check here
                    #array_mean_relative_mse[k][i] = 0
                #else:
                array_median_relative_mse[k][i] = array_with_accum_mse[k][i] / array_median_error_all_nodes[i]

        time_lim_weights.append(time.time()) #4
        print("Time for getting mse / median", time_lim_weights[4]-time_lim_weights[3])

        ######################
        # PRINT RELATIVE MSE

        #Create Folder Path for mse
        lim_weights_median_relative_mse_graph = os.path.join(folder_path, 'lim_weights_median_relative_mse_model_param')

        # Plot Array with Accum mse 
        plt.figure(figsize=(8,6))
            #PLOTS
        for i in range(0, self.number_of_nodes):
            if(self.which_node_malicious_array[i] == True):
                this_label = str(i+1) + " (M)" #start counting by 1
            else:
                this_label = str(i+1) + " (H)" #start counting by 1
            fig1 = plt.plot(array_median_relative_mse[i], label = this_label)
                #plot information of maliciousness
        if(self.round_turning_malicious != 0 and self.round_turning_malicious != -1):
            label_line ='M starts'
            plt.axvline(x = self.round_turning_malicious, label=label_line, color = 'black')
        if(self.round_turning_healthy_again != self.max_rounds and self.round_turning_healthy_again != -1):
            label_line ='M ends'
            plt.axvline(x = self.round_turning_healthy_again, label=label_line, color = 'grey')
            #TITLE
        #plt.suptitle("Relative MSE of top abs. " + str(int(percentage_of_weights_concidered_lim_case * 100)) +"% model parameters accross all nodes (Case " + str(self.case) + ")", fontsize = 30, fontweight = "bold")
        #plt.title(str(self.percentage_of_malicious_nodes) + "% malicious nodes (" + str(self.percentage_malicious_data*100) + "% malicious data) - " +str(self.number_of_nodes) + " nodes", fontsize = 16, pad = 20)
            #LABLE
        plt.xlabel("Update Round", fontsize = 30)
        y_label_text = "Relative average MSE of model parameters"
        y_label = textwrap.fill(y_label_text, width=22, break_long_words=False)
        plt.ylabel(y_label, fontsize = 30)
        plt.ylim([0,0.0003])
        plt.xticks(fontsize=30)
        plt.yticks(fontsize=30)
        plt.autoscale() 
            #LEGEND
        plt.legend(loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":30}, frameon = False, title='Node', title_fontsize=35)
            #GENERAL
        plt.subplots_adjust(top=0.8)
        plt.savefig(lim_weights_median_relative_mse_graph, bbox_inches='tight',pad_inches=0.1)
        plt.clf() # flushes plt

        time_lim_weights.append(time.time()) #5
        print("Time for making median graph", time_lim_weights[5]-time_lim_weights[4])

        ######################
        # CALCULATE MOVING AVERAGE RELATIVE MSE

        average_median_relative_mse_accum = np.zeros((self.number_of_nodes, self.max_rounds))
        
        #Create Moving Averages
        for j in range(0, self.number_of_nodes):
            for i in range(0, self.max_rounds):
                if (i < moving_average_of - 1):
                    sum = 0
                    for k in range(0, i+1):
                        sum += array_median_relative_mse[j][k]
                    div_by = i+1
                    sum /= div_by
                    average_median_relative_mse_accum[j][i] = sum
                else:
                    sum = 0
                    for k in range(i + 1 - moving_average_of, i+1):
                        sum += array_median_relative_mse[j][k]
                    sum /= moving_average_of
                    average_median_relative_mse_accum[j][i] = sum

        # Cut the first X values (new try)
        y_achsis_array = []
        for i in range(0, len(average_median_relative_mse_accum[0][moving_average_of:])):
            y_achsis_array.append(i + moving_average_of)

        time_lim_weights.append(time.time()) #6
        print("Time for moving averaging calculation", time_lim_weights[6]-time_lim_weights[5])

        # Create Path to Graph 
        lim_weights_median_average_relative_mse_graph = os.path.join(folder_path,'lim_weights_median_moving_average_relative_mse_model_param')


        ######################
        # PLOT MOVING AVERAGE RELATIVE MSE

        # Graph creation
        plt.figure(figsize=(8,6))
            #PLOT
        for i in range(0, self.number_of_nodes):
            if(self.which_node_malicious_array[i] == True):
                this_label = str(i+1) + " (M)" #start counting by 1
            else:
                this_label = str(i+1) + " (H)" #start counting by 1
            fig1 = plt.plot(y_achsis_array, average_median_relative_mse_accum[i][moving_average_of:], label = this_label)
                #plot information of maliciousness
        if(self.round_turning_malicious != 0 and self.round_turning_malicious != -1):
            label_line ='M starts'
            plt.axvline(x = self.round_turning_malicious, label=label_line, color = 'black')
        if(self.round_turning_healthy_again != self.max_rounds and self.round_turning_healthy_again != -1):
            label_line ='M ends'
            plt.axvline(x = self.round_turning_healthy_again, label=label_line, color = 'grey')
            #TITLE
        #plt.suptitle("Moving Average (" +str(moving_average_of) + " values) relative MSE of top abs. " + str(int(percentage_of_weights_concidered_lim_case * 100)) + "% model parameters \n accross all nodes (Case " + str(self.case) + ")", fontsize = 30, fontweight = "bold")
        #plt.title(str(self.percentage_of_malicious_nodes) + "% malicious nodes (" + str(self.percentage_malicious_data*100) + "% malicious data) - " +str(self.number_of_nodes) + " nodes", fontsize = 16, pad = 20)
            #LABLE
        plt.xlabel("Update Round", fontsize = 30)
        y_label_text = "Relative average MSE of model parameters"
        y_label = textwrap.fill(y_label_text, width=22, break_long_words=False)
        plt.ylabel(y_label, fontsize = 30)
        plt.xticks(fontsize=30)
        plt.yticks(fontsize=30)
            #LEGEND
        plt.legend(loc='center left', bbox_to_anchor=(1, 0.5), prop={"size":30}, frameon = False, title='Node', title_fontsize=35)
            #GENERAL
        plt.subplots_adjust(top=0.75)
        plt.savefig(lim_weights_median_average_relative_mse_graph, bbox_inches='tight',pad_inches=0.1)
        plt.clf() # flushes plt

        time_lim_weights.append(time.time()) #7
        print("Time for moving averaging graph", time_lim_weights[7]-time_lim_weights[6])

        print("Total time limited model params", time_lim_weights[7] - time_lim_weights[0])

        ######################
        #Exporting lim median MSE information

        # Export standard diviation Development over rounds
        limmedianMSE = os.path.join(self.folder_for_csv, 'limmedianMSE.csv')
        with open(limmedianMSE, 'a') as csv:
            average_median_relative_mse_accum.tofile(csv, sep=',', format='%.30e')
            csv.write('\n')
            csv.close() 

        lim_SUM_MSE_each_node = np.zeros((self.number_of_nodes))
        lim_SUM_MSE_each_node = np.mean(average_median_relative_mse_accum, axis = 1)

        # Export standard diviation Development over rounds
        SUMlimmedianMSE = os.path.join(self.folder_for_csv, 'SUMlimmedianMSE.csv')
        with open(SUMlimmedianMSE, 'a') as csv:
            lim_SUM_MSE_each_node.tofile(csv, sep=',', format='%.30e')
            csv.write('\n')
            csv.close() 

        ###############################################################
        # Export everything into csv! 
        ###############################################################


        ####################
        # Export timings of lim weight and normal weight
        ####################

        timing_full_weights = os.path.join(self.folder_for_csv, 'timing_full_weights.csv')
        with open(timing_full_weights, 'a') as csv:
            for i in range(0, len(time_all_weights)):
                if i == 0:
                    continue
                else:
                    calc_div = time_all_weights[i] - time_all_weights[i-1]
                    csv.write(str(calc_div))    
                    csv.write(',')
            csv.write('\n')
            csv.close()

        timing_lim_weights = os.path.join(self.folder_for_csv, 'timing_lim_weights.csv')
        with open(timing_lim_weights, 'a') as csv:
            for i in range(0, len(time_lim_weights)):
                if i == 0:
                    continue
                else:
                    calc_div = time_lim_weights[i] - time_lim_weights[i-1]
                    csv.write(str(calc_div))    
                    csv.write(',')
            csv.write('\n')
            csv.close()

        ####################
        #These are analysis of loss, accuracy, weights at minimum / end!
        ####################

        # Export Maximum Accuracy
        accuracy_csv = os.path.join(self.folder_for_csv, 'max_accuracy.csv')
        with open(accuracy_csv, 'a') as csv:
            #Make a comma if not empty as delimiter
            if not (os.stat(accuracy_csv).st_size == 0):
                csv.write(",")
            csv.write(str(self.maximum_accuracy))
            csv.close()

        # Export Minimum Loss
        loss_csv = os.path.join(self.folder_for_csv, 'min_loss.csv')
        with open(loss_csv, 'a') as csv:
            #Make a comma if not empty as delimiter
            if not (os.stat(loss_csv).st_size == 0):
                csv.write(",")
            csv.write(str(self.minimum_loss))
            csv.close()

        # Export Accuracy at last round
        last_accuracy_csv = os.path.join(self.folder_for_csv, 'last_accuracy.csv')
        with open(last_accuracy_csv, 'a') as csv:
            #Make a comma if not empty as delimiter
            if not (os.stat(last_accuracy_csv).st_size == 0):
                csv.write(",")
            csv.write(str(self.accuracy_per_round[self.round_tracker-1]))
            csv.close()
    

        # Export Loss at last round
        last_loss_csv = os.path.join(self.folder_for_csv, 'last_loss.csv')
        with open(last_loss_csv, 'a') as csv:
            #Make a comma if not empty as delimiter
            if not (os.stat(last_loss_csv).st_size == 0):
                csv.write(",")
            csv.write(str(self.loss_per_round[self.round_tracker-1]))
            csv.close()


        # Export Weights Average at last round
        last_average_weight_csv = os.path.join(self.folder_for_csv, 'last_average_model_param.csv')
        with open(last_average_weight_csv, 'a') as csv:
            #Make a comma if not empty as delimiter
            if not (os.stat(last_average_weight_csv).st_size == 0):
                csv.write(",")
            csv.write(str(self.global_aggregated_weight[self.round_tracker-1]))
            csv.close()

        ####################
        #These are analysis of loss, accuracy, weights over time compared between cases
        ####################

        # Export Accuracy Development over Rounds
        accuray_dev_csv = os.path.join(self.folder_for_csv, 'accuray_dev.csv')
        accuracy_over_rounds = self.accuracy_per_round
        with open(accuray_dev_csv, 'a') as csv:
            accuracy_over_rounds.tofile(csv, sep=',', format='%.30e')
            csv.write('\n')
            csv.close()

        # Export Loss Development over Rounds
        loss_dev_csv = os.path.join(self.folder_for_csv, 'loss_dev.csv')
        loss_over_rounds = self.loss_per_round
        with open(loss_dev_csv, 'a') as csv:
            loss_over_rounds.tofile(csv, sep=',', format='%.30e')
            csv.write('\n')
            csv.close()

        # Export average Weight Development over Rounds
        weights_csv = os.path.join(self.folder_for_csv, 'average_global_model_param_dev.csv')
        last_global_weights = self.global_aggregated_weight
        with open(weights_csv, 'a') as csv:
            last_global_weights.tofile(csv, sep=',', format='%.30e')
            csv.write('\n')
            csv.close()

        #Export average weight of each node over rounds
        weights_per_node_csv = os.path.join(self.folder_for_csv, 'average_model_param_per_node_dev.csv')
        weights_per_node = self.aggregated_weights
        with open(weights_per_node_csv, 'a') as csv:
            for i in range (0, self.number_of_nodes):
                weights_per_node[i].tofile(csv, sep=',', format='%.30e')
                csv.write('\n')
            csv.write('\n')
            csv.close()

        # Export standard diviation Development over rounds
        std_dev_scv = os.path.join(self.folder_for_csv, 'std_dev.csv')
        std_per_round = self.std_per_round
        with open(std_dev_scv, 'a') as csv:
            std_per_round.tofile(csv, sep=',', format='%.30e')
            csv.write('\n')
            csv.close()   

        ####################
        # Call all Cases Analysis if it ran through!
        ####################
    
        if(self.total_run_through and (self.case == self.highest_case)):
            # THIS IS HARDCODED RIGHT NOW; CHANGE POTENTIALLY!
            all_cases_analysis(self.folder_for_csv, self.highest_case, self.round_tracker, self.number_of_nodes)

        return self.folder_for_csv
