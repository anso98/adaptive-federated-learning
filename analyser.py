from cmath import sqrt
import csv
import math
import numpy as np
import os
from matplotlib import pyplot as plt
from datetime import datetime


class Analayser:
    def __init__(self, n_nodes, number_of_parameters, max_rounds, case):

        # general parameters
        self.number_of_parameters = number_of_parameters
        self.number_of_nodes = n_nodes
        self.max_rounds = max_rounds
        self.case = case

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

        #self.minimum_loss_w = np.zeros((number_of_parameters))

        #round update checks
        self.round_tracker = 0
        self.node_updates = np.empty((n_nodes))
        for i in range(0, n_nodes):
            self.node_updates[i] = False

    def newData(self, weights, node_number):

        #if global model, then out of range! -> happens at the very last!
        if (node_number == self.number_of_nodes):
            self.global_weight[self.round_tracker] = weights
            aggregated_weight = sum(weights)/self.number_of_parameters
            self.global_aggregated_weight[self.round_tracker] = aggregated_weight

            # Update Round Tracker
            self.round_tracker += 1
            print("Round number", self.round_tracker)
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

        # here create standard diviation -- PLEASE CHECK CALCULATION!
        temp_all_distances = 0
        for i in range(0, self.number_of_nodes):
            temp_all_distances += ((self.aggregated_weights[i][self.round_tracker] - self.mean_weight_per_round[self.round_tracker]) ** 2)
        std_this_round = math.sqrt(temp_all_distances / (self.number_of_nodes))
        print(std_this_round)

        self.std_per_round[self.round_tracker] = std_this_round

        print("this round std: ", self.std_per_round[self.round_tracker])
        
        #make all node_updates false again
        for i in range(0, self.number_of_nodes):
            self.node_updates[i] = False

        return

    def new_loss_accuracy(self, loss, accuracy):
        # Note: this is now one round ahead, because the round tracker already added one!

        self.loss_per_round[self.round_tracker - 1] = loss
        self.accuracy_per_round[self.round_tracker - 1] = accuracy

        print('---------------------------------')
        print("Loss of this round with independent test data", loss)
        print("Accuracy of this round with independent test data", accuracy)
        print('---------------------------------')

        if(loss < self.minimum_loss):
            self.minimum_loss = loss
            self.round_of_min_loss = self.round_tracker-1

        if(accuracy > self.maximum_accuracy):
            self.maximum_accuracy = accuracy
            self.round_of_max_accuracy = self.round_tracker-1

        return 

    def FinalAnalysis(self):

        # Create new folder with all new information
        current_directory = os. getcwd() 
        day_time = (datetime.today().strftime('%Y-%m-%d'))
        folder_name = day_time + '-case-' + str(self.case)
        folder_path = os.path.join(current_directory, 'analysis_results/' + folder_name)

        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        # Print the minimum Accuracys & losses 
        print("Maximum Accuracy accurred in", self.round_of_max_accuracy, "and is ", self.maximum_accuracy)
        print("Minimum Loss accurred in", self.round_of_min_loss, "and is ", self.minimum_loss)

        # Plot the different weights 
        weights_graph = os.path.join(folder_path, 'weights_graph')
        for i in range(0, self.number_of_nodes):
            this_label = "Node " + str(i+1) #start counting by 1
            plt.plot(self.aggregated_weights[i], label = this_label)
        plt.plot(self.global_aggregated_weight,label = "Global Model")
        plt.title("Weights of different nodes - case " + str(self.case))
        plt.xlabel("Update Round")
        plt.ylabel("Weight")
        plt.legend(loc = "best")
        plt.grid(axis="y", linewidth=0.5)
        plt.savefig(weights_graph)
        plt.show()

        # Plot the Standard derivation
        std_graph = os.path.join(folder_path, 'std_graph')
        plt.plot(self.std_per_round)
        plt.title("Std of weights over update rounds - case " + str(self.case))
        plt.xlabel("Update Round")
        plt.ylabel("Std")
        plt.grid(axis="y", linewidth=0.5)
        plt.savefig(std_graph)
        plt.show()

        # Plot loss & Accuracy
        # Add: show minimum in graph!! -> get value of round? how?
        loss_graph = os.path.join(folder_path, 'loss_graph')
        plt.plot(self.loss_per_round, label = "Loss")
        plt.scatter(self.round_of_min_loss, self.minimum_loss, label = "Minimum Loss over all rounds", color='green') # add min loss
        plt.title("Loss of model over update rounds - case " + str(self.case))
        plt.xlabel("Update Round")
        plt.ylabel("Loss")
        plt.grid(axis="y", linewidth=0.5)
        plt.legend(loc = "best")
        plt.savefig(loss_graph)
        plt.show()

        # Plot Accuracy
        accuracy_graph = os.path.join(folder_path, 'accuracy_graph')
        plt.plot(self.accuracy_per_round, label = "Accuracy")
        plt.scatter(self.round_of_max_accuracy, self.maximum_accuracy, label = "Maximum Accuracy over all rounds", color='green') # add max accuracy
        plt.title("Accuracy of model over update rounds - case " + str(self.case))
        plt.xlabel("Update Round")
        plt.ylabel("Accuracy")
        plt.legend(loc = "best")
        plt.grid(axis="y", linewidth=0.5)
        plt.savefig(accuracy_graph)
        plt.show()

        # export everything into csv!
        # This code works, need to think about datastructure of files
        # This can be an overall csv for all cases!
        results_file_name = os.path.join(current_directory, 'analysis_results/results.csv')
        test = np.zeros((3, 5))
        with open(results_file_name, 'a') as csvfile:
            csvfile.write('test,abcd,\n')
            np.savetxt(csvfile, test, fmt='%.18e', delimiter=', ', encoding=None)
            csvfile.close()

        # for saving for weights of case, please use folder link as above!

        return