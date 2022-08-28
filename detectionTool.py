import numpy as np
import os

class MaliciousUserDetection:

    def __init__(self, w_length, n_nodes, number_of_rounds_to_store, background_information_which_node_malicious,round_turning_malicious, round_turning_healthy_again):

        # Store all relavant information
        self.n_nodes = n_nodes
        self.number_of_parameters = w_length
        self.number_of_rounds_to_store = number_of_rounds_to_store
        self.global_relative_MSE_Array = np.zeros((self.number_of_rounds_to_store, self.n_nodes))
        self.round_counter = 0

        #Store information to validate the performance
        self.round_turning_malicious = round_turning_malicious
        self.round_turning_healthy_again = round_turning_healthy_again

        self.background_information_which_node_malicious = background_information_which_node_malicious

        self.number_of_wrongly_detected_malicious_nodes = 0 #healthy but malicious
        self.number_of_wrongly_classified_healthy_nodes = 0 #malicious but helathy
        self.number_of_rightly_detected_malicious_nodes = 0 #malicious and malicious
        self.number_of_rightly_classified_healthy_nodes = 0 #healthy and healthy

    def return_malicious_or_not_malcious(self, node_param_updates, threshold, moving_average_of, percentage_of_parameters_to_include):

        #calculate the mean per model parameter
        paramater_means = np.zeros((self.number_of_parameters))

        for j in range(0, self.number_of_parameters):
            sum_of_parameter = 0
            for k in range(0, self.n_nodes):
                sum_of_parameter += node_param_updates[k][j]
            sum_of_parameter /= self.n_nodes
            paramater_means[j] = sum_of_parameter


        # Get the indicies relevant!
        number_of_weights_concidered = int(self.number_of_parameters * percentage_of_parameters_to_include)
        indicies_larges_weights = np.zeros((number_of_weights_concidered))
        indicies_sorted = np.zeros(self.number_of_parameters)

        indicies_sorted = paramater_means.argsort()[::-1]

        beginning_counter = 0 
        end_counter = self.number_of_parameters - 1 

        for i in range(0, number_of_weights_concidered):
            if(abs(paramater_means[int(indicies_sorted[beginning_counter])]) > abs(paramater_means[int(indicies_sorted[end_counter])])):
                indicies_larges_weights[i] = indicies_sorted[beginning_counter]
                beginning_counter += 1
            else:
                indicies_larges_weights[i] = indicies_sorted[end_counter]
                end_counter -= 1

        mse_per_param_per_node = np.zeros((self.n_nodes, number_of_weights_concidered))
        accum_mse_per_node = np.zeros((self.n_nodes))

        # Get the mse for each node for each round and parameter
        # sum all paramter mse per node together and give back one value
        for k in range(0, self.n_nodes):
            intermediate_sum = 0
            for j in range(0, len(indicies_larges_weights)):
                mse_per_param_per_node[k][j] = ((paramater_means[int(indicies_larges_weights[j])] - node_param_updates[k][int(indicies_larges_weights[j])]) ** 2)
                intermediate_sum +=  mse_per_param_per_node[k][j]
            intermediate_sum /= number_of_weights_concidered
            accum_mse_per_node[k] += intermediate_sum

        # Take the median of the MSE
        array_median_error_all_nodes = np.median(accum_mse_per_node, axis = 0)
        
        array_median_relative_mse = np.zeros((self.n_nodes))

        # divide error by all errors to make it relative
        for k in range(0, self.n_nodes):
            array_median_relative_mse[k] = accum_mse_per_node[k] / array_median_error_all_nodes

        # array_median_relative_mse should have 5 values, print those!!

        #CHECK IF ROUND > NO OF ROUNDS TO STORE
        if (self.round_counter >= self.number_of_rounds_to_store):
            self.global_relative_MSE_Array[0].delete()
            print("Deleting first item!")

        # store the relative MSE array
        for i in range(0, self.n_nodes):
            self.global_relative_MSE_Array[self.round_counter][i] = array_median_relative_mse[i] 

        # Create moving average
        # Plot Array with average Accum mse
        average_median_relative_mse_accum = np.zeros((self.n_nodes))
        
        #Create Moving Averages
        for j in range(0, self.n_nodes):
                if (self.round_counter < moving_average_of - 1):
                    sum = 0
                    for k in range(0, self.round_counter+1): #+1 because range is excluding the last number
                        sum += self.global_relative_MSE_Array[k][j]
                    div_by = i+1
                    sum /= div_by
                    average_median_relative_mse_accum[j] = sum
                else:
                    sum = 0
                    for k in range(self.round_counter + 1 - moving_average_of, self.round_counter +1):
                        sum += self.global_relative_MSE_Array[k][j]
                    sum /= moving_average_of
                    average_median_relative_mse_accum[j] = sum

        # Threshold Check e.g. --> results stored in array which gets passed back to server!
        array_nodes_healthy = np.zeros((self.n_nodes))
        for i in range(0, self.n_nodes):
            if (average_median_relative_mse_accum[i] >= threshold):
                array_nodes_healthy[i] = 1 #malicious
            else:
                array_nodes_healthy[i] = 0 #healthy

        print("Array nodes classified as healthy (=0) or malicious (=1):", array_nodes_healthy)

        # Temporary background information based on temporary maliciousness
        background_information_which_node_malicious_this_round = []

        # Temporary background information based on temporary maliciousness
        for i in range(0, len(self.background_information_which_node_malicious)):
            background_information_which_node_malicious_this_round.append(self.background_information_which_node_malicious[i])


        # if this is a not malicious round, then it is not a malicious round
        if(self.round_counter < self.round_turning_malicious or self.round_counter >= self.round_turning_healthy_again):
            for i in range(0,len(background_information_which_node_malicious_this_round)):
                background_information_which_node_malicious_this_round[i] = 0

        #save the information on which nodes are classified wrongly or rightly
        for i in range(0, self.n_nodes):

            # correctly identified as healthy
            if (array_nodes_healthy[i] == background_information_which_node_malicious_this_round[i] and array_nodes_healthy[i] == 0):
                self.number_of_rightly_classified_healthy_nodes += 1

            # correctly identified as malicious
            elif (array_nodes_healthy[i] == background_information_which_node_malicious_this_round[i] and array_nodes_healthy[i] == 1):
                self.number_of_rightly_detected_malicious_nodes += 1

            # wrongly identified as healthy
            elif (array_nodes_healthy[i] == 0 and background_information_which_node_malicious_this_round[i] == 1):
                self.number_of_wrongly_classified_healthy_nodes += 1

            # wrongly identified as malicious
            elif (array_nodes_healthy[i] == 1 and background_information_which_node_malicious_this_round[i] == 0):
                self.number_of_wrongly_detected_malicious_nodes += 1

        self.round_counter += 1

        return array_nodes_healthy #return which nodes are classified healthy and malicious

    def last_round_save_information(self, folder_for_csv):
        
        # Export information to CSV
        csv1 = os.path.join(folder_for_csv, 'number_of_rightly_classified_healthy_nodes.csv')
        with open(csv1, 'a') as csv:
            csv.write(str(self.number_of_rightly_classified_healthy_nodes))    
            csv.write(',')
            csv.close()

        csv2 = os.path.join(folder_for_csv, 'number_of_rightly_detected_malicious_nodes.csv')
        with open(csv2, 'a') as csv:
            csv.write(str(self.number_of_rightly_detected_malicious_nodes))    
            csv.write(',')
            csv.close()

        
        csv3 = os.path.join(folder_for_csv, 'number_of_wrongly_classified_healthy_nodes.csv')
        with open(csv3, 'a') as csv:
            csv.write(str(self.number_of_wrongly_classified_healthy_nodes))    
            csv.write(',')
            csv.close()
                
        csv4 = os.path.join(folder_for_csv, 'number_of_wrongly_detected_malicious_nodes.csv')
        with open(csv4, 'a') as csv:
            csv.write(str(self.number_of_wrongly_detected_malicious_nodes))    
            csv.write(',')
            csv.close()

        return