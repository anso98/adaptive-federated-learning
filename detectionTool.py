import numpy as np

#how do I do this detection system
# needs to come in in the global model before aggregation
# it is coming into place in the central server, just bevor aggregation
# after having all model parameters: 

# What parameter could be useful to include: on how many parameters to base the decision, which threshold, which moving average, exclude, kick out or just reduce importance of that weight?

# caclulate relative (maybe 1%?) MSE for all of the nodes

class MaliciousUserDetection:

    def __init__(self, w_length, n_nodes, number_of_rounds_to_store):
        self.n_nodes = n_nodes
        self.number_of_parameters = w_length
        self.number_of_rounds_to_store = number_of_rounds_to_store
        self.global_relative_MSE_Array = np.zeros(( self.number_of_rounds_to_store, self.n_nodes))
        self.round_counter = 0

    def return_malicious_or_not_malcious(self, node_param_updates, threshold, moving_average_of):

        #calculate the mean per model parameter
        paramater_means = np.zeros((self.number_of_parameters))

        for j in range(0, self.number_of_parameters):
            sum_of_parameter = 0
            for k in range(0, self.n_nodes):
                sum_of_parameter += node_param_updates[k][j]
            sum_of_parameter /= self.n_nodes
            paramater_means[j] = sum_of_parameter

        # calculate the MSE and take the average of it 
        mse_per_param_per_node = np.zeros((self.n_nodes, self.number_of_parameters))
        accum_mse_per_node = np.zeros((self.n_nodes))

        for k in range(0, self.n_nodes):
            intermediate_sum = 0
            for j in range(0, self.number_of_parameters):
                mse_per_param_per_node[k][j] = (paramater_means[j] - node_param_updates[k][j]) ** 2
                intermediate_sum +=  mse_per_param_per_node[k][j]
            intermediate_sum /= self.number_of_parameters
            accum_mse_per_node[k] += intermediate_sum

        # Take the median of the MSE
        #PLEASE CHECK: am I taking the right axsis?
        array_median_error_all_nodes = np.median(accum_mse_per_node, axis = 0)
        
        array_median_relative_mse = np.zeros((self.n_nodes))

        # divide error by all errors to make it relative
        for k in range(0, self.n_nodes):
            array_median_relative_mse[k] = accum_mse_per_node[k] / array_median_error_all_nodes

        # NOW: as a result I have one error which I can now use to detect malicious users 
        # array_median_relative_mse Should have 5 values, print those!!
        print("Array with median relative mse:", array_median_relative_mse)

        #CHECK IF ROUND > NO OF ROUNDS TO STORE
        if (self.round_counter >= self.number_of_rounds_to_store):
            self.global_relative_MSE_Array[0].delete()
            print("Deleting first item!")
            #CHECK IF THIS IS CORRECT PLEASE!

        # STORE IN IN OVERALL ARRAY; THINK ABOUT HOW TO MAKE IT FLEXIBLE?
        for i in range(0, self.n_nodes):
            self.global_relative_MSE_Array[self.round_counter][i] = array_median_relative_mse[i] 

        #np.delete()
        #a = numpy.append(a, a[0])

        # Create moving average
        # Plot Array with average Accum mse
        average_median_relative_mse_accum = np.zeros((self.n_nodes))
        
        #Create Moving Averages
        for j in range(0, self.n_nodes):
                if (self.round_counter < moving_average_of - 1):
                    sum = 0
                    for k in range(0, self.round_counter+1): #+1 because range is excluding the last number
                        sum += array_median_relative_mse[j][k]
                    div_by = i+1
                    sum /= div_by
                    average_median_relative_mse_accum[j] = sum
                else:
                    sum = 0
                    for k in range(self.round_counter + 1 - moving_average_of, self.round_counter +1):
                        sum += array_median_relative_mse[j][k]
                    sum /= moving_average_of
                    average_median_relative_mse_accum[j] = sum

        # Threshold Check e.g.
        array_nodes_healthy = np.zeros((self.n_nodes))
        for i in range(0, self.n_nodes):
            if (average_median_relative_mse_accum[i] >= threshold):
                array_nodes_healthy[i] = False
            else:
                array_nodes_healthy[i] = True

        print("Array nodes classified as healthy (=1) or malicious (=0)", array_nodes_healthy)

        self.round_counter += 1

        return array_nodes_healthy #return which nodes are classified healthy and malicious

        # BUT: problem: if I want to do this with an moving average I have to store my old values somewhere as well?? Maybe I should do a class and store the information here (as long as the model is running? --> maybe not all values but the last 200 or so?) => would also be great in the report to argue
        #--> therefore make a class and store it over multiple rounds!

        # could I take into consideration that the node was classified malicious the round before? For example not taking into account the values for the mean calculation again to make sure the mean calculation is more stable?
        
        # take moving averages from MSE

        # Check if MSE is > threshold

        # if so classify as malicious --> 
            # check how the input comes out!!

        # give back that client is malicious

        # in server: check if client is malicious and then exclude him potentially?

        # for analysis: do the same thing once with this activated and once without and compare accuracy

        # also I want to capture how often a malicious user got detected: 
        # maybe like a database,

        x = 10

    def calculate_relative_MSE(node_param_updates):
        x = 1

    def take_moving_average(mse_param):
        x = 2




