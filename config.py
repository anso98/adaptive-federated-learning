#Config 

# Information: This config file enables to set the settings for this environment. 
# It is split in the following sections: 
# 1. Server - Network settings
# 2. Model and Dataset - Choosing the dataset and model, as well as batch size, learning rate and datset file
# 3. General Parameter - Including how many nodes, how many update rounds and which data distribution we should choose
# 4. Detection Tool - Activate detection tool and put settings as required
# 5. Analysis parameter - which moving average, which lim weights and what the folder name should be to store 
# 6. Type of Maliciousness
# 7. Time Frame of maliciousness
# 8. Full runthrough vs single case
# 9. Amount of malicious nodes and malicious data 

#1. Server
#++++++++++++++++++++++++++++++++++++++++++++++++++#
# RMI Data
SERVER_ADDR= 'localhost'   # When running in a real distributed setting, change to the server's IP address
SERVER_PORT = 52000

#2. Model and Dataset
#++++++++++++++++++++++++++++++++++++++++++++++++++#
# Three dataset options:
#A
#dataset = 'MNIST_ORIG_ALL_LABELS'  # Use for CNN model
#model_name = 'ModelCNNMnist'

#B
#dataset = 'CIFAR_10'
#model_name = 'ModelCNNCifar10'

#C
model_name = 'ModelSVMSmooth'
dataset = "MNIST_ORIG_EVEN_ODD"

# Model Data
batch_size = 100  # 100  # Value for stochastic gradient descent
total_data = 30000  # 60000  #Value for stochastic gradient descent
step_size = 0.01 #0.01 before
dataset_file_path = "/Users/Anso/Code/Imperial_College/IndividualProject/adaptive-federated-learning/datasets"


#3. General Parameter
#++++++++++++++++++++++++++++++++++++++++++++++++++#

n_nodes = 5 # Specifies the total number of clients
MAX_CASE = 5  # Specifies the maximum number of data cases, this should be a constant equal to 5
case_to_use = 0 # Specifies which data distribution to choose, case 0 = IID
max_rounds = 500 #number of update rounds 


# 4. Detection Tool activate / deactivate and decide for parameter
#++++++++++++++++++++++++++++++++++++++++++++++++++#
# TOOL FOR DETECTION; how many rounds to store
detection_system_activated = False
rounds_to_store = max_rounds
threshold = 1.5 #define threshold at which a node is identied malicious
percentage_of_parameters_to_include = 1 #1 = all included, 0.01= 1% included

# 5. Analysis parameter
#++++++++++++++++++++++++++++++++++++++++++++++++++#
storing_type = "date" #Options: "date" -> with date automatically, else: whatever you put as a string in here! --> important: when long models are run which run more than 1 day, you cannot use date, as it will put the results in different folders!

#Variable definition for analysis
moving_average_of = 25
percentage_of_weights_concidered_lim_case = 0.01


# 6. Type of Maliciousness
#++++++++++++++++++++++++++++++++++++++++++++++++++#
#Change depending on model:
type_malicious = "bool_switch" #Options:"bool_switch", "unvalid_0to9", "random_0to9", "unvalid_bool"


# 7. Time Frame of maliciousness
#++++++++++++++++++++++++++++++++++++++++++++++++++#
#Manually need to switch this up!
percentage_round_where_clients_turn_malicious = 0 #can be 0 or 0.3 or 0.6
percentage_round_where_clients_turn_healthy_again = 1 # can be 1 = never or 0.3 or 0.6


# 8. Full runthrough vs single case
#++++++++++++++++++++++++++++++++++++++++++++++++++#
full_analysis_all_cases = True #change to false if you manually want to test a single case or change something else -- this is for the analysis of malicious data

# 9. Amount of malicious nodes and malicious data 
#++++++++++++++++++++++++++++++++++++++++++++++++++#

# IF NOT FULL ANALYSIS; USE THOSE MODEL PARAMETERS:
# Maliciousness
percentage_of_malicious_nodes_config = 0.4
# cases in analysis: 0, 0.2, 0.4, 0.6, 0.8, 1
percentage_malicious_data_config = 0.8
# cases in analysis: 0.2, 0.4, 0.6, 0.8, 1
case_no_for_analysis_config = 9 # specify which case you want to do is!

# THIS IS FOR FULL ANALYSIS: 
#IMPORTANT' THIS IS HARDCODED; CHANGE IF NUMBER OF CASES CHANGES
list_percentages_data_cases = [0.2, 0.4, 0.6, 0.8, 1]
list_percentages_node_cases = [0, 0.2, 0.4, 0.6, 0.8, 1]
highest_case = 25