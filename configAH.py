#Config 

# RMI Data
SERVER_ADDR= 'localhost'   # When running in a real distributed setting, change to the server's IP address
SERVER_PORT = 51000
#sim_runs = 5 # I am defining it rn as the number of times the central server receives an update from it's clients # don't need sim rounds right now!

# Model, dataset, and control parameter configurations for MNIST with CNN
# dataset = 'MNIST_ORIG_ALL_LABELS'  # Use for CNN model
# model_name = 'ModelCNNMnist'
# control_param_phi = 0.00005   # Good for CNN

# Model, dataset, and control parameter configurations for CIFAR-10 with CNN
#dataset = 'CIFAR_10'
#model_name = 'ModelCNNCifar10'
# control_param_phi = 0.00005   # Good for CNN

model_name = 'ModelSVMSmooth'
dataset = "MNIST_ORIG_EVEN_ODD"

type_malicious = "bool_switch" #Options:"bool_switch", "unvalid_0to9", "random_0to9", "unvalid_bool"

# Model Data
batch_size = 100  # 100  # Value for stochastic gradient descent
total_data = 30000  # 60000  #Value for stochastic gradient descent
step_size = 0.01 #0.01 before
dataset_file_path = "/Users/Anso/Code/Imperial_College/IndividualProject/adaptive-federated-learning/datasets"

#SELECT HOW TO STORE (BIG VS SMALL MODEL:)
storing_type = "date" #Options: "date" -> with date automatically, else: whatever you put as a string there!!!


n_nodes = 5  # Specifies the total number of clients
MAX_CASE = 5  # Specifies the maximum number of cases, this should be a constant equal to 4 
case_to_use = 4 # OLD: case = 1 use second case
max_rounds = 500

full_analysis_all_cases = True #change to false if you manually want to test a single case or change something else -- this is for the analysis of malicious data

# IF NOT FULL ANALYSIS; USE THOSE MODEL PARAMETERS:
# Maliciousness
percentage_of_malicious_nodes_config = 1
# cases in analysis: 0, 0.2, 0.4, 0.6, 0.8, 1
percentage_malicious_data_config = 0.4
# cases in analysis: 0.2, 0.4, 0.6, 0.8, 1
case_no_for_analysis_config = 0 # specify which case you want to do is!

#IMPORTANT' THIS IS HARDCODED; CHANGE IF NUMBER OF CASES CHANGES

list_percentages_data_cases = [0.2, 0.4, 0.6, 0.8, 1]
list_percentages_node_cases = [0, 0.2, 0.4, 0.6, 0.8, 1]
highest_case = 25

#Manually need to switch this up!
percentage_round_where_clients_turn_malicious = 0 #can be 0 or 0.3 or 0.6
percentage_round_where_clients_turn_healthy_again = 1 # can be 1 = never or 0.3 or 0.6

def basic_analysis_cases(previous_case):

    case_no_for_analysis = previous_case + 1

    # Basecase
    if case_no_for_analysis == 0:
        case_no_for_analysis = 0
        percentage_of_malicious_nodes = 0
        percentage_malicious_data = 0
    
    # 1 Node Malicious
    elif case_no_for_analysis == 1:
        percentage_of_malicious_nodes = 0.2
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 2:
        percentage_of_malicious_nodes = 0.2
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 3:
        percentage_of_malicious_nodes = 0.2
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 4:
        percentage_of_malicious_nodes = 0.2
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 5:
        percentage_of_malicious_nodes = 0.2
        percentage_malicious_data = 1

    # 2 Nodes Malicious
    elif case_no_for_analysis == 6:
        percentage_of_malicious_nodes = 0.4
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 7:
        percentage_of_malicious_nodes = 0.4
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 8:
        percentage_of_malicious_nodes = 0.4
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 9:
        percentage_of_malicious_nodes = 0.4
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 10:
        percentage_of_malicious_nodes = 0.4
        percentage_malicious_data = 1

    # 3 Nodes Malicious
    elif case_no_for_analysis == 11:
        percentage_of_malicious_nodes = 0.6
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 12:
        percentage_of_malicious_nodes = 0.6
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 13:
        percentage_of_malicious_nodes = 0.6
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 14:
        percentage_of_malicious_nodes = 0.6
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 15:
        percentage_of_malicious_nodes = 0.6
        percentage_malicious_data = 1

    # 4 Nodes Malicious
    elif case_no_for_analysis == 16:
        percentage_of_malicious_nodes = 0.8
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 17:
        percentage_of_malicious_nodes = 0.8
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 18:
        percentage_of_malicious_nodes = 0.8
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 19:
        percentage_of_malicious_nodes = 0.8
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 20:
        percentage_of_malicious_nodes = 0.8
        percentage_malicious_data = 1

    # 5 Nodes Malicious
    elif case_no_for_analysis == 21:
        percentage_of_malicious_nodes = 1
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 22:
        percentage_of_malicious_nodes = 1
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 23:
        percentage_of_malicious_nodes = 1
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 24:
        percentage_of_malicious_nodes = 1
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 25:
        percentage_of_malicious_nodes = 1
        percentage_malicious_data = 1

    return case_no_for_analysis, percentage_of_malicious_nodes, percentage_malicious_data


def get_labeling_of_case(casenumber):
    result = ''
    if casenumber == 0:
        return "no malicious node"
    if casenumber == 1:
        return "20% mal. nodes (20% mal. data)"
    if casenumber == 2:
        return "20% mal. nodes (40% mal. data)"
    if casenumber == 3:
        return "20% mal. node (60% mal. data)"
    if casenumber == 4:
        return "20% mal. node (80% mal. data)"
    if casenumber == 5:
        return "20% mal. node (100% mal. data)"
    if casenumber == 6:
        return "40% mal. node (20% mal. data)"
    if casenumber == 7:
        return "40% mal. node (40% mal. data)"
    if casenumber == 8:
        return "40% mal. node (60% mal. data)"
    if casenumber == 9:
        return "40% mal. node (80% mal. data)"
    if casenumber == 10:
        return "40% mal. node (100% mal. data)"   
    if casenumber == 11:
        return "60% mal. node (20% mal. data)"
    if casenumber == 12:
        return "60% mal. node (40% mal. data)"
    if casenumber == 13:
        return "60% mal. node (60% mal. data)"
    if casenumber == 14:
        return "60% mal. node (80% mal. data)"
    if casenumber == 15:
        return "60% mal. node (100% mal. data)" 
    if casenumber == 16:
        return "80% mal. node (20% mal. data)"
    if casenumber == 17:
        return "80% mal. node (40% mal. data)"
    if casenumber == 18:
        return "80% mal. node (60% mal. data)"
    if casenumber == 19:
        return "80% mal. node (80% mal. data)"
    if casenumber == 20:
        return "80% mal. node (100% mal. data)"    
    if casenumber == 21:
        return "100% mal. node (20% mal. data)"
    if casenumber == 22:
        return "100% mal. node (40% mal. data)"
    if casenumber == 23:
        return "100 mal. node (60% mal. data)"
    if casenumber == 24:
        return "100% mal. node (80% mal. data)"
    if casenumber == 25:
        return "100% mal. node (100% mal. data)"
    else:
        return "Not in range"