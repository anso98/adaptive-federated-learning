#Config 
model_name = 'ModelSVMSmooth'
batch_size = 200  # 100  # Value for stochastic gradient descent
total_data = 30000  # 60000  #Value for stochastic gradient descent
step_size = 0.01 #0.01 before
dataset = "MNIST_ORIG_EVEN_ODD"
dataset_file_path = "/Users/Anso/Code/Imperial_College/IndividualProject/adaptive-federated-learning/datasets"
n_nodes = 5  # Specifies the total number of clients
MAX_CASE = 4  # Specifies the maximum number of cases, this should be a constant equal to 4 
# Note: I don't understand why 4 cases - why do we need this!
# See Jupyter notebook for the different legth of data!
# Will use case 1!
case_to_use = 0 # use second case
SERVER_ADDR= 'localhost'   # When running in a real distributed setting, change to the server's IP address
SERVER_PORT = 51000
#sim_runs = 5 # I am defining it rn as the number of times the central server receives an update from it's clients # don't need sim rounds right now!

max_rounds = 250

# Maliciousness
number_of_malicious_nodes_config = 1
# cases in analysis: 0, 1, 2, 3, 4, 5

percentage_malicious_data_config = 0.4
# cases in analysis: 0.2, 0.4, 0.6, 0.8, 1

round_where_clients_turn_malicious_config = 0
# cases in analysis: 0, 100, 200, 300, 400

full_analysis_all_cases = True #change to false if you manually want to test a single case or change something else -- this is for the analysis of malicious data

# write different cases: 
case_no_for_analysis_config = 0

#IMPORTANT' THIS IS HARDCODED RIGHT NOW; CHANGE IF NUMBER OF CASES CHANGES
highest_case = 25


def basic_analysis_cases(previous_case):

    case_no_for_analysis = previous_case + 1

    # Basecase
    if case_no_for_analysis == 0:
        case_no_for_analysis = 0
        number_of_malicious_nodes = 0
        percentage_malicious_data = 0
    
    # 1 Node Malicious
    elif case_no_for_analysis == 1:
        number_of_malicious_nodes = 1
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 2:
        number_of_malicious_nodes = 1
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 3:
        number_of_malicious_nodes = 1
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 4:
        number_of_malicious_nodes = 1
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 5:
        number_of_malicious_nodes = 1
        percentage_malicious_data = 1

    # 2 Nodes Malicious
    elif case_no_for_analysis == 6:
        number_of_malicious_nodes = 2
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 7:
        number_of_malicious_nodes = 2
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 8:
        number_of_malicious_nodes = 2
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 9:
        number_of_malicious_nodes = 2
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 10:
        number_of_malicious_nodes = 2
        percentage_malicious_data = 1

    # 3 Nodes Malicious
    elif case_no_for_analysis == 11:
        number_of_malicious_nodes = 3
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 12:
        number_of_malicious_nodes = 3
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 13:
        number_of_malicious_nodes = 3
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 14:
        number_of_malicious_nodes = 3
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 15:
        number_of_malicious_nodes = 3
        percentage_malicious_data = 1

    # 4 Nodes Malicious
    elif case_no_for_analysis == 16:
        number_of_malicious_nodes = 4
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 17:
        number_of_malicious_nodes = 4
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 18:
        number_of_malicious_nodes = 4
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 19:
        number_of_malicious_nodes = 4
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 20:
        number_of_malicious_nodes = 4
        percentage_malicious_data = 1

    # 5 Nodes Malicious
    elif case_no_for_analysis == 21:
        number_of_malicious_nodes = 5
        percentage_malicious_data = 0.2
    elif case_no_for_analysis == 22:
        number_of_malicious_nodes = 5
        percentage_malicious_data = 0.4
    elif case_no_for_analysis == 23:
        number_of_malicious_nodes = 5
        percentage_malicious_data = 0.6
    elif case_no_for_analysis == 24:
        number_of_malicious_nodes = 5
        percentage_malicious_data = 0.8
    elif case_no_for_analysis == 25:
        number_of_malicious_nodes = 5
        percentage_malicious_data = 1

    return case_no_for_analysis, number_of_malicious_nodes, percentage_malicious_data


def get_labeling_of_case(casenumber):
    result = ''
    if casenumber == 0:
        return "no malicious node"
    if casenumber == 1:
        return "1 mal. node (20%)"
    if casenumber == 2:
        return "1 mal. node (40%)"
    if casenumber == 3:
        return "1 mal. node (60%)"
    if casenumber == 4:
        return "1 mal. node (80%)"
    if casenumber == 5:
        return "1 mal. node (100%)"
    if casenumber == 6:
        return "2 mal. node (20%)"
    if casenumber == 7:
        return "2 mal. node (40%)"
    if casenumber == 8:
        return "2 mal. node (60%)"
    if casenumber == 9:
        return "2 mal. node (80%)"
    if casenumber == 10:
        return "2 mal. node (100%)"   
    if casenumber == 11:
        return "3 mal. node (20%)"
    if casenumber == 12:
        return "3 mal. node (40%)"
    if casenumber == 13:
        return "3 mal. node (60%)"
    if casenumber == 14:
        return "3 mal. node (80%)"
    if casenumber == 15:
        return "3 mal. node (100%)" 
    if casenumber == 16:
        return "4 mal. node (20%)"
    if casenumber == 17:
        return "4 mal. node (40%)"
    if casenumber == 18:
        return "4 mal. node (60%)"
    if casenumber == 19:
        return "4 mal. node (80%)"
    if casenumber == 20:
        return "4 mal. node (100%)"    
    if casenumber == 21:
        return "5 mal. node (20%)"
    if casenumber == 22:
        return "5 mal. node (40%)"
    if casenumber == 23:
        return "5 mal. node (60%)"
    if casenumber == 24:
        return "5 mal. node (80%)"
    if casenumber == 25:
        return "5 mal. node (100%)"
    else:
        return "Not in range"