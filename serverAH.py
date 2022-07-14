from analyser import Analayser
from models.get_model import get_model
from data_reader.data_reader import get_data
from util.utils import send_msg, recv_msg, get_indices_each_node_case
from configAH import *

import socket
import numpy as np


# Establish a connection to all clients

#Open port
listening_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listening_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listening_sock.bind((SERVER_ADDR, SERVER_PORT))
client_sock_all=[]

# Establish connections to each client, up to n_nodes clients
while len(client_sock_all) < n_nodes:
    listening_sock.listen(5)
    print("Waiting for incoming connections...")
    (client_sock, (ip, port)) = listening_sock.accept()
    print('Got connection from ', (ip,port))
    print(client_sock)

    client_sock_all.append(client_sock)


# Get Data
train_image, train_label, test_image, test_label, train_label_orig = get_data(dataset, total_data, dataset_file_path)

# Get Indices for Clients -> will now always be same - is that good or bad?
indices_each_node_case = get_indices_each_node_case(n_nodes, MAX_CASE, train_label_orig)

#Question: is the model just the model, does not learn, only thing stored is w?
# Get Model
model = get_model(model_name)
if hasattr(model, 'create_graph'):
    model.create_graph(learning_rate=step_size)


# Initialise loop variable 
execute_next_case = True
case = -1  #define invalid starting case -> will be updated in next line!


while(execute_next_case):

    #NOTE: need to think about how to connect and disconnect, or leave connection but just send new parameters and model? Not probably does not make sense, just new connection is the easiest

    #check here if full analysis should be ran or just simple test case
    if(full_analysis_all_cases == True):
        case, number_of_malicious_nodes, percentage_malicious_data = basic_analysis_cases(case) #adds one case, returns [case_no_for_analysis, number_of_malicious_nodes, percentage_malicious_data]
        if(case == highest_case):
            execute_next_case = False
    else:
        execute_next_case = False
        case = case_no_for_analysis_config #comes from Config File, set there
        # THINK ABOUT HOW TO DO IT IF ITS NOT A CASE; MAYBE DO NOT DEFINE? BUT DOES NOT WORK AS ITS INPUT FOR FUNCTIONS
        number_of_malicious_nodes = number_of_malicious_nodes_config
        percentage_malicious_data = percentage_malicious_data_config

    print('---------------------------------------------------------------------------')
    print('---------------------------------------------------------------------------')
    print("Case number", case)
    print("Number of malicious nodes:", number_of_malicious_nodes)
    print("Percentage of malicious data:", percentage_malicious_data*100)

    # Initialise weights to 0
    dim_w = model.get_weight_dimension(train_image, train_label)
    w_global_init = model.get_init_weight(dim_w)
    w_global = w_global_init

    # Q: do I need this?
    # initalise variables as in server
    w_global_min_loss = None
    loss_min = np.inf
    prev_loss_is_min = False
    i_min_loss = 0

    #send information to client to initialise!
    node_counter = 0

    # Old Version
    #for n in range(0, n_nodes):
        #number_this_node = n
        #indices_this_node = indices_each_node_case[case_to_use][n]
        # Send data 
        #msg = ['MSG_INIT_SERVER_TO_CLIENT', model_name, dataset, step_size,
        #        batch_size, total_data, indices_this_node, number_this_node]
        #send_msg(client_sock_all[n], msg)

    # For Loop for health nodes
    for n in range(0, (n_nodes - number_of_malicious_nodes)):

        # Initialise node and their parameters
        number_this_node = node_counter
        indices_this_node = indices_each_node_case[case_to_use][node_counter]

        # healthy nodes are not malicious
        client_malicious = False
        percentage_of_maliciousness = 0

        # Send data 
        msg = ['MSG_INIT_SERVER_TO_CLIENT', model_name, dataset, step_size,
                batch_size, total_data, indices_this_node, number_this_node, client_malicious, percentage_of_maliciousness]
        send_msg(client_sock_all[node_counter], msg)

        # iterate node Counter
        node_counter = node_counter + 1

    print(node_counter, "healthy nodes have received initial data for case", case)

    # For Loop for malicious nodes
    for n in range(0, number_of_malicious_nodes):

        # Initialise node and their parameters
        number_this_node = node_counter
        indices_this_node = indices_each_node_case[case_to_use][node_counter]

        # malicious nodes & there percentage of maliciousness
        client_malicious = True
        percentage_of_maliciousness = percentage_malicious_data

        # Send data 
        msg = ['MSG_INIT_SERVER_TO_CLIENT', model_name, dataset, step_size,
                batch_size, total_data, indices_this_node, number_this_node, client_malicious, percentage_of_maliciousness]
        send_msg(client_sock_all[node_counter], msg)

        # iterate node Counter
        node_counter = node_counter + 1

    # Print information
    if(number_of_malicious_nodes != 0):
        print(number_of_malicious_nodes, "malicious nodes have received initial data for case", case)

    # Receive messages from clients that data prep is done!
    for n in range(0, n_nodes):
        recv_msg(client_sock_all[n], 'MSG_DATA_PREP_FINISHED_CLIENT_TO_SERVER')

    print("All confirmation from nodes are received")

    #initilise iterator
    iterator = 0
    last_round = False

    #Start Analyser
    number_of_parameters = len(w_global)
    analyser = Analayser(n_nodes, number_of_parameters, max_rounds, case, number_of_malicious_nodes, percentage_malicious_data, full_analysis_all_cases, highest_case)

    while True:

        if (iterator + 1) == max_rounds:
            last_round = True

        # Send messages to Client
        for n in range(0, n_nodes):
            msg = ['MSG_WEIGHT_TAU_SERVER_TO_CLIENT', w_global, prev_loss_is_min, last_round]
            send_msg(client_sock_all[n], msg)
        
        print('---------------------------------------------------------------------------')
        print("Main parameters:", number_of_malicious_nodes, "malicious nodes", percentage_of_maliciousness*100, "%", "of data malicous")
        print("Round number", iterator + 1, "in case no", case)

        w_global_prev = w_global

        # Initialise new capturing data variables
        w_global = np.zeros(dim_w)
        loss_last_global = 0.0
        data_size_total = 0
        time_all_local_all = 0
        data_size_local_all = []

        for n in range(0, n_nodes):
            # delete what I don't need here!
            msg = recv_msg(client_sock_all[n], 'MSG_WEIGHT_TIME_SIZE_CLIENT_TO_SERVER')
            # ['MSG_WEIGHT_TIME_SIZE_CLIENT_TO_SERVER', w, data_size_local, loss_last_global, number_this_node]
            w_local = msg[1]
            data_size_local = msg[2]
            loss_local_last_global = msg[3]
            number_this_node = msg[4]

            #note: Tiffany did the w_global with the size of the local data (antteilig), I rather would do it equaliy, to test my model later! So changed this! (see in server.py)
            #old:
            #w_global += w_local * data_size_local
            #data_size_local_all.append(data_size_local)
            #data_size_total += data_size_local

            w_global += w_local
            
            # this is the loss calculation!
            #old:
            #loss_last_global += loss_local_last_global * data_size_local
            # Question: why time data_size_total - if I understand correctly this will only be the batch size?
            loss_last_global += loss_local_last_global

            # Analyser code!
            analyser.newData(w_local, number_this_node)

        #old:
        #w_global /= data_size_total
        w_global /= n_nodes
        analyser.newData(w_global, n_nodes)

        #old:
        #loss_last_global /= data_size_total
        loss_last_global /= n_nodes

        #Defensive Programming:
        if True in np.isnan(w_global):
            print('*** w_global is NaN, using previous value')
            w_global = w_global_prev   # If current w_global contains NaN value, use previous w_global
            use_w_global_prev_due_to_nan = True
        else:
            use_w_global_prev_due_to_nan = False

        # Updating loss_min and store w values for it!
        if loss_last_global < loss_min:
            loss_min = loss_last_global
            w_global_min_loss = w_global_prev
            i_min_loss = iterator
            prev_loss_is_min = True
        else:
            prev_loss_is_min = False

        # CHECK WITH TIFFANY THOSE VALUES _ WHY??
        print("Loss of previous global value (from nodes): " + str(loss_last_global))
        print("Minimum loss (from nodes): " + str(loss_min), "in round", i_min_loss)

        # note apparently we are using the old w to calculate a loss in client and then take this as a value! Which means that the last learning round is never fully accurat. 
        # Does it not make more sense to make the evaluation in here - just check with some of the test data and then calculate loss / accuracy?

        # In here evaluate loss and accuracy with test data!
        loss_this_global = model.loss(test_image, test_label, w_global)
        accuracy_this_global = model.accuracy(test_image, test_label, w_global)

        analyser.new_loss_accuracy(loss_this_global, accuracy_this_global)

        #Iterator +1
        iterator += 1

        #check for last round
        if iterator == max_rounds:
            print('---------------------------------------------------------------------------')
            print('---------------------------------------------------------------------------')
            print(str(iterator) + " iterations have been run through, break connection!")
            print("Case Number", case)
            analyser.FinalAnalysis()
            break



