from analyser import Analayser
from models.get_model import get_model
from data_reader.data_reader import get_data
from util.utils import send_msg, recv_msg, get_indices_each_node_case
from configAH import *

import socket
import numpy as np

# Tempory define case here, later in an analyser overview to switch between them!!
case = 0

# Get Data
train_image, train_label, test_image, test_label, train_label_orig = get_data(dataset, total_data, dataset_file_path)

# Get Model
model = get_model(model_name)
if hasattr(model, 'create_graph'):
    model.create_graph(learning_rate=step_size)

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

# Get Indices for Clients
indices_each_node_case = get_indices_each_node_case(n_nodes, MAX_CASE, train_label_orig)

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

    # note in here send, if client is malicious or not! and depending on this change for loop - send two bools: malicious or not malicios and percentage of maliciousnes (if malcious)

# An Stelle zwei for loops könnte ich auch eine liste machen für jeden case:
# this_node = case_list[n]
# if(this_node ==

#send information to client to initialise!

number_of_malicious_nodes = 1
percentage_of_maliciousness = 0
client_malicious_list = [True, False, False, False, False]



# Old Version
#for n in range(0, n_nodes):
    #number_this_node = n
    #indices_this_node = indices_each_node_case[case_to_use][n]
    # Send data 
    #msg = ['MSG_INIT_SERVER_TO_CLIENT', model_name, dataset, step_size,
    #        batch_size, total_data, indices_this_node, number_this_node]
    #send_msg(client_sock_all[n], msg)


# For Loop for health nodes
for n in range(0, n_nodes):

    #maybe also go back to other version with! 
    node_counter = 0
    client_malicious = False
    # Think about it!!

    # Initialise node and their parameters
    number_this_node = n
    indices_this_node = indices_each_node_case[case_to_use][n]
    
    # healthy nodes are not malicious
    client_malicious = client_malicious_list[n]

    if(client_malicious):
        percentage_of_maliciousness = 0

    # Send data 
    msg = ['MSG_INIT_SERVER_TO_CLIENT', model_name, dataset, step_size,
            batch_size, total_data, indices_this_node, number_this_node, client_malcious, percentage_of_maliciousness]
    send_msg(client_sock_all[n], msg)

# For Loop for malicious nodes
for n in range(0, number_of_nodes_malicious):
    #thest 
    # Maybe don't need this, see other idea!!
    hi = 0


# Receive messages from clients that data prep is done!
for n in range(0, n_nodes):
    recv_msg(client_sock_all[n], 'MSG_DATA_PREP_FINISHED_CLIENT_TO_SERVER')

#initilise iterator
iterator = 0

#Start Analyser
number_of_parameters = len(w_global)
analyser = Analayser(n_nodes, number_of_parameters, max_rounds, case)

while True:

    # Send messages to Client
    for n in range(0, n_nodes):
        msg = ['MSG_WEIGHT_TAU_SERVER_TO_CLIENT', w_global, prev_loss_is_min]
        send_msg(client_sock_all[n], msg)
    
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

    print("Loss of previous global value (from nodes): " + str(loss_last_global))
    print("Minimum loss (from nodes): " + str(loss_min))
    print("Minimum Loss (from nodes) was captured in round", i_min_loss)

    # note apparently we are using the old w to calculate a loss in client and then take this as a value! Which means that the last learning round is never fully accurat. 
    # Does it not make more sense to make the evaluation in here - just check with some of the test data and then calculate loss / accuracy?

    # In here evaluate loss and accuracy with test data!
    loss_this_global = model.loss(test_image, test_label, w_global)
    accuracy_this_global = model.accuracy(test_image, test_label, w_global)

    analyser.new_loss_accuracy(loss_this_global, accuracy_this_global)

    #Iterator +1
    iterator += 1
    print("We finished round number", iterator)

    #check for last round
    if iterator == max_rounds:
        print('---------------------------------------------------------------------------')
        print(str(iterator) + " iterations have been run through, break connection!")
        analyser.FinalAnalysis()
        exit()



