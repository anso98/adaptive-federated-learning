import socket
import struct
import random
import numpy as np
from configAH import *
from data_reader.data_reader import get_data
from models.get_model import get_model
from util.sampling import MinibatchSampling
from util.utils import recv_msg, send_msg


# Connect to server
sock = socket.socket()
sock.connect((SERVER_ADDR, SERVER_PORT))

('---------------------------------------------------------------------------')

try:

    # Need this while loop for the different cases!
    while(True):

        # receive message and store information
        msg = recv_msg(sock, 'MSG_INIT_SERVER_TO_CLIENT')
        #['MSG_INIT_SERVER_TO_CLIENT', model_name, dataset, step_size, batch_size, total_data, indices_this_node, number_this_node]

        # Store information
        model_name = msg[1]
        dataset = msg[2]
        step_size = msg[3]
        batch_size = msg[4]
        total_data = msg[5]
        indices_this_node = msg[6]
        number_this_node = msg[7]
        client_malicious = msg[8]
        percentage_maliciousness = msg[9]
        round_turning_malicious = msg[10]
        round_turning_healthy_again = msg[11]

        print('---------------------------------------------------------------------------')
        print('---------------------------------------------------------------------------')

        print("Node number:", msg[7])
        if(client_malicious):
            print("Node malicious to", (percentage_maliciousness) *100, "percent")
            print("Node turns malicious in round", round_turning_malicious)
            if round_turning_healthy_again == max_rounds:
                print("Node stays malicious")
            else:
                print("Node turns healthy again in round ", round_turning_healthy_again)
        else:
            print("This node is not malicious")

        # Initialise model
        model = get_model(model_name)

        if hasattr(model, 'create_graph'):
            model.create_graph(learning_rate=step_size)

        # Get Data
        # Note: this only needs to be done once, take it out of while loop!
        train_image, train_label, _, _, _ = get_data(dataset, total_data, dataset_file_path)

        # Prepare Data in Batch
        sim = 1 #just for now, find out what it is
        sampler = MinibatchSampling(indices_this_node, batch_size, sim)

        data_size_local = len(indices_this_node)

        # Initialise variables
        w_prev_min_loss = None
        w_last_global = None
        total_iterations = 0

        # set up done!
        msg = ['MSG_DATA_PREP_FINISHED_CLIENT_TO_SERVER']
        send_msg(sock, msg)

        while True:
            print('---------------------------------------------------------------------------')

            msg = recv_msg(sock, 'MSG_WEIGHT_TAU_SERVER_TO_CLIENT')
            # ['MSG_WEIGHT_TAU_SERVER_TO_CLIENT', w_global, prev_loss_is_min]
            w = msg[1]
            prev_loss_is_min = msg[2] # lets see why I need this?
            last_round = msg[3]

            # Store w_last_gloabl as w_min_loss if thats the case
            if prev_loss_is_min or ((w_prev_min_loss is None) and (w_last_global is not None)):
                w_prev_min_loss = w_last_global

            # Reinitalise the variables to Perform local iteration
            grad = None
            loss_last_global = None   # Only the loss at starting time is from global model parameter

            # get new training data
            train_indices = sampler.get_next_batch()

            # If node malicious, then switch train_labels of train_indicies!
            # # ONLY if we are in a round where the client is malicious!! 
            if(client_malicious and total_iterations >= round_turning_malicious and total_iterations < round_turning_healthy_again):

                print("Check I am in malicious indicies creation loop")
                # create a copy and shuffle indicies to maintain randomness
                randomised_indicies = train_indices
                random.shuffle(randomised_indicies)
                
                # take the percentage (given by server) of malicious data we need
                number_of_indicies = len(randomised_indicies)
                number_of_malicious_indicies_needed = round(number_of_indicies * percentage_maliciousness)

                #Create malicious list, list to match type of indices
                malicious_indicies = []
                
                # Create the list of indicies to be changed
                for i in range(0, int(number_of_malicious_indicies_needed)):
                    malicious_indicies.append(randomised_indicies[i])
                
                for element in malicious_indicies:
                    # switch 1 and -1 
                    train_label[element] = train_label[element] * -1

            # calculate new w
            grad = model.gradient(train_image, train_label, w, train_indices)

            # Change it back after to restore original dataset (also for loss calculation)
            if(client_malicious and total_iterations >= round_turning_malicious and total_iterations < round_turning_healthy_again):

                for element in malicious_indicies:
                    # switch 1 and -1 back 
                    train_label[element] = train_label[element] * -1

            # Calculate old loss - before updating w!
            loss_last_global = model.loss(train_image, train_label, w, train_indices)
            print('*** Loss computed from data')
            print("loss:", loss_last_global)

            # save old w 
            w_last_global = w

            # update w
            w = w - step_size * grad

            # keep track of iterations
            total_iterations += 1
            print("Total iterations:", total_iterations)
            
            #Print maliciousness again
            if(client_malicious):
                print("Client malicious (", (percentage_maliciousness)*100, "%)")
            else:
                print("Client not malicious")

            # send message to server
            # please see question to data_size_local!
            msg = ['MSG_WEIGHT_TIME_SIZE_CLIENT_TO_SERVER', w, data_size_local,
                    loss_last_global, number_this_node]
            send_msg(sock, msg)

            if last_round:
                break

except (struct.error, socket.error):
    print('Server has stopped')
    pass