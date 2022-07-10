import socket
import struct
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
    # here was another while loop don't think it makes sense!

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

    print("This node is node number ", msg[7])


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


        # Store w_last_gloabl as w_min_loss if thats the case
        if prev_loss_is_min or ((w_prev_min_loss is None) and (w_last_global is not None)):
            w_prev_min_loss = w_last_global

        # Reinitalise the variables to Perform local iteration
        grad = None
        loss_last_global = None   # Only the loss at starting time is from global model parameter

        # get new training data
        train_indices = sampler.get_next_batch()
        print(train_indices)

        # calculate new w
        grad = model.gradient(train_image, train_label, w, train_indices)

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

        # send message to server
        # please see question to data_size_local!
        msg = ['MSG_WEIGHT_TIME_SIZE_CLIENT_TO_SERVER', w, data_size_local,
                loss_last_global, number_this_node]
        send_msg(sock, msg)

except (struct.error, socket.error):
    print('Server has stopped')
    pass