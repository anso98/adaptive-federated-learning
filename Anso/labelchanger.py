
# so mnist_extractor.py creates two lists lables and data
# this could be the first point where we could change the lables in the first round already
# the second touch point is in data_reader.py there we create train_image, train_label, test_image, test_label, train_label_orig
# Now we use this within the central server and send it to the nodes
# do I want to poison all data or just the data for the nodes?
# probably only one of the nodes, so I need to find out how the data is distributed to the nodes
# how is it distrubuted how can I change it?

def create_malicious_data(train_label, number_of_node, percentage):
    #use percentage to define how much of the data should 
    for i in train_label:
        #reverse the thing
        train_label[i] = train_label[i] * -1

def create_accuracy_graph():
    # use this function to print accuracy graph

def save_local_parameters(number_of_node, sim_round):
    #use this function for all nodes to save the local parameters, I would like to be able to analyse the difference between them

def save_global_parameters(sim_round):
    #use this function to save global parameters

#next steps: 
    # find the parameters, how they look like
    # deactive controler algorithm look into it before meeting tomorrow
    # structure the excel / document where to store data







