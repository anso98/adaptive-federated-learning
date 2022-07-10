#Config 
model_name = 'ModelSVMSmooth'
batch_size = 100  # 100  # Value for stochastic gradient descent
total_data = 30000  # 60000  #Value for stochastic gradient descent
step_size = 0.01
dataset = "MNIST_ORIG_EVEN_ODD"
dataset_file_path = "/Users/Anso/Code/Imperial_College/IndividualProject/adaptive-federated-learning/datasets"
n_nodes = 5  # Specifies the total number of clients
MAX_CASE = 4  # Specifies the maximum number of cases, this should be a constant equal to 4 
# Note: I don't understand why 4 cases - why do we need this!
# See Jupyter notebook for the different legth of data!
# Will use case 1!
case_to_use = 1 # use second case
SERVER_ADDR= 'localhost'   # When running in a real distributed setting, change to the server's IP address
SERVER_PORT = 51000
#sim_runs = 5 # I am defining it rn as the number of times the central server receives an update from it's clients # don't need sim rounds right now!

max_rounds = 500
