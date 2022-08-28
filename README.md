### Adaptive Federated Learning in Resource Constrained Edge Computing Systems

This repository includes source code for the paper S. Wang, T. Tuor, T. Salonidis, K. K. Leung, C. Makaya, T. He, and K. Chan, "Adaptive federated learning in resource constrained edge computing systems," IEEE Journal on Selected Areas in Communications, vol. 37, no. 6, pp. 1205 – 1221, Jun. 2019.

More specifically: all code in the folders util_reused_code, models_reused_code and data_reader_reused_code, as well as the function calls for those functions in the respective folders and the remote procedure calls within serverAH.py and clientAH.py

### Mitigating Security concerns for Federated Learning 

This repository is part of a MSc Computing Individual Project by Anne-Sophie Hannes. It build upon cornerstones of the Adaptive Federated Learning in Resource Constrained Edge Computing Systems code repository and added functionality by changing it into an malicious Federated Learning enviornment analyis tool.

All code from analyser.py, all_cases_analyser.py, detectionTool.py is original. Almost all parts of the code in serverAh.py, clientAH.py and config.py are original, however small parts have been reused from the original repositories. 

#### Getting Started

This repository requires Python 3 with Tensorflow version 1 ((>=1.13). 
If you have already a suitable environment install the dependencies by running: pip3 install -r requirements.txt

Otherwise, a good way to install the environment is using Anaconda:
1. Download anaconda 
2. Use the following command: `conda create --name env_project python=3.6.13 tensorflow=1.15.0 matplotlib=3.3.4 numpy=1.19.2`
3. Activate enviornment: `Conda activate evn_project`
4. To deactivate: `Conda deactivate`

Download the `datasets` and put them into the dataset folder:
- For MNIST dataset, download from <http://yann.lecun.com/exdb/mnist/> and put the standalone files into `datasets/mnist`.
- For CIFAR-10 dataset, download the "CIFAR-10 binary version (suitable for C programs)" from <https://www.cs.toronto.edu/~kriz/cifar.html>, extract the standalone `*.bin` files and put them into `datasets/cifar-10-batches-bin`.

To test the code: 
- Select all the settings wanted in `config.py`
- Run `serverAH.py` and wait until you see `Waiting for incoming connections...` in the console output.
- Run as many parallel instances of `clientAH.py` as selected in terminals
- The Terminals will show prints of what is happening in the background 
- The `analysis_results` folder will have all the results

#### Code Structure

`config.py` is the file where all configurations to run this repositories can be made. A more detailed instruction is provided in `config.py`.

The folder `analysis_results` contains the results, once a code ran through. It is stored depending on the setup in config file, but the default is storing it under the date. 

Currently, the supported datasets are MNIST and CIFAR-10, and the supported models are SVM and CNN. The code can be extended to support other datasets and models too.  

#### Contributors

Part of this code was written by Shiqiang Wang and Tiffany Tuor.
The other part, as mentioned above was written by Anne-Sophie Hannes