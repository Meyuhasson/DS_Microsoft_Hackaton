# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D,Flatten,Dense,Dropout
tf.config.run_functions_eagerly(True)
from mnist import MNIST
import numpy as np
import tensorflow.keras as keras
from tensorflow.keras.utils import to_categorical
import argparse
import subprocess
import json
import os
import shutil
from sklearn.utils import shuffle

MNIST_PATH = './Testing/5_Mnist'
MODEL_WEIGHTS = './Model_Weights/analyzer_weights.h5'

def cleanup(dir):
    for root, dirs, files in os.walk(dir + '/2_Session'):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))

    for root, dirs, files in os.walk(dir + '/3_ProcessedSession'):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))

    for root, dirs, files in os.walk(dir + '/4_Png'):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))

    for root, dirs, files in os.walk(dir +'/5_Mnist'):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))

def read_data(path):
    mndata = MNIST(path)
    images_test, _ = mndata.load_training()

    test_data = np.array(images_test).reshape((np.array(images_test).shape[0], 28, 28))
    # Normalize data
    test_data = test_data / 255.0
    return test_data

def load_model(path_to_weights=None):
    model_layers = [Conv2D(32, (5, 5), activation='relu', input_shape=(28, 28, 1), padding='same'),
                    MaxPooling2D(pool_size=(2, 2), padding='same'),
                    Conv2D(64, activation='relu', kernel_size=(5, 5), padding='same'),
                    MaxPooling2D(padding='same'),
                    Flatten(),
                    Dense(1024, activation='relu'),
                    Dense(2, activation='softmax')]
    model = Sequential(model_layers)
    if path_to_weights:
        model.load_weights(path_to_weights)
        model = Sequential(model)
    else:
        model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    print("Model Loaded")
    return model


def analyze(path, weight_path):
    test_data = read_data(path)
    model = load_model(weight_path)
    print(test_data.shape)
    output = model.predict(test_data.reshape(-1, 28, 28, 1))
    n_pos = [{"Session_Number": ind,"Malicious": float(x[1]), "Benign" : float(x[0])} for ind,x in enumerate(output) if (x[0] < 0.5 and x[1] > 0.5)]
    n_neg = [{"Session_Number": ind,"Malicious": float(x[1]), "Benign" : float(x[0])} for ind,x in enumerate(output) if (x[0] > 0.5 and x[1] < 0.5)]
    output_mal_sess = "Malicious Sessions Confidence:" + str(n_pos)
    output_mal_pre = "Malicious Sessions In Pcap: " + str((len(n_pos)/len(output))*100) + "%"
    output_benign_sess = "Benign Sessions In Pcap: " + str((len(n_neg) / len(output))*100) + "%"
    return n_pos,n_neg



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # Instantiate the parser

    print(r"""\

 __  .__   __.  _______   _______ .______   .___________. __    __  
|  | |  \ |  | |       \ |   ____||   _  \  |           ||  |  |  | 
|  | |   \|  | |  .--.  ||  |__   |  |_)  | `---|  |----`|  |__|  | 
|  | |  . `  | |  |  |  ||   __|  |   ___/      |  |     |   __   | 
|  | |  |\   | |  '--'  ||  |____ |  |          |  |     |  |  |  | 
|__| |__| \__| |_______/ |_______|| _|          |__|     |__|  |__| 
                                                                    
Indepth ver 1.0 Deep Packet Analysis Created By David Schiff - 
All rights reserved  ©

Instructions:
#####################################################################
Supervised: To train the model, put all benign pcaps in the benign 1_Pcap folder,
and all your malicious pcaps in the 1_Pcap folder in the malicious folder. Use the --train option
To test the model, drop a pcap in the Testing folder and use the --test option
Unsupervised: To be implemented in version 2.0
                              
                    """)

    parser = argparse.ArgumentParser(description="DeepPacket - Deep Packet Analyzer")
    parser.add_argument('--test', type=str,nargs='?',
                        help='It testing required? Y/N')
    parser.add_argument('--train', type=str,nargs='?',
                        help='Is retraining required? Y/N Retraining will use the same folder as the testing folder'
                             'so clear out any remaining pcaps from testing there.')
    parser.add_argument('--cleanup', type=str,nargs='?',
                        help='Clean up after run? Y/N')
    parser.add_argument('--epochs', type=int, nargs='?',
                        help='N epochs on dataset')
    args = parser.parse_args()

    if args.train == "Y":
        # If we preprocess then all the files in 0_Pcaps will be preprocessed
        p = subprocess.Popen(["powershell", "./Benign/1_Pcap2Session.ps1"]).wait()

        p = subprocess.Popen(["powershell", "./Benign/2_ProcessSession.ps1"]).wait()

        p = subprocess.Popen(["python", "./Benign/3_Session2png.py"]).wait()

        p = subprocess.Popen(["python", "./Benign/4_Png2Mnist.py"]).wait()

        p = subprocess.Popen(["powershell", "./Malicious/1_Pcap2Session.ps1"]).wait()

        p = subprocess.Popen(["powershell", "./Malicious/2_ProcessSession.ps1"]).wait()

        p = subprocess.Popen(["python", "./Malicious/3_Session2png.py"]).wait()

        p = subprocess.Popen(["python", "./Malicious/4_Png2Mnist.py"]).wait()

        mndata = MNIST('./Benign/5_Mnist')
        images_ben, labels_ben = mndata.load_training()

        mndata = MNIST('./Malicious/5_Mnist')
        images_mal, labels_mal = mndata.load_training()
        images = images_mal + images_ben
        labels = labels_mal + labels_ben

        train = np.array(images).reshape((np.array(images).shape[0], 28, 28))
        train_labels = to_categorical(labels, num_classes=2)
        # Normalize data
        train = train / 255.0
        model = load_model()
        X, y = shuffle(train,train_labels)
        if not args.epochs:
            args.epochs = 20
            model.fit(x=X.reshape(X.shape[0], 28, 28, 1), y=y, verbose=1, epochs=args.epochs)
        model.save_weights(MODEL_WEIGHTS)

    if args.test == "Y":
        # If we preprocess then all the files in 0_Pcaps will be preprocessed
        p = subprocess.Popen(["powershell", "./Testing/1_Pcap2Session.ps1"]).wait()

        p = subprocess.Popen(["powershell", "./Testing/2_ProcessSession.ps1"]).wait()

        p = subprocess.Popen(["python", "./Testing/3_Session2png.py"]).wait()

        p = subprocess.Popen(["python", "./Testing/4_Png2Mnist.py"]).wait()


        pos, neg = analyze(MNIST_PATH, MODEL_WEIGHTS)
        if len(pos) >= 1:
            output_json = {"Malicious": True, "Event": "Malicious Traffic Detected", "Confidence": max([float(x["Malicious"]) for x in pos]), "Multicase": pos,  "Malicious Session Precentage": len(pos)/(len(pos)+len(neg)) }
        else:
            output_json = {"Malicious": False, "Event": "Benign Traffic", "Confidence": max([float(x["Malicious"]) for x in neg]), "Multicase": neg}
        print(output_json)
        with open('output_file.json', 'w') as f:
            json.dump(output_json, f)

    # CLEAN UP
    import os
    import glob
    if args.cleanup == "Y":
        cleanup('./Testing')
        cleanup('./Benign')
        cleanup('./Malicious')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
