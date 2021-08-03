# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D,Flatten,Dense,Dropout
tf.config.run_functions_eagerly(True)
from mnist import MNIST
import numpy as np
import keras
from keras.utils.all_utils import to_categorical
import argparse
import subprocess
import json
import os
import shutil

MNIST_PATH = './5_Mnist'
MODEL_WEIGHTS = './Model_Weights/analyzer_weights.h5'

def read_data(path):
    mndata = MNIST(path)
    images_test, _ = mndata.load_training()

    test_data = np.array(images_test).reshape((np.array(images_test).shape[0], 28, 28))
    # Normalize data
    test_data = test_data / 255.0
    return test_data

def load_model(path_to_weights):
    model_layers = [Conv2D(32, (5, 5), activation='relu', input_shape=(28, 28, 1), padding='same'),
                    MaxPooling2D(pool_size=(2, 2), padding='same'),
                    Conv2D(64, activation='relu', kernel_size=(5, 5), padding='same'),
                    MaxPooling2D(padding='same'),
                    Flatten(),
                    Dense(1024, activation='relu'),
                    Dense(2, activation='softmax')]
    model = Sequential(model_layers)
    model.load_weights(path_to_weights)
    new_model = Sequential(model)
    print("Model Loaded")
    return new_model


def analyze(path, weight_path):
    test_data = read_data(path)
    model = load_model(weight_path)
    print(test_data.shape)
    output = model.predict(test_data.reshape(-1, 28, 28, 1))
    n_pos = [{"Session_Number": ind,"Malicious": x[1], "Benign" : x[0]} for ind,x in enumerate(output) if (x[0] < 0.5 and x[1] > 0.5)]
    n_neg = [{"Session_Number": ind,"Malicious": x[1], "Benign" : x[0]} for ind,x in enumerate(output) if (x[0] > 0.5 and x[1] < 0.5)]
    output_mal_sess = "Malicious Sessions Confidence:" + str(n_pos)
    output_mal_pre = "Malicious Sessions In Pcap: " + str((len(n_pos)/len(output))*100) + "%"
    output_benign_sess = "Benign Sessions In Pcap: " + str((len(n_neg) / len(output))*100) + "%"
    return n_pos,n_neg

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # Instantiate the parser
    parser = argparse.ArgumentParser(description="DeepPacket - Deep Packet Analyzer")
    parser.add_argument('--preprocess', type=str,nargs='?',
                        help='Is preprocessing required? Y/N')
    parser.add_argument('--retrain', type=str,nargs='?',
                        help='Is retraining required? Y/N Retraining will use the same folder as the testing folder'
                             'so clear out any remaining pcaps from testing there.')
    args = parser.parse_args()
    if args.preprocess == "Y":
        # If we preprocess then all the files in 0_Pcaps will be preprocessed
        p = subprocess.Popen(["powershell", "./1_Pcap2Session.ps1"]).wait()

        p = subprocess.Popen(["powershell", "./2_ProcessSession.ps1"]).wait()

        p = subprocess.Popen(["python", "3_Session2png.py"]).wait()

        p = subprocess.Popen(["python", "4_Png2Mnist.py"]).wait()

    pos, neg = analyze(MNIST_PATH, MODEL_WEIGHTS)
    if len(pos) >= 1:
        output_json = {"Malicious": True, "Event": "Malicious Traffic Detected", "Confidence": max([x["Malicious"] for x in pos]), "Multicase": pos}
    else:
        output_json = {"Malicious": False, "Event": "Benign Traffic", "Confidence": 0.0, "Multicase": pos}
    print(output_json)
    with open('data.json', 'w') as f:
        json.dump(output_json, f)

    # CLEAN UP
    import os
    import glob

    for root, dirs, files in os.walk('./1_Pcap'):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))

    for root, dirs, files in os.walk('./2_Session'):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))

    for root, dirs, files in os.walk('./3_ProcessedSession'):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))

    for root, dirs, files in os.walk('./4_Png'):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))

    for root, dirs, files in os.walk('./5_Mnist'):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
