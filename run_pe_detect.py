# Raz

import os
import argparse
import pickle
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn import metrics
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--path", help="path to your pe file")
args = parser.parse_args()
path_to_pe = args.path

result = subprocess.run(["floss.exe",path_to_pe], stdout=subprocess.PIPE)
file_strings = result.stdout.decode('ascii').replace("\r","")

model_path = 'rfc_model.sav' 
vectorizer_path = 'vectorizer.sav'

loaded_model = pickle.load(open(model_path, 'rb'))
vectorizer = pickle.load(open(vectorizer_path, 'rb'))
X = vectorizer.transform([file_strings])
result = loaded_model.predict(X)[0]
confidence = loaded_model.predict_proba(X)[0][result]
most_important_vals = vectorizer.get_feature_names()[X.argmax()]
dict_val = {"Malicious": str(result),"Event": "most suspicious str: " + most_important_vals,"Confidence": confidence,"Multicase": "Suspicious file strings"}

with open('output_file.json', 'w+') as fp:
    json.dump(dict_val, fp)
