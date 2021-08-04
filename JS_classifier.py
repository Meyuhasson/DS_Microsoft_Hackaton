import pickle
import json
import sys
import js_extraction
from sklearn.feature_extraction.text import TfidfVectorizer
from bs4 import BeautifulSoup as bs
import esprima
import os
from tqdm import tqdm
import feature_extraction
from feature_extraction import tfidf_extractor
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_validate
from sklearn.metrics import accuracy_score, precision_score, recall_score, make_scorer, roc_auc_score
from sklearn.model_selection import train_test_split
from scipy.sparse import vstack
import numpy as np
import pickle
import matplotlib.pyplot as plt
import sys

# 0 - benign, 1 - malicious


def extract_script_from_html(html: str):
    soup = bs(html, "html.parser")
    scripts = []
    for script in soup.find_all("script"):
        scripts.append(script)
    return scripts

def tokenize_html(html: str):
    scripts_tokenize = ''
    for script in extract_script_from_html(html):
        scripts_tokenize += esprima.tokenize(script)
    return scripts_tokenize

def tokenize(file_path: str, js_file=True):
    try:
        with open(file_path, "r", errors='surrogateescape') as f:
            if js_file:
                return esprima.tokenize(f.read())
            else:
                return tokenize_html(f.read())
    except:
        return []
paths_benign = []
for s, d, f in os.walk(r"C:\Users\edenm\Documents\GitHub\DS_Microsoft_Hackaton\BENIGN"):
    for file in f:
        paths_benign.append(os.path.join(s,file))
paths_mal = []
for s, d, f in os.walk(r"C:\Users\edenm\Documents\GitHub\DS_Microsoft_Hackaton\MALICIOUS"):
    for file in f:
        paths_mal.append(os.path.join(s,file))
print(2)
mal_tokenize = []
for path in tqdm(paths_mal):
    mal_tokenize.append(tokenize(path,path.endswith('.js')))

benign_tokenize = []
for path in tqdm(paths_benign):
    benign_tokenize.append(tokenize(path,path.endswith('.js')))

mal_flat = []
for item in mal_tokenize:
    mal_flat.append(" ".join(["{0}_{1}".format(token.type,token.value.replace(' ','-')) for token in item]))
benign_flat = []
for item in benign_tokenize:
    benign_flat.append(" ".join(["{0}_{1}".format(token.type,token.value.replace(' ','-')) for token in item]))

vectorizer = TfidfVectorizer()
vector = vectorizer.fit(mal_flat)
malicious_tfidf = vectorizer.transform(mal_flat)
benign_tfidf = vectorizer.transform(benign_flat)

num_benign_samples = benign_tfidf.shape[0]
num_malicious_samples = malicious_tfidf.shape[0]

# 0 - benign, 1 - malicious
benign_classifications = [0 for _ in range(num_benign_samples)]
malicious_classifications = [1 for _ in range(num_malicious_samples)]

print("[+] Preparing Train-Test data")
all_samples = vstack((benign_tfidf,malicious_tfidf))
all_classes = []
all_classes.extend(benign_classifications)
all_classes.extend(malicious_classifications)

kfold = 5
print(f"[+] {kfold} Fold Cross Validation Random Forest Classifier")
random_forest = RandomForestClassifier(warm_start=True)
scores = cross_validate(random_forest, all_samples, all_classes, scoring = {"accuracy": make_scorer(accuracy_score),
                        "precision" : make_scorer(precision_score), "recall": make_scorer(recall_score)}, cv=kfold)

print("[+] Evaluating model")

accuracy = scores["test_accuracy"].mean()
precision = scores["test_precision"].mean()
recall = scores["test_recall"].mean()
print(f"\t- Accuracy = {accuracy}") # (tp + tn) / (tp + tn + fp + fn)
print(f"\t- Precision = {precision}") # tp / (tp + fp)
print(f"\t- Recall = {recall}") # tp / (tp+fn)

random_forest.fit(all_samples, all_classes)

# save model weights
pickle.dump(random_forest, open("RandomForest_model.sav",'wb'))