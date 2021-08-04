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

staticscripts = []

def extract_script_from_html(html: str):
    global staticscripts
    soup = bs(html, "html.parser")
    scripts = []
    for script in soup.find_all("script"):
        scripts.append(script)
    staticscripts = scripts
    return scripts

def tokenize_html(html: str):
    scripts_tokenize = []
    for script in extract_script_from_html(html):
        scripts_tokenize += esprima.tokenize(str(script))
    return scripts_tokenize

def tokenize(file_path: str, js_file=True):
    try:
        with open(file_path, "r", errors='surrogateescape') as f:
            if js_file:
                return esprima.tokenize(f.read())
            else:
                return tokenize_html(f.read())
    except Exception as e:
        print(e)
        return []
file_path = sys.argv[1]

file = tokenize(file_path,file_path.endswith('.js'))
Randomforest = pickle.load(open(r"RandomForest_model.sav", "rb"))
tfidf_vector = pickle.load(open(r"tfidfvectorizer.sav", "rb"))

flat = " ".join(["{0}_{1}".format(token.type,token.value.replace(' ','-')) for token in file])

tfidf_score = tfidf_vector.transform([flat])
predict = Randomforest.predict(tfidf_score)

output = {"Malicious": bool(predict), "Event": staticscripts, "Confidence":Randomforest.predict_proba(tfidf_score).max(), "Multicase": "-----------"}
#output_file = open("output_file.json", "w")
#pickle.dump(output, output_file)
with open('output_file.json', 'w') as f:
    json.dump(output, f)
f.close()
#output_file.close()
