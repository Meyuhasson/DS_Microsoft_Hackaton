import pickle
import json
import sys
import js_extraction
from bs4 import BeautifulSoup as bs
import esprima

# 0 - benign, 1 - malicious


def extract_script_from_html(html: str):
    soup = bs(html, "html.parser")
    scripts = []
    for script in soup.find_all("script"):
        scripts.append(script)
    return scripts

def tokenize_html(html: str):
    scripts_tokenize = []
    for script in extract_script_from_html(html):
        scripts_tokenize.append(esprima.tokenize(script))
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


file_path = sys.argv[1]

Randomforest = pickle.load(open(r"RandomForest_model.sav", "rb"))
tfidf_vector = pickle.load(open(r"tfidfvectorizer.sav", "rb"))
flag = False
if(file_path.endswith('.js')):
    flag = True
tokenized_file = tokenize(file_path,flag)
flat = []

if flag == False:
    for f in tokenized_file:
        flat.append(" ".join([f"{token.type}_{token.value.replace(' ', '-')}" for token in tokenized_file]))
else:
    flat = " ".join([f"{token.type}_{token.value.replace(' ', '-')}" for token in tokenized_file])

tfidf_score = tfidf_vector.transform([flat])
predict = Randomforest.predict(tfidf_score)

output = {"Malicious": bool(predict), "Event": "-----------", "Confidence":"----------", "Multicase": "-----------"}
output_file = open("JS_classifier", "w")
json.dump(output, output_file)
output_file.close()