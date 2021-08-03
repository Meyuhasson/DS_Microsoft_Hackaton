import pickle
import json
import sys
import js_extraction
from bs4 import BeautifulSoup as bs
import esprima

# 0 - benign, 1 - malicious


def extract_script_from_html(html: str):
    soup = bs(html, "html.parser")
    for script in soup.find_all("script"):
        yield script

def tokenize_html(html: str):
    for script in extract_script_from_html(html):
        for program in script:
            return esprima.tokenize(program)

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

if(file_path.endswith('.js')):
    tokenized_file = tokenize(file_path)
    flat_benign = []
    flat_benign = " ".join([f"{token.type}_{token.value.replace(' ', '-')}" for token in tokenized_file])
elif(file_path.endswith('html')):
    tokenized_file = tokenize_html(open(file_path, "rb"))
    flat_benign = []
    flat_benign = " ".join([f"{token.type}_{token.value.replace(' ', '-')}" for token in tokenized_file])

tfidf_score = tfidf_vector.transform([flat_benign])
predict = Randomforest.predict(tfidf_score)

output = {"Malicious": bool(predict), "Event": "-----------", "Confidence":"----------", "Multicase": "-----------"}
output_file = open("JS_classifier.json", "w")
json.dump(output, output_file)
output_file.close()