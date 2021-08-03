from sklearn.feature_extraction.text import TfidfVectorizer
import js_extraction
import pickle
import os

BENIGN_TFIDF_FNAME = "benign_tfidf.pickle"
MALICIOUS_TFIDF_FNAME = "malicious_tfidf.pickle"

def tfidf_extractor(ngramx,ngramy):
    flat_benign = []
    flat_malicious = []
    list_of_vectors_benign = []
    list_of_vectors_malicious = []


    if os.path.exists(BENIGN_TFIDF_FNAME):
        with open(BENIGN_TFIDF_FNAME,'rb') as f:
            flat_benign = pickle.load(f)
    else:
        for tokens in js_extraction.get_all_js_token(True):
            if not tokens:
                continue
            flat_benign.append(" ".join([f"{token.type}_{token.value.replace(' ','-')}" for token in tokens]))
        with open(BENIGN_TFIDF_FNAME,'wb') as f:
            pickle.dump(flat_benign,f)

    if os.path.exists(MALICIOUS_TFIDF_FNAME):
        with open(MALICIOUS_TFIDF_FNAME,'rb') as f:
            flat_malicious = pickle.load(f)
    else:
        for tokens in js_extraction.get_all_js_token(False):
            if not tokens:
                continue
            flat_malicious.append(" ".join([f"{token.type}_{token.value.replace(' ','-')}" for token in tokens]))
        with open(MALICIOUS_TFIDF_FNAME,'wb') as f:
            pickle.dump(flat_malicious,f)
    
    print("[+] Training TfidfVectorizer")
    vectorizer = TfidfVectorizer(ngram_range=(ngramx,ngramy))
    vectorizer.fit(flat_benign)
    vectorizer.fit(flat_malicious)
    
    list_of_vectors_benign = vectorizer.transform(flat_benign)
    list_of_vectors_malicious = vectorizer.transform(flat_malicious)

    return list_of_vectors_benign, list_of_vectors_malicious

#list_of_vectors_benign, list_of_vectors_malicious = tfidf_extractor(1,1)
