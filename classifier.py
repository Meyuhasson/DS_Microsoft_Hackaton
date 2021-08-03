from feature_extraction import tfidf_extractor
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_validate
from sklearn.metrics import accuracy_score, precision_score, recall_score, make_scorer
from scipy.sparse import vstack
import pickle

def main():

    print("[+] Extracting TF-IDF vectors from data")
    benign_tfidf, malicious_tfidf = tfidf_extractor(1,1)

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
    random_forest = RandomForestClassifier()
    scores = cross_validate(random_forest, all_samples, all_classes, scoring = {"accuracy": make_scorer(accuracy_score), 
                            "precision" : make_scorer(precision_score), "recall": make_scorer(recall_score)}, cv=kfold)

    print("[+] Evaluating model")
    
    accuracy = scores["test_accuracy"].mean()
    precision = scores["test_precision"].mean()
    recall = scores["test_recall"].mean()
    print(f"\t- Accuracy = {accuracy}") # (tp + tn) / (tp + tn + fp + fn)
    print(f"\t- Precision = {precision}") # tp / (tp + fp)
    print(f"\t- Recall = {recall}") # tp / (tp+fn)

    # save model weights
    pickle.dump(random_forest, open("RandomForest_model.sav",'wb'))




if __name__ == "__main__":
    main()

