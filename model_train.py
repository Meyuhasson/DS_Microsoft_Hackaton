import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn import metrics
import pickle

RAZ_PATH = r"C:\Users\leguy\OneDrive\Desktop\Raz"
WINDOWS_MALWARE_PATH = r"C:\Users\leguy\OneDrive\Desktop\Raz\malwares"
WINDOWS_LEGIT_PATH = r"C:\Windows\System32"
FLOSS_PATH = r"C:\Users\leguy\OneDrive\Desktop\Raz\floss.exe"
LEGIT_STRINGS_PATH = r"C:\Users\leguy\OneDrive\Desktop\Raz\LegitStrings"
MAL_STRINGS_PATH = r"C:\Users\leguy\OneDrive\Desktop\Raz\MalStrings"


legit_strings = []
mal_strings = []
for file in os.listdir(LEGIT_STRINGS_PATH):
    try:
        with open(os.path.join(LEGIT_STRINGS_PATH, file),'r') as f:
            data = f.read()
        legit_strings.append(data)
    except:
        continue
for file in os.listdir(MAL_STRINGS_PATH):
    try:
        with open(os.path.join(MAL_STRINGS_PATH, file),'r') as f:
            data = f.read()
        mal_strings.append(data)
    except:
        continue
print("Sdgdg")
badQueries = list(set(mal_strings))
validQueries = list(set(legit_strings))
allQueries = badQueries + validQueries
yBad = [1 for i in range(0, len(badQueries))]  #labels, 1 for malicious and 0 for clean
yGood = [0 for i in range(0, len(validQueries))]
y = yBad + yGood
queries = allQueries

vectorizer = TfidfVectorizer(min_df = 0.0, analyzer="char", sublinear_tf=True, ngram_range=(1,5)) #converting data to vectors
X = vectorizer.fit_transform(queries)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42) #splitting data

badCount = len(badQueries)
validCount = len(validQueries)

clf = RandomForestClassifier(max_depth=15, random_state=2)
clf.fit(X_train, y_train)
print(clf.score(X_test,y_test))

filename_model = RAZ_PATH + '//Second//rfc_model.sav'
filename_vectorizer = RAZ_PATH + '//Second//vectorizer.sav'
pickle.dump(vectorizer, open(filename_vectorizer, 'wb'))
pickle.dump(clf, open(filename_model, 'wb'))