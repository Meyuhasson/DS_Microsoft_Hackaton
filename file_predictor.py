import pickle
import json
import time

Randomforest = pickle.load(open(r"RandomForest_model.sav", "rb"))
diction = {"A": 1, "B": 2, "C": 3}
output_file = open("JS_classifier.json", "w")
json.dump(diction, output_file)
output_file.close()
time.sleep(3)
print ("end of function")