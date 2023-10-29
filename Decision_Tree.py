from pandas import read_csv
from sklearn.model_selection import train_test_split
from sklearn import tree
from sklearn.metrics import f1_score
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt

data = read_csv('data-set/MalwareDataSet.csv')

data.shape
data.describe()
data.groupby(data['legitimate']).size()

features = data.iloc[:,[0, 1, 2, 3, 4, 5, 6, 7]].values		# extracting thr first 8 columns from the dataset - features

print(features)

ifMalware = data.iloc[:, 8].values

features_train, features_test, ifMalware_train, ifMalware_test = train_test_split(features, ifMalware, test_size=0.25)
dtModel = tree.DecisionTreeClassifier()		# Defined the model
dtModel.fit(features_train, ifMalware_train)	# Provided training data

dtPredict = dtModel.predict(features_test)	# Give the test data then call predict.

print("Number if mislabeled out of a total of %d test entries: %d" % (features_test.shape[0], (ifMalware_test != dtPredict).sum()))

successRate = 100 * f1_score(ifMalware_test, dtPredict, average='micro') # Success rate calculation
print("The Success Rate was calculated as % : "+str(successRate) + " with the Decision Tree.")

cm = confusion_matrix(ifMalware_test, dtPredict)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Not Malware", "Malware"]).plot()
disp.plot(cmap=plt.cm.Blues)

plt.show()

