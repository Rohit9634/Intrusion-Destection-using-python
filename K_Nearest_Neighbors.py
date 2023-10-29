import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import f1_score
from sklearn.metrics import confusion_matrix
from sklearn.metrics import precision_recall_curve
from sklearn import metrics
from sklearn.metrics import roc_curve, auc

data = pd.read_csv('data-set/MalwareDataSet.csv')
#print(data)
data.shape
data.describe()
data.groupby(data['legitimate']).size

features = data.iloc[:, [0, 1, 2, 3, 4, 5, 6, 7]].values    # extracting the first 8 columns from the dataset  -  features
#print(features)

ifMalware = data.iloc[:,8]
# print(ifMalware)

features_train, features_test, ifMalware_train, ifMalware_test = train_test_split(features, ifMalware, test_size=0.25)
knModel = KNeighborsClassifier(n_neighbors=1)
knModel.fit(features_train, ifMalware_train)
knPredict = knModel.predict(features_test)
print("Number of mislabeled out of a total of %d test entries: %d"%(features_test.shape[0], (ifMalware_test != knPredict).sum()))
successRate = 100*f1_score(ifMalware_test, knPredict, average='micro')
print("The Success Rate was calculated as % : " + str(successRate) + "with the K-Nearest-Neighbors")

fpr, tpr, thresholds = roc_curve(ifMalware_test, knPredict)
auc_score = auc(fpr, tpr)
plt.plot(fpr, tpr, label = 'KNeighborsClassifier (AUC={:.3f})'.format(auc_score))
plt.xlabel('False positive rate')
plt.ylabel('True Positive Rate')
plt.title('Roc Curve for Malware Detection')
plt.legend()
cm = confusion_matrix(ifMalware_test, knPredict)
cm_display = metrics.ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=[False, True])
#pc, recall = precision_recall_curve(ifMalware_test, knModel)
#disp = metrics.PrecisionRecallDisplay(precision=pc, recall=recall)
#plot_roc_curve(knModel, feature_test, ifMalware_test)
cm_display.plot()
plt.show()
