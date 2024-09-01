import pandas as pd
import sys
#from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

# sudo python3 ai.py bruteforce results/bruteforce_packetInfo.csv

baseName = sys.argv[1];
fileName = sys.argv[2];
pd.set_option('display.max_columns', None)
#pd.set_option('display.max_rows', None)

data = pd.read_csv(fileName)
#print(data['Info'])

data = data.dropna()
#results = data.loc[data["Malicious"] == "True"]
#print(data)


###### encoding everything aghhhhh ######
vectorizer = TfidfVectorizer(max_features=5000)
data['Source'] = data['Source'].apply(lambda x: int(''.join([format(int(octet), '03d') for octet in x.split('.')])))
data['Destination'] = data['Destination'].apply(lambda x: int(''.join([format(int(octet), '03d') for octet in x.split('.')])))
data = pd.get_dummies(data, columns=['Protocol'], prefix='Protocol')
X_info = vectorizer.fit_transform(data['Info'])
data = data.drop('Info', axis=1)
X = pd.concat([data.drop('Malicious', axis=1), pd.DataFrame(X_info.toarray(), columns=vectorizer.get_feature_names_out())], axis=1)



#print(data)


X = data.drop('Malicious', axis=1)
y = data['Malicious']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.4, random_state=42)

clf = DecisionTreeClassifier(random_state=42)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
conf_matrix = confusion_matrix(y_test, y_pred)
classification_rep = classification_report(y_test, y_pred)

#print(f'Accuracy: {accuracy}')
#print(f'Confusion Matrix:\n{conf_matrix}')
#print(f'Classification Report:\n{classification_rep}')


s = ""
s += f"Confusion Matrix:\tAccuracy: {accuracy} \n"
s += f'{conf_matrix} \n'
#s += f'Accuracy: {accuracy} \n'
#s += f'Confusion Matrix:\n{conf_matrix} \n'
s += f'Classification Report:\n{classification_rep}'
file_path = f"results/{baseName}_aiStats.txt"
with open(file_path, 'w') as file:
    file.write(s)

##### visualizing the model
from sklearn.tree import plot_tree
from sklearn.tree import export_text

tree_rules = export_text(clf, feature_names=list(X.columns))

t = tree_rules
#print(s)


##### code to write s to a file for further reading

file_path = f"results/{baseName}_aiTree.txt"
with open(file_path, 'w') as file:
    file.write(t)
