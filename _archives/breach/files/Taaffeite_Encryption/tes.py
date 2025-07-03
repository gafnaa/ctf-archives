
from sklearn import datasets
iris = datasets.load_iris()
x = iris.data
y = iris.target

print("Banyak data: ", len(x))