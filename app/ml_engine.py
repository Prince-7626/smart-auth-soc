import numpy as np
from sklearn.ensemble import IsolationForest

ml_data = []
model = IsolationForest(contamination=0.1)

def detect_anomaly(ip, count):
    ml_data.append([count])

    if len(ml_data) < 10:
        return False

    X = np.array(ml_data)
    model.fit(X)
    prediction = model.predict([[count]])

    return prediction[0] == -1
