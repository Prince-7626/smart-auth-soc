import numpy as np
from sklearn.ensemble import IsolationForest
import datetime

class AnomalyDetector:
    def __init__(self):
        # We will build an Isolation Forest model per user to establish a baseline of "Normal"
        # In a real enterprise system, this model state is saved to disk/S3 per user.
        self.models = {}
        self.user_history = {}
        
    def _extract_features(self, timestamp_str, location_score):
        """
        Convert a login event into a numerical feature vector.
        Features: [Hour of day (0-23), Day of Week (0-6), Location Risk Score]
        """
        try:
            # Parse typical Syslog timestamp (e.g., "Mar 06 00:35:00")
            dt = datetime.datetime.strptime(f"{datetime.datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            hour = dt.hour
            day_of_week = dt.weekday()
        except:
            # Fallback if timestamp unparseable
            now = datetime.datetime.now()
            hour = now.hour
            day_of_week = now.weekday()
            
        return [hour, day_of_week, location_score]

    def record_and_check_anomaly(self, username, timestamp_str, location_score=0):
        """
        Record a successful login and check if it's highly anomalous compared to the user's past data.
        Returns: Tuple (is_anomalous: bool, risk_score: float)
        """
        if username not in self.user_history:
            self.user_history[username] = []
            self.models[username] = IsolationForest(contamination=0.1, random_state=42)
            
        features = self._extract_features(timestamp_str, location_score)
        
        # We need at least 10 historical logins to establish a baseline for this specific user
        if len(self.user_history[username]) < 10:
            self.user_history[username].append(features)
            return False, 0.0
            
        # Fit the model on historical data
        X = np.array(self.user_history[username])
        self.models[username].fit(X)
        
        # Predict on the new login event
        prediction = self.models[username].predict([features])[0]
        
        # Calculate an anomaly score (negative scores are more anomalous)
        decision_function = self.models[username].decision_function([features])[0]
        risk_score = max(0, min(100, abs(decision_function * 100)))
        
        # Record the event for future training
        self.user_history[username].append(features)
        
        # If prediction is -1, it's an anomaly.
        is_anomalous = bool(prediction == -1)
        
        return is_anomalous, risk_score

# Left over legacy function to avoid breaking existing code just in case
ml_data = []
fallback_model = IsolationForest(contamination=0.1)
def detect_anomaly(ip, count):
    ml_data.append([count])
    if len(ml_data) < 10:
        return False
    X = np.array(ml_data)
    fallback_model.fit(X)
    return fallback_model.predict([[count]])[0] == -1
