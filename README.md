# AI-Based Payload Analyzer

AI-Based Payload Analyzer is a real-time web security application that detects malicious web payloads such as SQL Injection (SQLi) and Cross-Site Scripting (XSS) attacks using Machine Learning.

The system uses **TF-IDF** for feature extraction and **Random Forest** for payload classification. A Flask-based web interface allows users to analyze payloads and receive predictions with confidence scores and rule-based explanations.

---

## Features

* Real-time payload analysis
* Detects SQLi and XSS attacks
* TF-IDF feature extraction
* Random Forest classification
* Rule-based explainability
* Flask web interface
* Confidence score display

---

## Tech Stack

* Python
* Flask
* Scikit-learn
* HTML/CSS
* Pandas & NumPy

---

## Model Performance

| Model               | Accuracy |
| ------------------- | -------- |
| Logistic Regression | 99.40%   |
| Random Forest       | 99.74%   |
| LSTM                | 99.35%   |

Random Forest achieved the highest accuracy and was selected as the final model.

---

## Dataset

Dataset derived from the IEEE paper:

**“SQL Injection Attack Detection by Machine Learning Classifier” (2022)**

Labels:

* `0` → Safe Payload
* `1` → Malicious Payload

---

## Run the Project

```bash id="1n2p7w"
pip install flask pandas numpy scikit-learn
python train_model.py
python app.py
```

Open:

```text id="7k6x7j"
http://127.0.0.1:5000
```

---

## Example Payloads

Safe:

```text id="ylh2xy"
hello world
```

Malicious:

```html id="7aempr"
<script>alert(1)</script>
```

---

## Applications

* Web Security
* Intrusion Detection
* Firewall Filtering
* Cybersecurity Monitoring

---

## Author

**Karthikeya Y**

