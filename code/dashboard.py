
from flask import Flask, render_template, jsonify
import csv
import os


app = Flask(__name__)

@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/api/flows')
def get_flows():
    flows = []
    try:
        with open('flow_log.csv', newline='') as f:
            reader = csv.reader(f)
            for row in reader:
                flows.append({
                    "time": row[0],
                    "src": row[1],
                    "dst": row[2],
                    "proto": row[3],
                    "len": row[4],
                    "ml": row[7],
                    "mud": row[8],
                })
    except FileNotFoundError:
        pass
    return jsonify(flows)

@app.route('/api/trust')
def get_trust():
    trust_scores = {}
    if os.path.exists('trust_scores.csv'):
        with open('trust_scores.csv') as f:
            for line in f:
                ts, ip, score = line.strip().split(",")
                trust_scores[ip] = float(score)
    return jsonify(trust_scores)

if __name__ == '__main__':
    app.run(debug=True)
