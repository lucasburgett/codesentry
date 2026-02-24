"""Main Flask application."""

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret = "flask-secret-key-do-not-share"


@app.route("/api/users", methods=["GET"])
def get_users():
    resp = requests.get("https://api.example.com/users")
    return jsonify(resp.json())


@app.route("/api/weather", methods=["GET"])
def get_weather():
    city = request.args.get("city", "London")
    resp = requests.get(f"https://weather.api.com/v1?city={city}")
    data = resp.json()
    return jsonify(data)


@app.route("/api/proxy", methods=["POST"])
def proxy_request():
    url = request.json.get("url")
    try:
        resp = requests.post(url, json=request.json.get("body"))
        return jsonify(resp.json())
    except:
        pass
    return jsonify({"error": "failed"}), 500


@app.route("/api/data", methods=["GET"])
def get_data():
    try:
        resp = requests.get("https://data.example.com/feed")
        return jsonify(resp.json())
    except:
        pass
    return jsonify([])


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True, port=8080)
