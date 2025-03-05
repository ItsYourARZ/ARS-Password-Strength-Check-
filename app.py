from flask import Flask, request, jsonify
import re
import requests
import hashlib

app = Flask(__name__)

def check_password_strength(password):
    # Check length
    strength = 0
    if len(password) > 7:
        strength += 1
    if re.search(r"[A-Z]", password):
        strength += 1
    if re.search(r"[a-z]", password):
        strength += 1
    if re.search(r"\d", password):
        strength += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        strength += 1

    # Check if password is leaked
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    
    breached = suffix in response.text

    return {"strength": strength, "breached": breached}

@app.route("/check_password", methods=["POST"])
def check_password():
    data = request.json
    password = data.get("password", "")
    result = check_password_strength(password)

    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
