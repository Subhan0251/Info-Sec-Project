from flask import Flask, render_template, request, redirect, url_for, flash
from flask_talisman import Talisman
from kyber_py.kyber import Kyber512
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
csp = {
    'default-src': "'self'",
    'style-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
}

app = Flask(__name__)
app.secret_key = os.urandom(24)
Talisman(app,content_security_policy=csp)

# Store keys in memory for this demo
keys = {"public_key": None, "private_key": None}

@app.route("/")
def index():
    return render_template("index.html", keys=keys)

@app.route("/generate_keys", methods=["POST"])
def generate_keys():
    public_key, private_key = Kyber512.keygen()
    keys["public_key"] = public_key
    keys["private_key"] = private_key
    flash("Keys generated successfully!", "success")
    return redirect(url_for("index"))

@app.route("/encrypt", methods=["POST"])
def encrypt():
    message = request.form.get("message")
    if not keys["public_key"]:
        flash("Please generate keys first.", "danger")
        return redirect(url_for("index"))
    try:
        shared_key, capsule = Kyber512.encaps(keys["public_key"])
        aes_key = sha256(shared_key).digest()
        cipher = AES.new(aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
        ciphertext_b64 = base64.b64encode(ct_bytes).decode()
        iv_b64 = base64.b64encode(cipher.iv).decode()
        flash("Message encrypted successfully!", "success")
        return render_template("index.html", keys=keys, ciphertext=ciphertext_b64, iv=iv_b64, capsule=capsule)
    except Exception as e:
        flash("Encryption failed.", "danger")
        return redirect(url_for("index"))

@app.route("/decrypt", methods=["POST"])
def decrypt():
    ciphertext_b64 = request.form.get("ciphertext")
    iv_b64 = request.form.get("iv")
    capsule_str = request.form.get("capsule")

    if not keys["private_key"]:
        flash("Please generate keys first.", "danger")
        return redirect(url_for("index"))
    try:
        capsule = eval(capsule_str)  # Use safe deserialization in production!
        shared_key = Kyber512.decaps(keys["private_key"], capsule)
        aes_key = sha256(shared_key).digest()
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=base64.b64decode(iv_b64))
        plaintext = unpad(cipher.decrypt(base64.b64decode(ciphertext_b64)), AES.block_size).decode("utf-8")
        flash("Message decrypted successfully!", "success")
        return render_template("index.html", keys=keys, plaintext=plaintext)
    except Exception as e:
        flash("Decryption failed.", "danger")
        return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)

