from flask import Flask, render_template, request
app = Flask(__name__)
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

def encrypt(text):
    cipher = AES.new(app.secret_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return b64encode(cipher.iv + ciphertext).decode('utf-8')
def decrypt(encrypted_text):
    try:
        data = b64decode(encrypted_text.encode('utf-8'))
        iv = data[:AES.block_size]
        cipher = AES.new(app.secret_key, AES.MODE_CBC, iv)
        decrypted_text = unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size).decode('utf-8')
        return decrypted_text
    except Exception as e:
        print(f"Error decrypting text: {e}")
        return "Decryption error"


@app.route('/', methods=['GET', 'POST'])
def index():
    result = ''
    if request.method == 'POST':
        if 'encrypt' in request.form:
            result = encrypt(request.form['text'])
        elif 'decrypt' in request.form:
            result = decrypt(request.form['text'])
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)