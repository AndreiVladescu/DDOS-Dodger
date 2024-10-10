from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    with open("great_success.txt") as f:
        return f.read()
    print('Client connected with success')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)