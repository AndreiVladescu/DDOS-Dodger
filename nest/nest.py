from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    with open("great_success.txt") as f:
        f.write("Nest is running, receiving traffic.")
    return "Nest is running, receiving traffic."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)