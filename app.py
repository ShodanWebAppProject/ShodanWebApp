#IDEA FROM: https://github.com/tutsplus/create-a-web-app-from-scratch-using-python-flask-and-mysql

from flask import Flask, render_template, json, request, session

app = Flask(__name__)

@app.route('/')
def main():
    return render_template('index.html')

@app.route('/signUp')
def registration():
    return render_template('signUp.html')

@app.route('/signIn')
def login():
    return render_template('signIn.html')

if __name__ == "__main__":
    app.run()
    