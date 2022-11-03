from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy

app =Flask(__name__)
Bootstrap(app)

@app.route('/')
def home():
    return render_template('index.html')

if __name__ =='__main__':
    app.run(debug=True)

