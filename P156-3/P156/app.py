from flask import Flask, render_template, request, redirect, url_for, session,jsonify

import mysql.connector
import os



app = Flask(__name__)
app.secret_key = "your key"



# MySQL Configuration
db_connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="phishing"
)
db_cursor = db_connection.cursor()


import pickle
import numpy as np
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import tldextract

# Load the saved model
with open('model_phishing_webpage_classifier.pkl', 'rb') as file:
    loaded_model = pickle.load(file)

def extract_features_from_url(url):
    # Initial extraction from the URL
    parsed_url = urlparse(url)
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"

    # Features that can be directly extracted from the URL
    features = {
        'length_url': len(url),
        'length_hostname': len(parsed_url.netloc),
        'ip': 1 if parsed_url.hostname.replace('.', '').isdigit() else 0,  # Simplistic IP check
        'nb_dots': url.count('.'),
        'nb_qm': url.count('?'),
        'nb_eq': url.count('='),
        'nb_slash': url.count('/'),
        'nb_www': 1 if 'www' in parsed_url.netloc else 0,
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url) if url else 0,
        'ratio_digits_host': sum(c.isdigit() for c in parsed_url.netloc) / len(parsed_url.netloc) if parsed_url.netloc else 0,
        'tld_in_subdomain': 1 if ext.subdomain and ext.suffix in ext.subdomain else 0,
        'prefix_suffix': 1 if '-' in parsed_url.netloc else 0,
        # Placeholder values for features requiring more complex extraction or external data
        'shortest_word_host': 0,  # Requires parsing and analysis of the host's components
        'longest_words_raw': 0,   # Requires parsing and analysis of the entire URL
        'longest_word_path': 0,   # Requires analysis of the path component
        'phish_hints': 0,         # Requires a list of phishing-indicative terms and checking against them
        'nb_hyperlinks': 0,       # Requires fetching and parsing the HTML content
        'ratio_intHyperlinks': 0, # Same as above
        'empty_title': 0,         # Requires fetching and parsing the HTML content
        'domain_in_title': 0,     # Requires fetching the HTML content and checking the title
        'domain_age': 0,          # Requires WHOIS query or external service
        'google_index': 0,        # Requires checking with Google or using an API
        'page_rank': 0            # Requires external data or service
    }

    # Example of fetching the webpage to check for title (simplistic and for illustration only)
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.find('title').get_text() if soup.find('title') else ''
            features['empty_title'] = 1 if not title else 0
            features['domain_in_title'] = 1 if domain.lower() in title.lower() else 0
    except Exception as e:
        print(f"Error fetching the URL content: {e}")

    # Convert dictionary to list in the order expected by your model
    features_list = [features[feature] for feature in [
        'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_qm', 'nb_eq',
        'nb_slash', 'nb_www', 'ratio_digits_url', 'ratio_digits_host',
        'tld_in_subdomain', 'prefix_suffix', 'shortest_word_host',
        'longest_words_raw', 'longest_word_path', 'phish_hints',
        'nb_hyperlinks', 'ratio_intHyperlinks', 'empty_title',
        'domain_in_title', 'domain_age', 'google_index', 'page_rank'
    ]]

    return features_list


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        db_cursor.execute("INSERT INTO user (name, email, password) VALUES (%s, %s, %s)", (name, email, password))
        db_connection.commit()
        return render_template('LoginSignup.html')

    return render_template('LoginSignup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db_cursor.execute("SELECT * FROM user WHERE email = %s AND password = %s", (email, password))
        user = db_cursor.fetchone()
        print("details recived")
        if user:
            session['username'] = email
            print("user registred")
            return render_template('home.html')
    return render_template('LoginSignup.html')

@app.route ('/abstract')
def abstract():
    return render_template("abstract.html")

@app.route('/prediction',methods=['GET','POST'])
def prediction():
    if request.method=='POST':
        url=request.form['url']
        if not (url.startswith('http://') or url.startswith('https://')):
            return render_template("prediction.html", r="Enter a Valid URL!!")
        print(url)
        session['url']=url
    url_in_session = session.get('url', '')
    return render_template("prediction.html", url=url_in_session)

@app.route('/check',methods=['GET','POST'])
def check():
    if request.method=='POST':
        url=session['url']
        features = extract_features_from_url(url)
        prediction = loaded_model.predict([features])[0]  # Ensure the features are in the correct format
        session['prediction'] = int(prediction)
        url_in_session = session.get('url', '')
        if prediction==1:
            return render_template("prediction.html", r="It is Phishing website",url = url_in_session)
        else:
            return render_template("prediction.html", r="It is Legitimate website",url =url_in_session)


@app.route('/clear', methods=['POST'])
def clear():
    session.pop('url', None)  # Clear the URL from session
    session.pop('prediction', None)  # Optionally clear prediction result
    return redirect(url_for('prediction')) 

@app.route('/flag', methods=['GET','POST'])
def flag():
    url = session.get('url')
    prediction = session.get('prediction')
    if request.method == 'POST':
        # Check if you already have a list of flagged URLs, if not, create one
        if 'flagged_urls' not in session:
            session['flagged_urls'] = []

        # Add the new URL and prediction status to the flagged URLs list
        if prediction == 1:
            session['flagged_urls'].append((url, "Phishing"))
        else:
            session['flagged_urls'].append((url, "Legitimate"))

        # Update the session to store the changes
        session.modified = True
        flagged_urls=session['flagged_urls']
        session['flagged_urls_disp']=flagged_urls
        url_in_session = session.get('url', '')
        # Pass the list of flagged URLs to the template
        return render_template("prediction.html",url = url_in_session)
    return render_template("flaggedurls.html", flagged_urls=session.get('flagged_urls', []))

@app.route('/dis_flag', methods=['GET','POST'])
def dis_flag():
    flag_url=session['flagged_urls_disp']
    
    return render_template("flaggedurls.html", flagged_urls=flag_url)
    


@app.route('/visitlink', methods=['GET', 'POST'])
def visit_link():
    if 'url' in session:
        url = session['url']
        if url.startswith(('http://', 'https://')):
            return redirect(url)
        else:
            return redirect('http://' + url)
    else:
        return render_template("prediction.html")

@app.route('/back_home', methods=['GET','POST'])
def back_home():
    if 'url' in session:
        return render_template('home.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
