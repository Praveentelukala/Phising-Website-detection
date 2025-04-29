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

def predict_phishing_from_url(url):
    features = extract_features_from_url(url)
    prediction = loaded_model.predict([features])[0]  # Ensure the features are in the correct format
    return 'Phishing' if prediction == 1 else 'Legitimate'

# Ask user to enter URL
url = input("Enter the URL: ")

# Predict if the URL is phishing or legitimate
prediction = predict_phishing_from_url(url)
print(f"The URL '{url}' is predicted to be: {prediction}")