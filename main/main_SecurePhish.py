import hashlib
import requests
import csv
import time
import json
import _md5
from bs4 import BeautifulSoup


# Define the URL of the webpage to crawl
try:
    url = 'https://7SAH.numexi.com'

    # Send a GET request to the webpage
    response = requests.get(url)

    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find all the links in the webpage
    links = []
    for link in soup.find_all('a'):
        link_href = link.get('href')
        if link_href and link_href.startswith('http'):
            links.append(link_href)

    # Find all the words in the webpage
    words = []
    for string in soup.stripped_strings:
        words.extend(string.split())


    def hashCheck(url):
        hashmd5 = hashlib.md5(url.encode())
        hashURL = hashmd5.hexdigest()
        # print(hashURL)
        endpoint = "https://www.virustotal.com/vtapi/v2/file/report"
        api_key = "cba7be062a9ab5a632df53960ebd59776197d14b0bc901a217f918884497362d"
        file_hash = hashURL
        params = {"apikey": api_key, "resource": file_hash}

        # Send a GET request to the API endpoint
        response = requests.get(endpoint, params=params)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Process the API response (e.g., extract data from JSON)
            data = response.json()
            if data.get('response_code') == 0:
                print("You are good to go.")
    for link in links:
        hashCheck(link)
except requests.exceptions.ConnectionError as error:
    print("Invalid or MALICIOUS site.")
