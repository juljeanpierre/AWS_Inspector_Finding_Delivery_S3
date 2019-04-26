import urllib3
import requests

data = # put the file location in here

url = # put the key tag to the url here

data_extract = requests.get(data).json()
print(data_extract)

