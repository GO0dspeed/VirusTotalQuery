#!/usr/local/bin/python3
# queryVT.py - Query VirusTotal API for information about the hash of an
# executable
# usage: queryVT.py <file/url> <url/hash>

import requests
import logging
import json
import urllib3
import configparser
import os
import sys


# logging ish
logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s - %(message)s')
logging.disable(logging.CRITICAL)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Sanity Check: Verify that there are three arguments
if len(sys.argv) < 3:
	print('usage: queryVT.py <file/url> <url/hash>')
	sys.exit()

# Check for the existence of a config file. If not create one
config = configparser.ConfigParser()
if os.path.isfile('./VTconfig.ini'):
	config.read('./VTconfig.ini')
else:
	print('Looks like there is no current configuration file. Lets create one in ' + os.path.curdir)
	config['VIRUSTOTAL'] = {}
	apiKey = config['VIRUSTOTAL']
	apiKey['apikey'] = input('Please enter your VirusTotal API key:\n')
	with open('./VTconfig.ini', 'w') as configFile:
		config.write(configFile)
	config.read('./VTconfig.ini')

# empty dictionary to define the paramaters for requests to fill out
params = {}

params['apikey'] = config['VIRUSTOTAL']['apikey'] 														# my API key
params['resource'] = sys.argv[2] 																		# Hash is the second argument from sys
# more logging ish for debugging
logging.debug('The paramaters are %s' % params)

# URL for VirusTotal api
urlfile = 'https://www.virustotal.com/vtapi/v2/file/report'
urlurl = 'https://www.virustotal.com/vtapi/v2/url/report'

# Request to VirusTotal
if sys.argv[1] == 'file':
	response = requests.get(urlfile, params=params, verify=False)
elif sys.argv[1] == 'url':
	response = requests.get(urlurl, params=params, verify=False)



# more logging ish for debugging
logging.debug('The url is %s' % response.request.url)

# Data is stored as a python dictionary
vtData = json.loads(response.text, encoding=object)

try:
	print('\nResults: \n')
	print('Scan date: %s' % vtData['scan_date'])														# Print the scan date
	print('%s out of %s engines detected this file' % (vtData['positives'], vtData['total']))			# Print how many engines detected this as malicious
	print('The sha256 hash of this file is %s \n' % vtData['sha256'])									# Print the hash of the file
except:
	KeyError
	print('No Detections')
	sys.exit()
# Loop though keys and verify if hash has been detected by an Anti Virus
print('AntiVirus Detections:\n')
for keys, values in vtData['scans'].items():
	if values.get('detected'):
		scanResult = values.get('result')
		print(f'{keys:20}  {scanResult:20}')
