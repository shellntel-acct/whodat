#!/usr/bin/env python3

r"""

       _               _             ___  
      | |             | |        _  / _ \ 
 _ _ _| |__   ___   __| |_____ _| |(_( ) )
| | | |  _ \ / _ \ / _  (____ (_   _) (_/ 
| | | | | | | |_| ( (_| / ___ | | |_   _  
 \___/|_| |_|\___/ \____\_____|  \__) (_) 

Usage:
    python3 whodat.py <sourceIPfile>
    python3 whodat.py <sourceIPfile> <outputFile>
    python3 whodat.py -h | --help

Example:
    python3 whoday.py sourceiplist.txt
    python3 whoday.py sourceiplist.txt output.csv
    python3 whoday.py sourceiplist.txt \\home\\user\\output.csv

Arguments:
    <sourceIPfile>     Required -text file containing 1 IPv4 IP address per line
    <outputFile>       Optional -stores to output.csv by default

Options:
    -h, --help         show this screen

Requirements:
     pip install readchar

If using for commercial use or where rate limiting gets in the way, we recommend using
an inexpensive API key from ip-api.com for "Professional" use.

*** If using ip-api for GeoIP, you must paste your API key into the 'key' variable on line 57
*** Microsoft may block the guid below, but a new guid can be generated for free through their website

If local copies of ip-ranges.json (AWS IP ranges) and worldwide.json (MS 365 IP ranges)
do not exist in the current execution path, they will be downloaded and loaded from the 
following urls:
  -https://ip-ranges.amazonaws.com/ip-ranges.json
  -https://endpoints.office.com/endpoints/worldwide

"""

import os
import sys
import csv
import requests
import json
import urllib
from re import search
import ipaddress

# API Keys
guid = '5a42f33d-f9c8-4bb5-86a4-279fc89ae979' # GUID for Microsoft worldwide.json download (you should replace)
key = '' # Paste paid API key for xxx between the quote symbols ex. key = 'PEgSoDWfY9k08fH'

doubleline = '=' * 130
outfile = 'output.csv' # default file name for output
testIP = '1.1.1.1' #default IP for evaluation

# Default values for incomplete whois + geoip lookups
whoisResult = 'NO-whoisResult'
isp = 'NO-isp'
org = 'NO-org'
country = 'NO-country'
countryCode = 'NO-countryCode'
region = 'NO-region'
city = 'NO-city'
whoisNetblock = 'NO-whoisNetblock'
extended = 'NO-extended'

# Some regular expression magic to make life easier
isAWS = '\\b(?:AMAZO|AT-88|Amazon|AWS)\\b' # Regular expression for matching AWS whois results
isMSFT = '\\b(?:MSFT|Microsoft)\\b' # Regular expression for matching Microsoft whois results

def check_readchar():
    global readchar
    try:
        import readchar
        return True
    except ImportError:
        print('')
        print('"readchar" library not installed:  pip install readchar')
        print('If output.csv file already exists, it will be appended to!')
        print('')

def check_argv():
    try:
        exists = len(sys.argv)
        if exists == 1: # If there is only 1 argument (whodat.py), then show help
            print(__doc__)
            sys.exit()
            return
    except (IndexError, FileNotFoundError) as e:
        print(e)
        sys.exit()

# Function to check entire list of ip addresses to validate that each line contains a 'global' IP address
# Note: This does permit IPv6 addresses despite this script not supporting IPv6
def check_sourcefileIPs():
    failcount = 0
    with open(inputFile, 'r') as sourceIPs:
         for line in sourceIPs:
            testIP = line.strip()
            try:
                ipaddress.ip_address(testIP).is_global
            except (ValueError):
                print('Error: ' + testIP + ' is not a valid IP address')
                failcount = failcount + 1
    if failcount > 0:
        print('')
        print('The input file contained ' + str(failcount) + ' invalid IP address.')
        print('Remove the invalid IP addresses from the input file and try again.')
        print('')
        sys.exit()

def check_testIP(testIP):
    try:
        ipaddress.ip_address(testIP).is_global
        return 'good'
    except (ValueError):
        return 'bad'

def check_outputexists(): # Checks current running directory to see if output.csv exists
    try:
        open(outfile)
        print('')
        print('File: ' + str(outfile) + ' already exists!')
        print('Press (a) to append, (o) to overwrite or any other key to exit')
        print('')
        try:
            choice = readchar.readchar()
            if choice == 'o':
                os.remove(outfile)
        except NameError as e: # most likely because the readchar library is not installed
            print(e)
            print('readchar library required:  pip install readchar')
            sys.exit()
    except FileNotFoundError:
        return # output.csv does not exist

def get_whoisNetblock(ip):
    try:
        response = requests.get(
            # Use non-SSL due to arin.net having small DH key that is incompatible with OpenSSL
            f"http://whois.arin.net/rest/ip/{ip}",
            # Use header to prefer JSON (otherwise XML is default)
            headers = {
                "Accept": "application/json",
            },
            timeout=5, # Had occassional errors at timeout=3
        )
    except requests.exceptions.RequestException as e:
        print(e)
        return {}
    if response.status_code not in [200, 201]:
        print(f"Request failed: ({response.status_code})")
    results = response.json()
    response = (f"http{str(results['net']['ref'])[12:-2]}")
    return response

def get_whoisResult(url, address):
    try:
        response = requests.get(
            f"{url}",
            # Use header to prefer JSON (otherwise XML is default)
            headers = {
                "Accept": "application/json",
            },
            timeout=5,
        )
    except requests.exceptions.RequestException as e:
        print(e)
        return {}
    if response.status_code not in [200, 201]:
        print(f"Request failed: ({response.status_code})")
    results = response.json()
    extract = results['net']['name']
    string = str(extract)
    whoisName = string[7:-2] # Trim extra characters from both sides
    netblock = results['net']['handle']
    netblockclean = str(netblock)[7:-2] # Trim extra characters from both sides

    cidrs = results['net']['netBlocks']['netBlock']
    # checks if there is multiple netblocks returned or not
    if isinstance(cidrs, list):
        # Find the blocks that contain the address, should only return one block
        for cidr in cidrs:
            ip = ipaddress.IPv4Network(f'{address}/32')
            subnet = ipaddress.IPv4Network(f"{cidr['startAddress']['$']}/{cidr['cidrLength']['$']}")
            if ip.subnet_of(subnet):
                netblockcidrclean = str(subnet)
    else:
        netblockcidrclean = f"{cidrs['startAddress']['$']}/{cidrs['cidrLength']['$']}"

    return whoisName, netblockclean, netblockcidrclean

def get_geoipapi(ip): # This API requires a key and throttles for free users (paid key required for commercial use)
    global country, countryCode, region, city, isp, org
    try:
        response = requests.get(
            f"https://pro.ip-api.com/json/{ip}?key={key}",
            timeout=5,
        )
    except requests.exceptions.RequestException as e:
        print(e)
        return {}
    if response.status_code not in [200, 201]:
        if response.status_code == 403:
            print(f"Request failed: ({response.status_code})  <-- Most likely a bad API key")
        else:
            print(f"Request failed: ({response.status_code})")
    geoipResult = response.json()
    if str(geoipResult['status']) == 'fail':
        country = 'error'
        countryCode = 'error'
        region = 'error'
        city = 'error'
        isp = 'error'
        org = 'error'
    else:
        # Assigns variables to geoIP results
        country = geoipResult['country']
        countryCode = geoipResult['countryCode']
        region = geoipResult['regionName']
        city = geoipResult['city']
        isp = geoipResult['isp']
        org = geoipResult['org']  
    return

def get_geowhoisapi(ip): #This geoip source had good results and free
    global country, countryCode, region, city, isp, org
    try:
        response = requests.get(
            f"https://ipwhois.app/json/{ip}",
            timeout=4,
        )
    except requests.exceptions.RequestException as e:
        print(e)
        return {}
    if response.status_code not in [200, 201]:
        print(f"Request failed: ({response.status_code})")
    geoipResult = response.json()
    if str(geoipResult['success']) == 'false':
        country = 'error'
        countryCode = 'error'
        region = 'error'
        city = 'error'
        isp = 'error'
        org = 'error'
    else:
        # Assigns variables to geoIP results
        country = geoipResult['country']
        countryCode = geoipResult['country_code']
        region = geoipResult['region']
        city = geoipResult['city']
        isp = geoipResult['isp']
        org = geoipResult['org']  
    return

# This function is not currently used, but can be enabled to replace the get_geowhoisapi function
def get_geoIP(ip): #This geoip source had lacking and unreliable results, but still free and does not require an API key
    global country, countryCode, region, city
    try:
        response = requests.get(
            f"https://freegeoip.app/json/{ip}",
            timeout=7, # Needs higher timeout or errors are more likely
        )
    except requests.exceptions.RequestException as e:
        print(e)
        return {}
    if response.status_code not in [200, 201]:
        print(f"Request failed: ({response.status_code})")
    geoipResult = response.json()
    if str(geoipResult['country_code']) == '':
        country = 'error'
        countryCode = 'error'
        region = 'error'
        city = 'error'
    else:
        # Assigns variables to geoIP results
        country = geoipResult['country_name']
        countryCode = geoipResult['country_code']
        region = geoipResult['region_name']
        city = geoipResult['city']
    return

def get_awslist():
    try:
        with open('ip-ranges.json') as awsranges:
            awsdata = json.load(awsranges)
            return awsdata
    except (IndexError, FileNotFoundError):
        print('Local ip-ranges.json file does not exist.')
        print('Downloading now')
        with urllib.request.urlopen("https://ip-ranges.amazonaws.com/ip-ranges.json") as url:
            awsdata = json.loads(url.read().decode())
            return awsdata

def get_aws(ip):
    data = awsdata['prefixes'] # creates a smaller list to search in
    host = ipaddress.ip_network(ip)
    # AWS includes 2 matching records for each IP address searched. The 2nd record is more descriptive so we keep that 
    matchcount = 0 # intialize match counter to find 2nd match
    for x in range(len(data)):
        test = data[x]['ip_prefix']
        block = ipaddress.ip_network(test)
        if host.subnet_of(block) == True:
            matchcount = matchcount + 1
            if matchcount == 2:
                return data[x]

def get_msftlist():
    try:
        with open('worldwide.json') as msftranges:
            msftdata = json.load(msftranges)
            return msftdata
    except (IndexError, FileNotFoundError):
        print('Local worldwide.json file does not exist.')
        print('Downloading now')
        with urllib.request.urlopen("https://endpoints.office.com/endpoints/worldwide?clientrequestid=" + str(guid)) as url:
            msftdata = json.loads(url.read().decode())
            return msftdata

def get_msft(ip):
    host = ipaddress.ip_network(ip)
    for x in range(msftdata):
        try:
            for y in range(msftdata[x]['ips']):
                test = msftdata[x]['ips'][y]
                block = ipaddress.ip_network(test)
                try:
                    if host.subnet_of(block) == True:
                        response = ('MSFT-' + msftdata[x]['serviceAreaDisplayName'])
                        return response
                except TypeError:
                    pass
        except KeyError:
            pass
    # If no match is found inside of the Microsoft ip ranges, then check Azure
    azureserviceTagId = get_azure(ip)
    if str(azureserviceTagId) != 'None':
        return ('MSFT-' + str(azureserviceTagId))
    else:
        return ('Microsoft')

def get_azure(ip): # This function uses the azurespeed.com api, could also lookup in json object
    try:
        response = requests.get(f"https://www.azurespeed.com/api/ipinfo?ipAddressOrUrl={ip}")
    except requests.exceptions.RequestException as e:
        print(e)
        return {}
    if response.status_code not in [200, 201]:
        print(f"Request failed: ({response.status_code})")
    results = response.json()
    serviceTagId = results['serviceTagId']
    return serviceTagId

####################################################################################################################
#                                Start of main program
# ==========================================================================
#         R E A D   I N   F I L E   O F   I P    A D D R E S S E S
# ==========================================================================
check_argv() # Calls function to check if command line argument exists

try:
    inputFile = sys.argv[1]
    open(inputFile, 'r')
except FileNotFoundError as e:
    print('')
    print(e)
    print(__doc__)
    sys.exit()

try:
    outfile = sys.argv[2]
except IndexError:
    outfile = 'output.csv'

check_sourcefileIPs() # Calls function to check all source IPs to see if each is a valid address. Comment out to skip!

if check_readchar() == True: # Makes sure that the 'readchar' library is installed and imports it
    check_outputexists() # Calls function to see if output.csv exists in current running directory

try:
    awsdata = get_awslist() # Loads local ip-ranges.json or downloads it if it doesn't exist
except (TypeError, NameError):
    print('Unable to load a valid ip-ranges.json file.')
try:
    msftdata = get_msftlist() # Loads local worldwide.json or downloads it if it doesn't exist
except (TypeError, NameError):
    print('Unable to load a valid worldwide.json file.')

# ======================================================================
#                 P R I N T   H E A D E R
# ======================================================================
print('')
print('IP_Address, ARIN Whois, Service Provider, Organization, Country, Country Code, Region, City, ARIN Netblock, Cloud Specific Details')
print(doubleline)

# ======================================================================
#  V A L I D A T E   I P   A D D R E S S   B E F O R E   L O O K U P S
# ======================================================================
with open(inputFile, 'r') as sourceIPs:
  for line in sourceIPs:
    extended = 'NO-extended' # Reinitialize variable for each loop 
    testIP = line.strip()
    if check_testIP(testIP) == 'bad':
        continue
    else:
        # ======================================================================
        #         P E R F O R M   I P  L O O K U P S
        # ======================================================================

        # Calls the whoisNetblock function sending an IP address and returning
        # the URL for the ARIN netblock
        try:
            whoisURL = get_whoisNetblock(testIP)
        except ValueError:  # includes simplejson.decoder.JSONDecodeError
            print('')
            print('Invalid IP address:' + testIP + ' in source file... skipping!')
            print('')

        # Calls the whoisResult function sending a request URL and returning the
        # ARIN netblock 'name'
        try:
            whoisResult, whoisNetblock, whoisCIDR = get_whoisResult(whoisURL, testIP)
        except ValueError:
            whoisResult, whoisNetblock, whoisCIDR = 'error'

        # Calls the geoipapi function sending an IP address and returning full json
        # response containing country, state, city, isp, etc.
        if key == '':
            geoipResult = get_geowhoisapi(testIP) # Completely free, no API key required
        else:
            geoipResult = get_geoipapi(testIP) # REQUIRES free (throttled) or paid API key from https://ip-api.com

        # If ip-api is used for geoip, there is little value to the following specific lookups for AWS and Microsoft
        if search(isAWS, whoisResult):
            try:
                awsresponse = get_aws(testIP)
                service = awsresponse['service']
                awsregion = awsresponse['region']
                extended = ('Amazon-' + service + '-' + awsregion)
            except TypeError:
                pass
        if search(isMSFT, whoisResult):
            if str(whoisResult) == 'MICROSOFT-GLOBAL-NET':
                extended = 'Microsoft-Global-NET'
            else:
                try:
                    msftresponse = get_msft(testIP)
                    if msftresponse != 'None':
                        extended = msftresponse
                except:
                    pass
        # =======================================================================

        # Write out csv formatted output to screen
        write = (testIP + ',' + whoisResult + ',' + isp + ',' + org + ',' + country + ',' + countryCode + ',' + region + ',' + city + ',' + whoisNetblock + ',' + extended)
        print(write)

        # Open and append csv formatted output to output.csv file
        with open(outfile, 'a+', newline="") as file: 
            writer = csv.writer(file)
            writer.writerow([testIP,whoisResult,isp,org,country,countryCode,region,city,whoisNetblock,extended])

print('')
print('Thank you for playing, your output file is: ' + str(outfile))
print('')