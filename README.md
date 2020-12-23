# whodat.py
A tool for doing bulk Whois and GeoIP lookups.
Includes looking up specific data center locations for AWS and applications for Microsoft

## The Blog
www.shellntel.com/blog/2020/12/23/in-scope-or-out-of-scope

## Why?
As pentesters we continue to see our client's external scopes chging as they move more systems to the "cloud". Unfortunately, they
often forget to include systems they're hosting in AWS, Azure, Google Cloud, etc.  This makes scoping, discovery, and enumeration
more important than ever. Domain enumeration, subdomain enumeration, and passive DNS sources can uncover dozens if not hundreds of
systems. Once we know their IP addresses (resolved from FQDN), we need a quick way to see who owns them and where they are located. 
Whodat.py was written to automate this process by reading in a bulk list of IP addresses and outputting a csv containing their Whois and 
GeoIP information.

## Help and Usage
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
    
