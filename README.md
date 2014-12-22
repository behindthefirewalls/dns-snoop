dns-snoop
=========
///Beta version

For a list of domains given, dns-snoop allows you to look for suspicious DNS request. You just need to provide a CSV file with the domains requested in your network to figure out if some of your hosts could be compromised. We are able to export this file with the requested domains from our event correlations.

Our CSV file has one domain per line in this format: "www.domain.org","" Notice you can change the line 144 of dns-snoop.py to adapt the script to your CSV file to split the domains as you want.


	usage: dns-snoop.py [-h] [-f FILE] [-w] [-d] [-ds] [-n] [-nl]
	
	optional arguments:

	-h, --help  show this help message and exit.
	-f FILE     path to the CSV file.
	-w          Show only domains registered in the last month.
	-d          Check for many vowels or consonants in a row. Subdomains are NOT included.
	-ds         Check for many vowels or consonants in a row. Subdomains are included.
	-n          Check if the domain names can't be resolved.
	-nl         Check if the domain names resolve a loopback address

If you are interested in this project don't hesitate to collaborate!!! We will be really glad!!!
