### 
### FTPredator
###
### Authors: 	Chris Wood (christopherwood07@gmail.com)
###				Robert Wood (robertwood50@gmail.com)
###
### Purpose:	FTPredator is a tool for FTP security auditing, it will first check IP addresses for open 
###				or poorly protected FTP services. It will then map out the directory structrue of FTP(s) 
###				services and automatically download potentially sensitive filenames for further analysis 
###				during a penetration test/red team assessment.
###

# application inputs:
#	IP addresses - copy/paste
#	IP addresses - text file import
#
# application outputs:
#	TODO
#

# imports
import ftplib

# read all usernames from the USERNAMES config file to l_usernames list
with open('USERNAMES') as f:
	l_usernames = f.read().splitlines()

# login with default credential set
def login_defaults(target):
	# TODO: step through USERNAMES and PASSWORDS files and attempt to authenticate until successful
	# or list runs out
	for i in 


def record_open_ftps(target):
	l_open_ftps = []
	l_open_ftps.append(target)

# attempt to connect over clear text FTP
def connect_ftp(host, username, password):
	ftp = FTP(target)

	# attempt anonymous login
	ftp.login()
	
	# if unsuccessful, try to log in with the default credential list
	login_defaults(ftp)


