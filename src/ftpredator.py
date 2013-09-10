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
import sys
import ftplib
import argparse

def check_host(host, usernames, passwords, strings):
	''' Check the host by logging in with the set of usernames
	and passwords. 

	Return a list of absolute paths to files on the host that contain sensitive words
	'''
	return []

def main(host = "", host_file = "", username_file = "USERNAMES", password_file = "PASSWORDS", string_file = "STRINGS"):
	''' Main entry point - use the specified parameters to target single/multiple hosts.
	'''
	usernames = []
	passwords = []
	strings = []

	# read all usernames/passwords from the USERNAMES/PASSWORDs config files
	with open(username_file) as f:
		usernames = f.read().splitlines()
	with open(password_file) as f:
		passwords = f.read().splitlines()
	with open(string_file) as f:
		strings = f.read().splitlines()

	# check single host or file containing all hosts
	hdump = []
	if (len(host) > 0):
		hdump.append(check_host(host, usernames, passwords, strings))
	if (len(host_file) > 0):
		with open(host_file) as f:
			hdump.append(check_host(f.readline().strip(), usernames, passwords, strings))

	# TODO: do something with hdump!

def usage():
	print >> sys.stderr, "usage: python ftpredator.py [-host <host> | -host_file <host_file> | -h] [ ... ]]"

if __name__ == "__main__":
	# setup the parser
	parser = argparse.ArgumentParser(prog='ftpredator')
	parser.add_argument('--host', type=str, default="192.158.1.1")
	parser.add_argument('--host_file', type=str, default="")
	parser.add_argument('--username_file', type=str, default="USERNAMES")
	parser.add_argument('--password_file', type=str, default="PASSWORDS")
	parser.add_argument('--string_file', type=str, default="STRINGS")

	# TODO: maybe consider adding a mode to enable/disable checking for substrings of each string?
	# ... way too many possibilities unless severely filtered/limited

	# actually do the parsing and then strip out the parameters
	args = parser.parse_args()
	host = parser.host
	host_file = parser.host_file
	username_file = parser.username_file
	password_file = parser.password_file
	string_file = parser.string_file

	# let it rip
	main(host, host_file, username_file, password_file, string_file)

#def record_open_ftps(target):
#	l_open_ftps = []
##	l_open_ftps.append(target)
#
# attempt to connect over clear text FTP
#def connect_ftp(host, username, password):
#	ftp = FTP(target)
#
#	# attempt anonymous login
#	ftp.login()
#	
#	# if unsuccessful, try to log in with the default credential list
#	login_defaults(ftp)
#
##
