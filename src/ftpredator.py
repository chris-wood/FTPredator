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

def check_contents(ftp, strings):
	''' 
	Return a list of absolute paths to files on the ftp connection that contain sensitive words.
	'''
	current_dir_contents = ftp.nlist()
	sensitive_files = []
	for i in current_dir_contents:
		try:
			# try to set the new current working directory to each item in the list to determine if its a new dir
			ftp.cwd(i)
			sensitive_files.append(check_contents(ftp, strings))
		except:
			if name_contains(i, strings):
				sensitive_files.append(i)
	return sensitive_files

def name_contains(file_name, strings):
	'''
	Return the file name if it contains a sensitive word.
	'''
	for i in strings:
		result = i in file_name
		if result == True:
			return True
	return False

def check_host(host, usernames, passwords, strings):
	''' Check the host by logging in with the set of usernames
	and passwords. 

	Return a list of absolute paths to files on the host that contain sensitive words
	'''

	try: 
		# connect to the target host over clear text FTP
		ftp = FTP(host)
		try:
			# attempt to login with anonymous
			ftp.login()
		except:
			# attempt to login with all usernames provided with blank passwords
			for user in usernames:
				try:
					ftp.login(host, user, "")
					check_contents(ftp, strings)
				except:
					print user + " username failed to authenticate with blank password"
	except:
		# connect to the target host over encrypted FTP
		ftp = FTP_TLS(host)
		try:
			# attempt to login with anonymous
			ftp.login()
			check_contents(ftp, strings)
		except:
			# attempt to login with all usernames provided with blank passwords
			for user in usernames:
				try:
					ftp.login(host, user, "")
					check_contents(ftp, strings)
				except:
					print user + " username failed to authenticate with blank password"
	else:
		# host is not accessible over clear text or encrypted FTP ports
		print host + " does not appear to have an open FTP service"
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
	parser.add_argument('--host', type=str, default="192.168.1.1")
	parser.add_argument('--host_file', type=str, default="")
	parser.add_argument('--username_file', type=str, default="USERNAMES")
	parser.add_argument('--password_file', type=str, default="PASSWORDS")
	parser.add_argument('--string_file', type=str, default="STRINGS")

	# TODO: maybe consider adding a mode to enable/disable checking for substrings of each string?
	# ... way too many possibilities unless severely filtered/limited

	# actually do the parsing and then strip out the parameters
	args = parser.parse_args()
	host = parser.hosts
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
