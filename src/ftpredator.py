### 
### FTPredator
###
### Authors: 	Christopher Wood (christopherwood07@gmail.com)
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

# Test with linux kernel FTP server: ftp://ftp.kernel.org/pub/ (host is just ftp.kernel.org/pub/)
# Observe...
# >>> p = FTP("kernel.org")
# >>> p.login()
# '230 Login successful.'

# Imports
import sys
import argparse
from ftplib import *

# Setup FTP protocol message/response list here
ftp_resp_list = ["230"] # TODO: add the rest - they'll probably be needed at some point

def check_remote_ftp_contents(ftp, strings, dirstr = "/"):
	''' 
	Return a list of absolute paths to files on the ftp connection that contain sensitive words.
	'''
	current_dir_contents = ftp.nlst()
	sensitive_files = []
	for entry in current_dir_contents:
		try:
			# try to set the new current working directory to each item in the list to determine if its a new dir
			ftp.cwd(entry)

			sensitive_files.append(check_remote_ftp_contents(ftp, strings, dirstr + str(entry) + "/"))
		except:
			# This entry must be a file, so create a list of matching words
			matches = []
			for ss in strings:
				if ss in entry:
					matches.append(ss)
			if (len(matches) > 0):
				sensitive_files.append((dirstr + entry, matches))
	return sensitive_files

def find_valid_logins(host, username, passwords, TLS = False):
	''' Return a boolean flag indicating if anonymous login was successful and 
	a list of (username,password) tuples that were able to successfully log into the system
	'''

	creds = []

	print >> sys.stderr, "FINDING LOGINS FOR THE FOLLOWING CREDENTIALS"
	print >> sys.stderr, "Usernames: " + str(username)
        print >> sys.stderr, "Passwords: " + str(passwords)
	
	if len(host) == 0:
		raise Exception("You must provide a valid host name")

	# Try anonymous first
	anon = False
	try:
		anon = is_valid_login(host, "", "", TLS)
	except:
		print >> sys.stderr, "Anonymous login failed."

	# Empty passwords
	for u in username:
		try:
			if is_valid_login(host, u, "", TLS):
				creds.append((u, ""))
		except:
			print >> sys.stderr, "Blank password for username " + str(u) + " failed"

	# Non-empty usernames and passwords
	for u in username:
		for p in passwords:
			try:
				if is_valid_login(host, u, p, TLS):
					creds.append((u, p))
			except:
				print >> sys.stderr, "Username/password " + username + " " + password + " failed"

	return anon, creds

def is_valid_login(host, username, password, TLS = False):
	''' Check the validity of a specific username/password combination.
	Return true if login successful, false otherwise.
	'''

	success = False

	print >> sys.stderr, "Trying:\n\t" + username + "\n\t" + password
	print >> sys.stderr, "TLS enabled: " + str(TLS)

	if len(host) == 0:
		raise Exception("You must provide a valid host name")

	ftp = None
	try:
		if TLS:
			ftp = FTP_TLS(host)
		else:
			ftp = FTP(host)
		if len(username) == 0 and len(password) == 0: # Anonymous
			try:
				ftp.login()
				success = True
			except Exception as e:
				print >> sys.stderr, e
		elif len(password) == 0: # Blank password
			try:
				ftp.login(username)
				success = True
			except Exception as e:
				print >> sys.stderr, e
		else: # Non-empty username and password
			try:
				ftp.login(username, password)
				success = True
			except Exception as e:
				print >> sys.stderr, e

		# Clean up
		ftp.quit() 
	except:
		raise Exception("Could not establish connection to host: " + host)

	return success

def find_matching_files_on_host(host, usernames, passwords, strings):
	''' Check the host by logging in with the set of usernames
	and passwords. 

	Return a list of absolute paths to files on the host that contain sensitive words
	'''

	paths = []

	print >> sys.stderr, "Usernames:"
	print >> sys.stderr, usernames
	print >> sys.stderr, "Passwords:"
	print >> sys.stderr, passwords
	print >> sys.stderr, "Strings:"
	print >> sys.stderr, strings

	# Determine which login combinations work and which don't
	anon_tls = False
	anon_clr = False
	creds_tls = []
	creds_clr = []
	try:
		anon_tls, creds_tls = find_valid_logins(host, usernames, passwords, True)
	except:
		print >> sys.stderr, "Error: could not connect to service with FTP over TLS"
	try:
		anon_clr, creds_clr = find_valid_logins(host, usernames, passwords, False)
	except:
		print >> sys.stderr, "Error: could not connect to service with unsecure FTP (plaintext)"

	# Check contents using anonymous first
	# Note: if we get here, then the FTP service exists, so we don't need to do
	# 	any error handling.
	if anon_tls:
		print >> sys.stderr, "Checking anonymous login with TLS"
		ftp = FTP_TLS(host)
		ftp.login()
		paths.append(check_remote_ftp_contents(ftp, strings))
		ftp.quit()
	if anon_clr:
		print >> sys.stderr, "Checking anonymous login in the clear"
		ftp = FTP(host)
		ftp.login()
		paths.append(check_remote_ftp_contents(ftp, strings))
                ftp.quit()
	if len(creds_tls) > 0:
		print >> sys.stderr, "Checking credential combinations in the clear"
		for creds in creds_tls:
			ftp = FTP_TLS(host)
			un = creds[0]
			pw = ""
			if len(creds[1]) > 0:
				pw = creds[1]
			ftp.login(un, pw)
			paths.append(check_remote_ftp_contents(ftp, strings))
			ftp.quit()
	if len(creds_clr) > 0:
		print >> sys.stderr, "Checking credential combinations in the clear"
		for creds in creds_clr:
			ftp = FTP(host)
			un = creds[0]
			pw = ""
			if len(creds[1]) > 0:
				pw = creds[1]
			ftp.login(un, pw)
			paths.append(check_remote_ftp_contents(ftp, strings))
			ftp.quit()

	return paths

	# check for duplicate items in nested list
	def unique_nested_list(list):
		'''Remove duplicate file entries from nested list'''
		counter = 0
		file_names = []
		list_name = []
		for i in list:
			if type(i) == list:
				counter = counter + 1
				list_name = i
				unique_nested_list(i)
			else:
				# check for unique
				if i in file_names:
					# remove the duplicate item
					list_name.remove(i)
				else:
					file_names.append(i)

	# try: 
	# 	# connect to the target host over clear text FTP
	# 	ftp = FTP(host)
	# 	try:
	# 		# attempt to login with anonymous
	# 		ftp.login()
	# 	except:
	# 		# attempt to login with all usernames provided with blank passwords
	# 		for user in usernames:
	# 			try:
	# 				ftp.login(host, user, "")
	# 				check_contents(ftp, strings)
	# 			except:
	# 				print user + " username failed to authenticate with blank password"
	# except:
	# 	# connect to the target host over encrypted FTP
	# 	ftp = FTP_TLS(host)
	# 	try:
	# 		# attempt to login with anonymous
	# 		ftp.login()
	# 		check_contents(ftp, strings)
	# 	except:
	# 		# attempt to login with all usernames provided with blank passwords
	# 		for user in usernames:
	# 			try:
	# 				ftp.login(host, user, "")
	# 				check_contents(ftp, strings)
	# 			except:
	# 				print user + " username failed to authenticate with blank password"
	# else:
	# 	# host is not accessible over clear text or encrypted FTP ports
	# 	print host + " does not appear to have an open FTP service"
	# 	return []

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
		hdump.append(find_matching_files_on_host(host, usernames, passwords, strings))
	if (len(host_file) > 0):
		with open(host_file) as f:
			hdump.append(find_matching_files_on_host(f.readline().strip(), usernames, passwords, strings))

	# TODO: do something with hdump!
	print(hdump)

def usage():
	print >> sys.stderr, "usage: python ftpredator.py [-host <host> | -host_file <host_file> | -h] [ ... ]]"

# Entry point if run as the executable.
if __name__ == "__main__":
	parser = argparse.ArgumentParser(prog='ftpredator - preying on stupidly insecure FTP services')
	parser.add_argument("-t", "--target", help="IP address of the target/host to attack", type=str, default="localhost")
	parser.add_argument("-tf", "--target_file", help="File containing a list of targets/hosts on each line", type=str, default="")
	parser.add_argument("-uf", "--username_file", help="File containing a list of usernames to try", type=str, default="USERNAMES")
	parser.add_argument("-pf", "--password_file", help="File containing a list of passwords to try", type=str, default="PASSWORDS")
	parser.add_argument("-sf", "--string_file", help="File containing a list of substrings to match against", type=str, default="STRINGS")

	# TODO: maybe consider adding a mode to enable/disable checking for substrings of each string?
	# ... way too many possibilities unless severely filtered/limited

	# Do the parsing and then strip out the parameters
	argmap = parser.parse_args()
	args = vars(argmap)
	host = args["target"]
	host_file = args["target_file"]
	username_file = args["username_file"]
	password_file = args["password_file"]
	string_file = args["string_file"]

	# Let it rip
	main(host, host_file, username_file, password_file, string_file)
