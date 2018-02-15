import optparse
import sys
import crypt
def cryptCrack(saltedHash, dict):
	salt = saltedHash.split('$')[2]
	salt = '$6$'+ salt
	dictFile = open(dict)
	for word in dictFile.readlines():
		word = word.strip('\n')
		print "[*] Trying Password %r " % word
		cryptPass = crypt.crypt(word,salt)
		if cryptPass == saltedHash:
			print "[+] Password Found: %s " % word	
			return
		else:
			print "[-] Failed..Moving to Next Password"	
def hashChecker(crypt):
	if '$1$' in crypt:
		print "[*] Salted MD5 Detected "
	elif '$2$' in crypt:
		print "[*] Salted Blowfish Detected "
	elif '$2y$' in crypt:
		print "[*] Salted Blowfish with correct handling of 8 bits detected "
	elif '$5$' in crypt:
		print "[*] Salted SHA 256 detected "
	elif '$6$' in crypt:
		print "[*] Salted SHA 512 detected "
	else:
		print "Couldn't Identify Type of Hash "
		print "Exiting"
		sys.exit(0)
def main():
	usage = "Usage:python hashcrack.py -c <hash-File> -f <dictionary> -a <account>"
	parser = optparse.OptionParser(usage)
	parser.add_option('-c', dest = 'saltedHash', help = 'Specify file containing hash', type = 'string')
	parser.add_option('-f', dest = 'dictFile', help = 'Specify Dictionary File', type = 'string')
	parser.add_option('-a', dest = 'account', help = 'Specify account' , type = 'string')
	(options,args) = parser.parse_args()
	saltedHash = options.saltedHash
	dictFile = options.dictFile
	account = options.account
	if saltedHash is None or dictFile is None or account is None:
		print parser.usage
		return
	else:
		with open(saltedHash) as hashFile:
			for line in hashFile.readlines():
				if account in line:
					user = line.split(':')[0]
					crypt = line.split(':')[1]
					print "--------------------------------"
					print "[!] Cracking Password for %r" % user
					print "--------------------------------"
					print "[*] Detecting Hashtype"
					hashChecker(crypt)
					cryptCrack(crypt, dictFile)
												
if __name__ == '__main__':
	main()

		
		
	
		
