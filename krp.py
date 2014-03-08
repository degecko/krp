#!/usr/bin/python

import re
import sys
import base64
import urllib
import hashlib

def switch(val, obj):
	return obj.get(val, 'default');

def base64_(action, string):
	global encodes
	global decodes

	if action in encodes:
		try:
			result = base64.b64encode(string)
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	elif action in decodes:
		try:
			result = base64.b64decode(string)
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	else:
		return 'Invalid cipher action ('+ action +')'

	return result

def base32_(action, string):
	global encodes
	global decodes

	if action in encodes:
		try:
			result = base64.b32encode(string)
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	elif action in decodes:
		try:
			result = base64.b32decode(string)
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	else:
		return 'Invalid cipher action ('+ action +')'

	return result

def base16_(action, string):
	global encodes
	global decodes

	if action in encodes:
		try:
			result = base64.b16encode(string)
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	elif action in decodes:
		try:
			result = base64.b16decode(string)
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	else:
		return 'Invalid cipher action'

	return result

def binary_(action, string):
	global encodes
	global decodes

	if action in encodes:
		try:
			result = ' '.join(format(ord(x), 'b').zfill(8) for x in string)
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	elif action in decodes:
		try:
			result = ''.join(chr(int(x, 2)) for x in string.split(' '))
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	else:
		return 'Invalid cipher action'

	return result

def hex_(action, string):
	global encodes
	global decodes

	if action in encodes:
		try:
			result = ' '.join(x.encode('hex') for x in string)
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	elif action in decodes:
		try:
			result = re.sub(r'[^0-9a-f]', '', string).decode('hex')
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	else:
		return 'Invalid cipher action'

	return result

def ascii_(action, string):
	global encodes
	global decodes

	if action in encodes:
		try:
			result = ' '.join(str(ord(x)) for x in string)
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	elif action in decodes:
		try:
			result = ''.join(chr(int(x)) for x in string.split(' '))
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	else:
		return 'Invalid cipher action ('+ action +')'

	return result

def rot13_(action, string):
	return string.encode('rot13')

def url_(action, string):
	global encodes
	global decodes

	if action in encodes:
		try:
			result = urllib.quote(string)
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	elif action in decodes:
		try:
			result = urllib.unquote(string)
		except Exception as e:
			result = 'Cipher error, check the input and the action for the cipher.'

	else:
		return 'Invalid cipher action ('+ action +')'

	return result

def crypt_(hasher, string):
	temp = eval('hashlib.'+ hasher +'("""'+ string.replace('"""', '\\"\\"\\"') +'""")');
	return temp.hexdigest()

def all_(string, action):
	global encodes
	global decodes
	global hashing
	global ciphers
	global hashes

	if action not in decodes:
		for c in ciphers:
			if c not in ['ascii', 'hex', 'url']:
				print c[0].upper() + c[1:],
			else:
				print c.upper(),

			print '\t: '+ eval(c +'_("""'+ action +'""", """'+ string.replace('"""', '\\"\\"\\"') +'""")')

		for c in hashing:
			print c.upper() +' \t: '+ eval('crypt_("""'+ c +'""", """'+ string.replace('"""', '\\"\\"\\"') +'""")')

	else:
		for c in ciphers:
			if c not in ['ascii', 'hex', 'url']:
				print c[0].upper() + c[1:],
			else:
				print c.upper(),

			print '\t: '+ eval(c +'_("""'+ action +'""", """'+ string.replace('"""', '\\"\\"\\"') +'""")')

def enc(string, cipher, action):
	global ciphers

	if cipher not in ciphers and cipher not in hashing and cipher != 'all':
		print 'Cipher "'+ cipher +'" not available!'
		return None

	if cipher == 'all':
		all_(string, action)
	elif cipher in hashing:
		print eval('crypt_("""'+ cipher +'""", """'+ string.replace('"""', '\\"\\"\\"') +'""")')
	else:
		print eval(cipher +'_("""'+ action +'""", """'+ string.replace('"""', '\\"\\"\\"') +'""")')

ciphers = ['base64', 'base32', 'base16', 'binary', 'hex', 'ascii', 'rot13', 'url']
hashing = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
encodes = ['e', 'en', 'enc', 'encode']
decodes = ['d', 'de', 'dec', 'decode']
hashes  = ['h', 'hash', 'hashes', 'hashing']
cipher_shorts = { 'b64': 'base64', 'b32': 'base32', 'b16': 'base16', 'bin': 'binary', 'r13': 'rot13' }
help_text = '''K R Y P T O N - CLI Encryption Tool
Usage:

Available ciphers & hashing algorithms:
'''+ ', '.join(ciphers + hashing) +'''
Some shortcuts: b64, b32, b16, r13 and bin

krp <string>
\tThe string encoded using all of the ciphers

krp <d|de|dec|decode> <string>
\tThe string decoded using all of the ciphers
\t(could be useful for cipher identification)

krp <cipher> [<e|en|enc|encode>] <string>
\tThe string encoded using the specified cipher

krp <cipher> <d|de|dec|decode> <string>
\tThe string decoded using the specified cipher

The same rules apply for piping, just omit the <string>

E.g.:
cat /etc/hosts | krp md5
\tReturns the md5 of the file contents'''

if __name__ == '__main__':
	args = sys.argv[1:]
	
	# If there is content being piped as the input string
	if sys.stdin.isatty() == False:
		string = sys.stdin.read()

		if len(args) > 1:
			cipher = args[0].lower()
			action = args[1].lower()
		else:
			cipher = 'all'
			action = 'e'

			if len(args) > 0:
				first_arg = args[0].lower()

				if first_arg != 'all' and switch(first_arg, cipher_shorts) != 'default':
					first_arg = switch(first_arg, cipher_shorts)
				
				if first_arg in ciphers + hashing:
					cipher = first_arg

	# If the string is passed normally
	else:
		if len(args) < 1 or (len(args) and args[0] == '-h'):
			print help_text
			exit(0)

		if len(args) > 2:
			string = args[2]
		else:
			if len(args) > 1:
				string = args[1]
			else:
				string = args[0]
	
		if len(args) > 2:
			cipher = args[0].lower()
			action = args[1].lower()
		else:
			cipher = 'all'
			action = 'e'

			first_arg = args[0].lower()

			if first_arg != 'all' and switch(first_arg, cipher_shorts) != 'default':
				first_arg = switch(first_arg, cipher_shorts)
			
			if len(args) > 1 and first_arg in ciphers + hashing:
				cipher = first_arg

	if cipher != 'all' and switch(cipher, cipher_shorts) != 'default':
		cipher = switch(cipher, cipher_shorts)

	enc(string, cipher, action)
