#! /usr/bin/python
import requests
import argparse
import os
import time

def checkkey(kee):
	try:
		if len(kee) == 64:	#This will check your Public/Private key
			return kee
		else:
			print "There is something wrong with Public/Private your key. Not 64 Alpha Numeric characters."
			exit()
	except Exception, e:
			print e
			
def checkhash(hsh):
	try:
		if len(hsh) == 32: 	# MD5 produces 32 chars hash
			return hsh
		elif len() == 40:  	# SHA1 produces 32 chars hash
			return hsh
		elif len(hsh) == 64: 	# SHA256 produces 32 chars hash
			return hsh
		else:
			print "The Hash input does not appear valid."
			exit()
	except Exception, e:
			print e
			
def fileexists(filepath):
	try:
		if os.path.isfile(filepath):   #Input file path (give full path if file not in current folder)
			return filepath
		else:
			print "There is no file at:" + filepath
			exit()
	except Exception, e:
			print e

	#This define all Input formats including input file, single input hash, output file, our private(unlimited) or public key 
def main():
	parser = argparse.ArgumentParser(description="Query hashes against Virus Total.")
	parser.add_argument('-i', '--input', type=fileexists, required=False, help='Input File Location EX: /root/Desktop/hashes.txt')
	parser.add_argument('-o', '--output', required=True, help='Output File Location EX: /root/Desktop/output.txt ')
	parser.add_argument('-H', '--hash', type=checkhash, required=False, help='Single Hash EX: d41d8cd98f00b204e9800998ecf8427e')
	parser.add_argument('-k', '--key', type=checkkey, required=True, help='VT API Key EX: ASDFADSFDSFASDFADSFDSFAHGHJGJFGHFHGDSF')
	parser.add_argument('-u', '--unlimited', action='store_const', const=1, required=False, help='Changes the 16 second sleep timer to 1.')
	args = parser.parse_args()




	#Run for a single hash through command line + key
	if args.hash and args.key:
		file = open(args.output,'w+')
		file.write('This Script is created by Prashant Singh so just give him some treat for creating this script  \n\n')
		file.write('Below is input Hash to MD5 Hash conversion.\n\n')
		file.close()
		VT_Request(args.key, args.hash.rstrip(), args.output)
	#Run for an input file + key
	elif args.input and args.key:
		file = open(args.output,'w+')
		file.write('#####This Script is created by Prashant Singh so just give him some treat for creating this script#### \n\n')
		file.write('\n\n Below are input Hashes to MD5 Hash conversion.\n\n')
		file.close()
		with open(args.input) as o:
			for line in o.readlines():
				VT_Request(args.key, line.rstrip(), args.output)
				if args.unlimited == 1:					#  this defines timer
					time.sleep(1)					#  unlimited Timer (private key)
				else:
					time.sleep(16)					#  for Public key (has limit of 4 search in 1 min)
	
def VT_Request(key, hash, output):
	params = {'apikey': key, 'resource': hash}
	url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
	json_response = url.json()
	print json_response
	response = int(json_response.get('response_code'))
	if response == 0:					# means not in VT
		print hash + ' is not in Virus Total'
		file = open(output,'a')
		file.write(hash + ' is not in Virus Total')
		file.write('\n')
		file.close()
	elif response == 1:
		positives = str(json_response.get('md5'))  # Just change MD5 to other parameters (SHA1, SHA256 or any other from Json output)
		file = open(output,'a')
		file.write('Input hash is: ' + hash + '.  Output MD5 hash is : ' + str(positives))
		file.write('\n')
		file.close()
	else:
		print hash + ' could not be searched. Please try again later.'
# execute the program
if __name__ == '__main__':
	main()
