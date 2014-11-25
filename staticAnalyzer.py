# Static Analyzer

import pefile
import peutils
import os, sys, math, time
import magic
import yara
import pydasm
import commands
import md5
import hashlib
import ssdeep
import binascii

# Constants
SignatureDB = './userdb.txt'
Machine_x86 = hex(0x14c)
Machine_x64 = hex(0x8664)
YaraRulesFolder = './YaraRules/'
WinAPI = ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'ReadProcessMemory',
          'CreateProcess', 'WinExec', 'ShellExecute', 'HttpSendRequest', 'InternetReadFile', 'InternetConnect',
          'CreateService', 'StartService']
#MAGIC = ['MZ', 'ELF', ]

def PEiD(pe):
	signatures = peutils.SignatureDatabase(SignatureDB)		  	
	matches = signatures.match_all(pe, ep_only = True)
	return matches	

def getEntropy(data):
	if not data:
		return 0
	
	entropy = 0
	for x in range(256):
		p_x = float(data.count(chr(x)))/len(data)
		if p_x > 0:
			entropy += -p_x*math.log(p_x, 2)
	
	return entropy

def getImports(pe):
	print '\nImport Table:'

	pe.parse_data_directories()

	try:
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
	  		print entry.dll
		  	for imp in entry.imports:
			    print '\t', hex(imp.address), imp.name
	except:
		print 'No Import Data'

def matchYaraRules(data):
	def YaraCallback(data):
		print data
		yara.CALLBACK_CONTINUE

	matches = []

	for file in os.walk(YaraRulesFolder):
		rule = yara.compile(file, includes=False)
		matches.append(rule.match(data, callback=YaraCallback))

def getExports(pe):
	print '\nExport Table:'
	pe.parse_data_directories()

	try:
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
	  		print '%s\t%-*s\t%s' % (hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), 25, exp.name, exp.ordinal)
  	except:
		print 'No Export Data'

def getMagic(file):
	return magic.from_file(file)
	pass

def getMachine(pe):	
	if hex(pe.FILE_HEADER.Machine) == Machine_x86:
		print 'Machine: x86'
	elif hex(pe.FILE_HEADER.Machine) == Machine_x64:
		print 'Machine: x64'
	else:
		print 'Unknown Machine Type'

def getSections(pe):
	print 'NumberOfSections: %s' % (pe.FILE_HEADER.NumberOfSections)
	print ('Section Name\tVirtual Address\t\tVirtual Size\tSize Of Raw Data\tEntropy')

	for section in pe.sections:
		try:
			print '%s\t\t%s\t\t\t%s\t\t%s\t\t\t%s' % (section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), hex(section.SizeOfRawData), getEntropy(section.get_data()))
		except:
			pass

def getAddress(pe):
	print 'EntryPoint:\t%s' % (hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
	print 'ImageBase:\t%s' % (hex(pe.OPTIONAL_HEADER.ImageBase))

def dumpPEInfo(pe):
	print pe.dump_info()
	pass

def QueryVirusTotal():
	pass
	pass

def getPECompileTime(pe):
	epoch = pe.FILE_HEADER.TimeDateStamp
	humantime = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epoch))
	print "Possible compile time: " + humantime

def getHashes(filename):
	with open(filename, "r") as file:
		print "File Name:\t", filename
		print "MD5:\t\t", hashlib.md5(file.read()).hexdigest()
		print "SHA1:\t\t", hashlib.sha1(file.read()).hexdigest()
		print "SHA256:\t\t", hashlib.sha256(file.read()).hexdigest()
		print "SHA512:\t\t", hashlib.sha512(file.read()).hexdigest()
		print "SSDeep:\t\t", str(ssdeep.hash_from_file(filename))
		print "File Size:\t", os.path.getsize(filename), "bytes"

def checkTLS(pe):
	callbacks = []
	print '\nTLS Callbacks:'
	pe.parse_data_directories()

	try:
		callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
		if callback_array_rva is not None:
			print 'Directory Found!'
			print 'TLS Callback Array Address: %s' % (hex(callback_array_rva))

			idx = 0
			while True:
				func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
				if func == 0: 
					break
				callbacks.append(func)
				print hex(func)
				idx += 1
	except:
		print '\tNone.'

	return callbacks
	

def main():
	sample_path = None
	pe = None

	print ''

	if len(sys.argv) > 1:
		sample_path = sys.argv[1]

	try:
		pe =  pefile.PE(sample_path, fast_load=True)
	except:
		print 'Error: Could not open PE file %s' % (sample_path)		

	if sample_path is not None:
		getHashes(sample_path)
		if pe is not None:
			print sample_path, ": ", PEiD(pe)
			getPECompileTime(pe)
			getMachine(pe)
			getSections(pe)
			print ''
			getAddress(pe)
			getImports(pe)
			getExports(pe)
			checkTLS(pe)
			#dumpPEInfo(pe)

		print '\n', getMagic(sample_path), '\n'		
	else:
		print 'Error: Please Enter Filename...'

if __name__ == '__main__':
    main()
