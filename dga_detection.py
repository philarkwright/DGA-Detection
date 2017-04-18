from __future__ import division
from pprint import pprint
from scapy.all import *
import scipy

import ConfigParser
import os.path
import json
import tldextract #Seperating subdomain from input_domain in capture 
import alexa

def hasNumbers(inputString):
	return any(char.isdigit() for char in inputString)

def ConfigSectionMap(section):
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print("exception on %s!" % option)
            dict1[option] = None
    return dict1

Config = ConfigParser.ConfigParser()

def load_settings():

	if os.path.isfile('/data/settings.conf'):
		Config.read("/data/settings.conf")
		percentage_list_dga_settings = float(ConfigSectionMap("Percentages")['percentage_list_dga_settings'])
		percentage_list_alexa_settings = float(ConfigSectionMap("Percentages")['percentage_list_alexa_settings'])
		total_average_percentage = float(ConfigSectionMap("Percentages")['baseline'])
		total_bigrams_settings = float(ConfigSectionMap("Values")['total_bigrams_settings'])
		return total_average_percentage, total_bigrams_settings
	else:
		"No settings file. Please run training function."

def load_data():



	if os.path.isfile('/data/database.json') and os.path.isfile('/data/settings.conf'):

		total_average_percentage, total_bigrams_settings = load_settings()

		with open('/data/database.json', 'r') as f:
		    try:
		        bigram_dict = json.load(f)
		        process_data(bigram_dict, total_bigrams_settings) #Call process_data
		    # if the file is empty the ValueError will be thrown
		    except ValueError:
		        bigram_dict = {}
	else:

		try:
			cfgfile = open("/data/settings.conf",'w')
			Config.add_section('Percentages')
			Config.add_section('Values')
			Config.set('Percentages','total_average_percentage', 0)
			Config.write(cfgfile)
			cfgfile.close()
		except:
			print "Settings file error. Please Delete."
			exit()

		
		if os.path.isfile('alexa_top_1m_domain.json'):
			with open('alexa_top_1m_domain.json', 'r') as f:
				training_data = json.load(f)
		else:
			print "Downloading Alexa Top 1m Domains..."
			training_data = alexa.top_list(1000000)
			with open('alexa_top_1m_domain.json', 'w') as f:
				json.dump(training_data, f)


		bigram_dict = {} #Define bigram_dict
		total_bigrams = 0 #Set initial total to 0
		for input_domain in xrange(len(training_data)): #Run through each input_domain in the training list
			input_domain = tldextract.extract(training_data[input_domain][1])
			if len(input_domain.domain) > 5 and "-" not in input_domain:
				print "Processing domain:", input_domain.domain #Print input_domain number in list
				for  bigram_position in xrange(len(input_domain.domain) - 1): #Run through each bigram in input_domain
					total_bigrams = total_bigrams + 1 #Increment bigram total
					if input_domain.domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram already exists in dictionary
						bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] = bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] + 1 #Increment dictionary value by 1
					else:
						bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] = 1 #Add bigram to list and set value to 1

		pprint(bigram_dict) #Print bigram list
		with open('/data/database.json', 'w') as f:
			json.dump(bigram_dict, f)

		process_data(bigram_dict, total_bigrams) #Call process_data

def process_data(bigram_dict, total_bigrams):

	data = open('/data/alexa_training.txt').read().splitlines()
	percentage_list_alexa = [] #Define average_percentage

	for input_domain in xrange(len(data)): #Run through each input_domain in the data
		input_domain = tldextract.extract(data[input_domain])
		if len(input_domain.domain) > 5 and "-" not in input_domain.domain:
			percentage = [] #Clear percentage list
			for  bigram_position in xrange(len(input_domain.domain) - 1): #Run through each bigram in the data
				if input_domain.domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram is in dictionary 
					percentage.append((bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] / total_bigrams) * 100) #Get bigram dictionary value and convert to percantage
				else:
					percentage.append(0) #Bigram value is 0 as it doesn't exist

			percentage_list_alexa.append(scipy.mean(percentage)) #Add percentage value to list for total average
			print input_domain.domain, "AP:", scipy.mean(percentage) #Print input_domain and percentage list


	data = open('/data/dga_training.txt').read().splitlines()
	percentage_list_dga = [] #Define average_percentage

	for input_domain in xrange(len(data)): #Run through each input_domain in the data
		input_domain = tldextract.extract(data[input_domain])
		if len(input_domain.domain) > 5 and "-" not in input_domain.domain:
			percentage = [] #Clear percentage list
			for  bigram_position in xrange(len(input_domain.domain) - 1): #Run through each bigram in the data
				if input_domain.domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram is in dictionary 
					percentage.append((bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] / total_bigrams) * 100) #Get bigram dictionary value and convert to percantage
				else:
					percentage.append(0) #Bigram value is 0 as it doesn't exist

			percentage_list_dga.append(scipy.mean(percentage)) #Add percentage value to list for total average
			print input_domain.domain, "AP:", scipy.mean(percentage) #Print input_domain and percentage list

	print 67 * "*"
	print "Total Average Percentage Alexa:", scipy.mean(percentage_list_alexa), "( Min:", min(percentage_list_alexa), "Max:", max(percentage_list_alexa), ")" #Get average percentage
	print "Total Average Percentage DGA:", scipy.mean(percentage_list_dga), "( Min:", min(percentage_list_dga), "Max:", max(percentage_list_dga), ")" #Get average percentage
	print "Baseline:", (((scipy.mean(percentage_list_alexa) - scipy.mean(percentage_list_dga)) / 2) + scipy.mean(percentage_list_dga))
	print 67 * "*"

	cfgfile = open("/data/settings.conf",'w')
	Config.set('Percentages','percentage_list_alexa_settings', scipy.mean(percentage_list_alexa))
	Config.set('Percentages','percentage_list_dga_settings', scipy.mean(percentage_list_dga))
	Config.set('Percentages','baseline', (((scipy.mean(percentage_list_alexa) - scipy.mean(percentage_list_dga)) / 2) + scipy.mean(percentage_list_dga)))
	Config.set('Values','total_bigrams_settings', total_bigrams)
	Config.write(cfgfile)
	cfgfile.close()

	percentage = [] #Define percentage

def check_domain(input_domain):

	if os.path.isfile('/data/database.json'):
		with open('/data/database.json', 'r') as f:
		    try:
		        bigram_dict = json.load(f)
		    # if the file is empty the ValueError will be thrown
		    except ValueError:
		        bigram_dict = {}
	
	percentage = []

	for  bigram_position in xrange(len(input_domain) - 1): #Run through each bigram in the data
		if input_domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram is in dictionary 
			percentage.append((bigram_dict[input_domain[bigram_position:bigram_position + 2]] / total_bigrams_settings) * 100) #Get bigram dictionary value and convert to percantage
		else:
			percentage.append(0) #Bigram value is 0 as it doesn't exist

	if total_average_percentage >= scipy.mean(percentage):
		print 67 * "*"
		print 'Baseline:', total_average_percentage, 'Domain Average Bigram Percentage:',scipy.mean(percentage)
		return 1
	else:
		return 0

	percentage = [] #Clear percentage list

def capture_traffic(pkt):

	total_average_percentage, total_bigrams_settings = load_settings()

	if IP in pkt:
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
			input_domain = tldextract.extract(pkt.getlayer(DNS).qd.qname)
			if input_domain.suffix != '' and input_domain.suffix != 'localdomain' and input_domain.subdomain == '' and len(input_domain.domain) > 5 and "-" not in input_domain: #Domains are no smaller than 6
				if check_domain(input_domain.domain) == 1:
					print 'Extracted Domain:', input_domain.domain
					print str(ip_src) +  "->",  str(ip_dst), "Warning! Potential DGA Detected ", "(", (pkt.getlayer(DNS).qd.qname), ")"
					print 67 * "*"
					print '\n'

				#else:
					#print "Safe input_domain", "(" + input_domain + ")"

def testing():

	total_average_percentage, total_bigrams_settings = load_settings()

	if os.path.isfile('/data/database.json'):
		with open('/data/database.json', 'r') as f:
		    try:
		        bigram_dict = json.load(f)
		    # if the file is empty the ValueError will be thrown
		    except ValueError:
		        bigram_dict = {}


	data = open('/data/test_domains.txt').read().splitlines()


	flag = 0
	total_flags = 0
	percentage = [] #Define percentage

	for input_domain in xrange(len(data)): #Run through each input_domain in the data
		input_domain = tldextract.extract(data[input_domain])
		if len(input_domain.domain) > 5 and "-" not in input_domain.domain:
			for  bigram_position in xrange(len(input_domain.domain) - 1): #Run through each bigram in the data
				if input_domain.domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram is in dictionary
					percentage.append((round(((bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] / total_bigrams_settings) * 100), 2))) #Get bigram dictionary value and convert to percantage
				else:
					percentage.append(0) #Bigram value is 0 as it doesn't exist
			

			total_flags = total_flags + 1

			if total_average_percentage >= scipy.mean(percentage):
				flag = flag + 1
				print input_domain.domain, percentage,"AP:", scipy.mean(percentage)
			else:
				print input_domain.domain, percentage, "AP:", scipy.mean(percentage)


			percentage = [] #Clear percentage list

	print 67 * "*"
	print "Detection Rate:", flag / total_flags * 100
	print 67 * "*"

ans=True
while ans:
	print 30 * "-" , "MENU" , 30 * "-"
	print ("""
	1. Train Data
	2. Start Capturing DNS
	3. Testing
	4. View Config File
	5. Delete script data
	6. Exit/Quit
	""")
	print 67 * "-"
	ans=raw_input("Select an option to proceed: ") 
	if ans=="1": 
		load_data()
	elif ans=="2":
		try:
			interface = raw_input("[*] Enter Desired Interface: ")
		except KeyboardInterrupt:
			print "[*] User Requested Shutdown..."
			print "[*] Exiting..."
			sys.exit(1)
		sniff(iface = interface,filter = "port 53", prn = capture_traffic, store = 0)
	elif ans=="3":
		if os.path.isfile('/data/settings.conf') and os.path.isfile('/data/database.json'):
			testing()
		else:
			print "\nYou must run the training algoirthm first."
	elif ans=="4":
		if os.path.isfile('/data/settings.conf') and os.path.isfile('/data/database.json'):
			print 67 * "*"
			print "Total Average Percentage Alexa:", percentage_list_alexa_settings
			print "Total Average Percentage DGA:", percentage_list_dga_settings
			print "Baseline (Baseline):", total_average_percentage
			print 67 * "*"
		else:
			print "\n No data files available."
	elif ans=="5":
		if os.path.isfile('/data/settings.conf') and os.path.isfile('/data/database.json'):
		  os.remove('/data/settings.conf')
		  os.remove('/data/database.json')
		  print "\nData has been deleted"
		else:
			print "\nNo data to delete."
	elif ans=="6":
	  print("\nDeleting script data files...") 
	  quit()
	elif ans !="":
	  print("\n Not Valid Choice Try again") 






