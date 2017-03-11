from __future__ import division
from pprint import pprint
import scipy

def train_data():

	training_data = open('alexa_top_10k_domain.txt').read().splitlines() #Import alexa top domains 
	bigram_list = {} #Define bigram_list
	total_bigrams = 0 #Set initial total to 0
	for word in xrange(len(training_data)): #Run through each word in the training list
		print word #Print word number in list
		for  bigram_position in xrange(len(training_data[word]) - 1): #Run through each bigram in word
			total_bigrams = total_bigrams + 1 #Increment bigram total
			if training_data[word][bigram_position:bigram_position + 2] in bigram_list: #Check if bigram already exists in dictionary
				bigram_list[training_data[word][bigram_position:bigram_position + 2]] = bigram_list[training_data[word][bigram_position:bigram_position + 2]] + 1 #Increment dictionary value by 1
			else:
				bigram_list[training_data[word][bigram_position:bigram_position + 2]] = 1 #Add bigram to list and set value to 1

	pprint(bigram_list) #Print bigram list
	process_data(bigram_list, total_bigrams) #Call process_data


 


def process_data(bigram_list, total_bigrams):

	data = open('dgapro.txt').read().splitlines()
	percentage = [] #Define percentage
	percentage_list = [] #Define average_percentage
	for word in xrange(len(data)): #Run through each word in the data
		for  bigram_position in xrange(len(data[word]) - 1): #Run through each bigram in the data
			if data[word][bigram_position:bigram_position + 2] in bigram_list: #Check if bigram is in dictionary 
				percentage.append((bigram_list[data[word][bigram_position:bigram_position + 2]] / total_bigrams) * 100) #Get bigram dictionary value and convert to percantage
			else:
				percentage.append(0) #Bigram value is 0 as it doesn't exist
		percentage_list.append(scipy.mean(percentage)) #Add percentage value to list for total average
		print data[word], percentage, "AP:", scipy.mean(percentage) #Print word and percentage list
		percentage = [] #Clear percentage list
	print "Total Average Percentage:", scipy.mean(percentage_list) #Get average percentage


train_data()



