# DGA-Detection
More and more malware is being created with advanced blocking circumvention techniques. One of the most prevalent techniques being used is the use of Domain Generation Algorithms which periodically generates a set of Domains to contact a C&C server. The majority of these DGA domains generate random alphanumeric strings which differ significantly in structure to a standard domain. By looking at the frequency that a set of bigrams in a domain occur within the Alexa top 1M, we were able to detect whether a domain was structured with a random string or if it was a legitimate human readable domain. If a domain is comprised nearly entirely of low frequency bigrams which occurred rarely within the Alexa top 1m then the domain would more likely be a random string. Bigrams of a vowel and constants occurred the most frequent whereas characters and integers occurred the least frequent. The script was ran against 100,000 GameoverZeus domains and had a detection rate of 100% and a false positive rate against the Alexa top 1m of 8% without any domain whitelisting being applied. 


This System has been tested on Ubuntu and RaspberryPi.
Currently I have my raspberrypi setup as a DNS server using Bind9.
The DGA-Detection script is also run on the raspberrypi and reads the requests.
The requests are then processed to determine if they are a potential DGA or not.

## Install

```python
git clone https://github.com/philarkwright/DGA-Detection.git  
cd DGA-Detection  
chmod +x install.sh
./install.sh
```

## Use

```python
sudo python dga_detection.py
```

## Training
- The /data/dga_training.txt file contains DGA domains from the Tinba DGA. I'd suggest using this to train the model as this follows the structure of the majority of the DGA's domains however you may replace the domains with your own set if you wish too.

## Testing
- To test domains against the model after training has been complete, create a textfile called test_domains.txt and place it into /data/.
-A sample of the Tinba DGA domains has been included in the download.

## Settings File
- The settings file is where the model stores the baseline value used to decide whether or not a domain is a potential DGA. This value can be manually changed to increase detection rate or reduced to decrease false positives.

## Live Capture Arguments

```python
nohup sudo python dga-detection.py -o 2 -i <interface>
```

## Potential Issues
When running the install.sh file please note that the git:// protocol uses port 9418, so you should make sure your firewall allows outbound connections to this port.

This project is still very much in development.

While running the script at network level on my home network I noticed that if I did certain google searches on google chrome, that I'd get a bunch of alerts which appeared to be DGA domains. Even if you don't visit these sites which are normally chinese (Since they use giberish strings for their domains), google chrome will preload and fetch them causing the alerts.

NOTE: Whitelist features uses the Alexa Top 1m.

Contact me via Twitter @philarkwright

## Completed

- [ ] Add Alexa Whitelisting
- [ ] Add Pushbullet (Notify admin)
- [ ] Fix Lag on capture traffic alerts
- [ ] Add arguments so capture live can be ran with nohup

