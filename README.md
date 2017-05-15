# DGA-Detection

Testing on SIFT Workstation. Download here: https://digital-forensics.sans.org/community/downloads/SIFT-Tool-Listing.pdf

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


## Potential Issues
When running the install.sh file please note that the git:// protocol uses port 9418, so you should make sure your firewall allows outbound connections to this port.

As this project is still very much in development, some features still haven't been added, e.g. a domain whitelist feature.

Contact me via Twitter @philarkwright
