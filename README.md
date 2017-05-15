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
- The /data/dga_training.txt file contains DGA domains from the Tinba. I'd suggest using this to train the model as this follows the structure of the majority of the DGA's domains. 

## Testing
-To test domains against the model after training has been complete, create a textfile called test_domains.txt and place it into /data/.
-A sample of the Tinba DGA domains has been included in the download.



## Potential Issues
When running the install.sh file please note that the git:// protocol uses port 9418, so you should make sure your firewall allows outbound connections to this port.
