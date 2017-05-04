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

## Potential Issues
When running the install.sh file please note that the git:// protocol uses port 9418, so you should make sure your firewall allows outbound connections to this port.
