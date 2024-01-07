# RaspberryPi-Protector
## Table of contents
* [General info](#general-info)
* [Setup](#setup)

## General info
This project is Bash installer which and sets up different programs in order to secure my personal Nextcloud instance. The script was made and tested on Ubuntu 64bit 22.10 ARM64 and RaspberryPi 4 
	
## Setup
If You want to run this project on freshly installed Ubuntu do full system update and upgrade and reboot your device:
```
sudo apt update && sudo apt upgrade -y && sudo reboot
```
After rebooting download insatllation script:
```
wget https://raw.githubusercontent.com/adambaczkowski/RaspberryPi-Protector/main/install.sh
```
Change permissions using:
```
sudo chmod +x install.sh
```
Execute script:
```
./install.sh
```


