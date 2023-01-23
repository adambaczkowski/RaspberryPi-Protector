# RaspberryPi-Protector
## Table of contents
* [General info](#general-info)
* [Technologies used in project](#technologies)
* [Setup](#setup)

## General info
This project is an Bash installer which installs and sets up different programs in order to secure Nextcloud instance. The script was made and tested on Ubuntu 64bit 22.10 ARM64
	
## Technologies used in project
Project is created with:
* Bash
* Python
	
## Setup
If You want to run this project on freshly installed Ubuntu do full system update and upgrade and reboot your device:
```
$ sudo apt update && sudo apt upgrade -y && sudo reboot
```
After rebooting download insatllation script:
```
$ wget https://raw.githubusercontent.com/adambaczkowski/RaspberryPi-Protector/main/protector_installer.sh
```
Change permissions using:
```
$ sudo chmod +x protector_installer.sh
```
Execute script:
```
./protector_installer.sh
```
