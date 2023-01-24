#!/bin/bash
#Author: Adam Bączkowski
#Page: github.com/adambaczkowski
#LICENSE: GNUPLv2
#Tested on: Ubuntu 22.10 ARM 64 bit

#COLORS
RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
PINK='\033[0;35m'
NO_COLOR='\033[0m'

function main() {
    enable_colors
    Welcome
    whiptail --title "Information" --msgbox "If you are running this script on a fresh instance of Raspberry Pi, consider running 'sudo apt-get update && sudo apt-get upgrade' followed by a reboot before running the installation script." 10 60
    #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
    #VARIABLES
    HOST_IP_ADDRESS=$(hostname -I | awk '{print $1}')
    HOST_MASK_ADDRESS=$(ip addr show | grep -oP '^[0-9]+: \K(e[^:]*)')
    EMAIL=$(whiptail --inputbox "Enter your email address:" 8 78 --title "Email" 3>&1 1>&2 2>&3)
    EMAIL_PASSWORD=$(whiptail --passwordbox "Enter your email password:" 8 78 --title "Password" 3>&1 1>&2 2>&3)
    GRAFANA_LOGIN=$(whiptail --inputbox "Enter your Grafana login:" 8 78 --title "Grafana Login" 3>&1 1>&2 2>&3)
    GRAFANA_PASSWORD=$(whiptail --passwordbox "Enter your Grafana password:" 8 78 --title "Grafana Password" 3>&1 1>&2 2>&3)
    NEXTCLOUD_LOGIN=$(whiptail --inputbox "Enter your Nextcloud login:" 8 78 --title "Nextcloud Login" 3>&1 1>&2 2>&3)
    NEXTCLOUD_PASSWORD=$(whiptail --passwordbox "Enter your Nextcloud password:" 8 78 --title "Nextcloud Password" 3>&1 1>&2 2>&3)
    NEXTCLOUD_DB_PASSWORD=$(whiptail --passwordbox "Enter your Nextcloud Database password:" 8 78 --title "Nextcloud Database Password" 3>&1 1>&2 2>&3)
    OINKCODE=$(whiptail --inputbox "Enter your Oinkcode for Snort. If you don't have Snort account, please register at https://www.snort.org/users/sign_in in order to get newest Snort ules:" 8 78 --title "Snort Oinkcode" 3>&1 1>&2 2>&3)
    SSH_CLIENT_IP=$(echo -ne $SSH_CLIENT | awk '{ print $1}')
    
    SSH_CUSTOM_PORT_NUMBER=$(whiptail --inputbox "Enter your custom SSH port number between 1024 and 65536 :" 8 78 --title "SSH Port" 3>&1 1>&2 2>&3)
    result=$?
    if [ $result = 0 ]; then
        echo "Custom SSH port number: $SSH_CUSTOM_PORT_NUMBER"
    else
        SSH_CUSTOM_PORT_NUMBER=60001
    fi
    
    if [[ $SSH_CUSTOM_PORT_NUMBER -lt 1024 || $SSH_CUSTOM_PORT_NUMBER -eq 22 || $SSH_CUSTOM_PORT_NUMBER -eq 80 || $SSH_CUSTOM_PORT_NUMBER -eq 443 || $SSH_CUSTOM_PORT_NUMBER -eq 8080 || $SSH_CUSTOM_PORT_NUMBER -gt 65536 ]]; then
        echo "Invalid port number. I've chosen port 60001 for You"
        SSH_CUSTOM_PORT_NUMBER=60001
    else
        echo "Custom SSH port number: $SSH_CUSTOM_PORT_NUMBER"
    fi
    sudo systemctl enable ssh
    #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
    sleep 5
    check_device_info
    sleep 2
    start_time=$(date +%s)
    Update #|| echo -ne "${RED}Update has failed ❌${NO_COLOR}"
    sleep 2
    rsyslog_installer
    sleep 2
    snort #|| echo -ne "${RED}Snort installation has failed ❌${NO_COLOR}"
    sleep 2
    pulledpork_installation
    sleep 2
    docker_installer #|| echo -ne "${RED}Dokcer installation has failed ❌${NO_COLOR}"
    sleep 2
    nextcloud_installer
    sleep 2
    yacht_installer #|| echo -ne "${RED}Yacht installation has failed ❌${NO_COLOR}"
    sleep 2
    sudo docker update --restart unless-stopped $(sudo docker ps -q)
    sleep 2
    grafana_installer #|| echo -ne "${RED}Grafana installation has failed ❌${NO_COLOR}"
    sleep 2
    prometheus_installer #|| echo -ne "${RED}Prometheus installation has failed ❌${NO_COLOR}"
    sleep 2
    node_exporter_installer #|| echo -ne "${RED}Node Exporter installation has failed ❌${NO_COLOR}"
    sleep 2
    loki_installer #|| echo -ne "${RED}Loki installation has failed ❌${NO_COLOR}"
    sleep 2
    mail_setup #|| echo -ne "${RED}Setting up mail installation has failed ❌${NO_COLOR}"
    sleep 2
    promtail_installer #|| echo -ne "${RED}Promtail installation has failed ❌${NO_COLOR}"
    sleep 2
    fail2ban_installer #|| echo -ne "${RED}Fail2ban installation has failed ❌${NO_COLOR}"
    sleep 2
    ClamAV_installer #|| echo -ne "${RED}ClamAV installation has failed ❌${NO_COLOR}"
    sleep 2
    OS_Hardening #|| echo -ne "\n${RED}OS Hardening has failed ❌${NO_COLOR}\n"
    sleep 2
    Kernel_Hardening #|| echo -ne "\n${RED}Kernel hardening has failed ❌${NO_COLOR}\n"
    sleep 2
    sudo apt-get install aha -y
    AuditD_installer #|| echo -ne "\n${RED}AuditD installation has failed ❌${NO_COLOR}\n"
    sleep 2
    Rkhunter_installer #|| echo -ne "\n${RED}Rkhunter installation has failed ❌${NO_COLOR}\n"
    sleep 2
    Lynis_installer #|| echo -ne "\n${RED}Lynis installation has failed ❌${NO_COLOR}\n"
    sleep 2
    Docker_Bench_Installer #|| echo -ne "\n${RED}Docker Bench installation has failed ❌${NO_COLOR}\n"
    sleep 2
    Firewall
    sleep 2
    Honeypot_installer #|| echo -ne "\n${RED}Setting up Honeypot has failed ❌${NO_COLOR}\n"
    sleep 2
    echo q | crontab -e
    echo -ne "\nSetting up additional scripts 📜\n"
    DDOS_Mail_Setup #|| echo -ne "\n${RED}Setting DDos mail script has failed ❌${NO_COLOR}\n"
    sleep 2
    High_RAM_Mail_Setup #|| echo -ne "\n${RED}Setting High RAM notification mail script has failed ❌${NO_COLOR}\n"
    sleep 2
    Cleanup #|| echo -ne "\n${RED}Cleanup function has failed ❌${NO_COLOR}\n"
    summary
    
    end_time=$(date +%s)
    elapsed_time=$((end_time - start_time))
    minutes=$((elapsed_time / 60))
    seconds=$((elapsed_time % 60))
    
    echo -ne "\nInstallation took: $minutes minutes and $seconds seconds 🕑\n"
    
    reboot_function
}

function enable_colors(){
    sudo sed -i 's/#force_color_prompt=yes/force_color_prompt=yes/' ~/.bashrc
    sudo echo "export LS_COLORS='rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;'" | sudo tee -a ~/.bashrc > /dev/null
    source ~/.bashrc
}

function Update() {
    echo -ne "\nUpdating the system 🖥️\n"
    sudo apt update && sudo apt upgrade -y #/dev/null 2>&1
}

function Welcome() {
    echo -ne "\nWelcome to RaspberryPi Protector insatllation 👋\n"
    sudo apt-get install figlet -y # > /dev/null 2>&1
    figlet -f slant "Raspberry Pi Protector"
    echo -n "
   .~~.   .~~.
  '. \ ' ' / .'
   .~ .~~~..~.
  : .~.'~'.~. :
 ~ (   ) (   ) ~
( : '~'.~.'~' : )
 ~ .~ (   ) ~. ~
  (  : '~' :  )
   '~ .~~~. ~'
       '~'
    "
}

function check_device_info() {
    echo -ne "\nChecking device info 🔍\n"
    sudo apt-get install neofetch -y #> /dev/null 2>&1
    check_device_info_counter=0
    # Check the amount of RAM
    ram=$(free -h | awk '/Mem:/ {print $2}' | grep -Eo '[0-9].[0-9]')
    if [ $ram -lt 3.7 ]; then
        echo -ne "\nThis device does not have enough RAM (less than 4 GB)❌\n"
        let "check_device_info_counter++"
    fi
    
    # Check the Linux distribution
    distro=$(lsb_release -i | awk '{print $3}')
    if [ "$distro" != "Ubuntu" ]; then
        echo -ne "\nThis device is not running an Ubuntu-based system❌\n"
        let "check_device_info_counter++"
    fi
    
    # Check the CPU architecture
    arch=$(uname -m)
    if [ "$arch" != "aarch64" ]; then
        echo -ne "\nThis device does not have an ARM64 CPU❌\n"
        let "check_device_info_counter++"
    fi
    
    if [ "$check_device_info_counter" -gt 0 ]; then
        result=$(whiptail --title "This device doesn't meet requirements." --yesno " Are you sure you want proceed with installation?" 8 78 3>&1 1>&2 2>&3)
        if [ $result = 0 ]; then
            echo -ne "\nThis device doesn't meet the requirements for installation❌\n"
            echo -ne "\nRunning installer, might break the system😟\n"
            break
        else
            exit 1
        fi
    fi
    
    echo -ne "\nThis device meets the requirements for installation ✅\n"
    neofetch
    sleep 5
    clear
}
function rsyslog_installer() {
    sudo apt-get install -y rsyslog
    sudo sed -i 's/#module(load="imudp")/module(load="imudp")/' /etc/rsyslog.conf
    sudo sed -i 's/#input(type="imudp" port="514")/input(type="imudp" port="514")/' /etc/rsyslog.conf
    sudo sed -i 's/#module(load="imtcp")/module(load="imtcp")/' /etc/rsyslog.conf
    sudo sed -i 's/#input(type="imtcp" port="514")/input(type="imtcp" port="514")/' /etc/rsyslog.conf
    
    echo '$template LokiFormat,"<%pri%>%protocol-version% %timestamp:::date-rfc3339% %HOSTNAME% %app-name% %procid% %msgid% [snort_event_id=%msg%][snort_sid=%msg:::json%][snort_gid=%msg:::json%]"' | sudo tee -a /etc/rsyslog.d/snort_logs.conf > /dev/null 2>&1
    echo 'if $programname == 'snort' then @@127.0.0.1:3100;LokiFormat;' | sudo tee -a /etc/rsyslog.d/snort_logs.conf > > /dev/null 2>&1
    
    sudo systemctl daemon-reload
    sudo systemctl enable rsyslog
    sudo systemctl restart rsyslog
}

function snort() {
    echo -ne "\n${PINK} Installing snort${NO_COLOR}🐖\n"
    sudo apt-get update && sudo apt-get upgrade -y
    sudo DEBIAN_FRONTEND=noninteractive apt-get install snort -y
    sudo systemctl enable snort
    sudo chmod 766 /etc/snort/rules/local.rules
    sudo sed -i 's/ipvar HOME_NET any/ipvar HOME_NET '$HOST_IP_ADDRESS'/' /etc/snort/snort.conf
    sudo sed -i 's/# output alert_syslog: LOG_AUTH LOG_ALERT/output alert_syslog: host='$HOST_IP_ADDRESS':514, LOG_AUTH LOG_ALERT /' /etc/snort/snort.conf
    sudo sed -i 's/# output log_tcpdump: tcpdump.log/output log_tcpdump: tcpdump.log/' /etc/snort/snort.conf
    wget https://raw.githubusercontent.com/adambaczkowski/snort-local-rules/main/snort_rules.txt
    sudo cat snort_rules.txt >> /etc/snort/rules/local.rules
    sudo snort -T -c /etc/snort/snort.conf
    sudo systemctl daemon-reload
    sudo systemctl restart snort.service
}

function pulledpork_installation() {
    echo -ne "\n${PURPLE} Installing Pulledpork - snort rules importer${NO_COLOR}🥩\n"
    sudo apt-get install libcrypt-ssleay-perl liblwp-protocol-https-perl -y
    git clone https://github.com/shirkdog/pulledpork.git
    cd pulledpork
    sudo cp pulledpork.pl /usr/local/bin
    sudo chmod +x /usr/local/bin/pulledpork.pl
    sudo mkdir /etc/pulledpork
    sudo cp etc/*.conf /etc/pulledpork/
    sudo sed -i "s/<oinkcode>/$OINKCODE/g" /etc/pulledpork/pulledpork.conf
    sudo sed -i "s/#rule_url=https:\/\/rules.emergingthreats.net\//https://www.snort.org/rules/snortrules-snapshot-29151.tar.gz?oinkcode='$OINKCODE'\//g" /etc/pulledpork/pulledpork.conf
    sudo sed -i "s/\/usr\/local\/etc\/snort\//\/etc\/snort\//g" /etc/pulledpork/pulledpork.conf
    sudo sed -i "s/# enablesid=/enablesid=/g" /etc/pulledpork/pulledpork.conf
    sudo sed -i "s/# dropsid=/enablesid=/g" /etc/pulledpork/pulledpork.conf
    sudo sed -i "s/# disablesid=/enablesid=/g" /etc/pulledpork/pulledpork.conf
    sudo sed -i "s/# modifysid=/enablesid=/g" /etc/pulledpork/pulledpork.conf
    sudo sed -i "s/distro=FreeBSD-12/distro=Ubuntu-18-4/g" /etc/pulledpork/pulledpork.conf
    sudo sed -i "s/# out_path=/out_path=/g" /etc/pulledpork/pulledpork.conf
    sudo chmod 766 /etc/crontab
    sudo echo "0 */12 * * * root /usr/local/bin/pulledpork.pl -c /etc/pulledpork/pulledpork.conf -i disablesid.conf -T -H" >> /etc/crontab
    sudo echo "0 */12 * * * root /usr/local/bin/ruleitor" >> /etc/crontab
    cd
    sudo pulledpork.pl -V
}

function docker_installer() {
    echo -ne "\n${BLUE}Installing docker${NO_COLOR}🐋\n"
    sudo apt-get remove docker docker-engine docker.io containerd runc -y
    sudo apt-get update
    sudo apt-get install ca-certificates curl gnupg lsb-release lsb-core -y
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update
    sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin -y
    sudo systemctl daemon-reload
    sudo systemctl enable docker
    sudo chmod 666 /var/run/docker.sock
}

function nextcloud_installer() {
    echo -ne "\n${CYAN}Installing Nextcloud${NO_COLOR}☁️\n"
    docker pull nextcloud
    docker pull postgres
    sudo docker network create --driver bridge nextcloud-net
    sudo docker run --name postgres -v /home/pi/nextcloud-db:/var/lib/postgresql/data -e POSTGRES_PASSWORD=$NEXTCLOUD_DB_PASSWORD --network nextcloud-net -d postgres
    sudo docker run --name nextcloud -d -p 8080:80 -v /home/pi/nextcloud:/var/www/html --network nextcloud-net nextcloud
    sudo systemctl daemon-reload
}

function yacht_installer() {
    echo -ne "\nInstalling Yacht ⛵\n"
    sudo docker volume create yacht
    docker pull selfhostedpro/yacht
    sudo docker run -d -p 8000:8000 -v /var/run/docker.sock:/var/run/docker.sock -v yacht:/config --name yacht selfhostedpro/yacht
    sudo systemctl daemon-reload
}

function grafana_installer() {
    echo -ne "\n${YELLOW}Installing Grafana${NO_COLOR}🌞\n"
    sudo wget -qO /etc/apt/trusted.gpg.d/grafana.asc https://packages.grafana.com/gpg.key
    echo -ne "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
    sudo apt update
    sudo apt install -y grafana
    sudo systemctl daemon-reload
    sudo service grafana-server start
    sudo systemctl enable grafana-server
    sudo usermod -a -G adm grafana
}

function prometheus_installer() {
    echo -ne "\n${ORANGE}Installing Prometheus${NO_COLOR}🔥\n"
    sudo mkdir /etc/prometheus
    sudo useradd --no-create-home --shell  prometheus
    sudo mkdir /var/lib/prometheus
    sudo groupadd prometheus
    sudo usermod -a -G prometheus prometheus
    sudo chown prometheus:prometheus /etc/prometheus
    sudo chown prometheus:prometheus /var/lib/prometheus
    sudo wget https://github.com/prometheus/prometheus/releases/download/v2.41.0/prometheus-2.41.0.linux-arm64.tar.gz
    sudo tar xvfz prometheus-*.tar.gz
    sudo cp prometheus-2.41.0.linux-arm64/prometheus /usr/local/bin/
    sudo cp prometheus-2.41.0.linux-arm64/promtool /usr/local/bin/
    sudo chown prometheus:prometheus /usr/local/bin/prometheus
    sudo chown prometheus:prometheus /usr/local/bin/promtool
    sudo cp -r prometheus-2.41.0.linux-arm64/consoles /etc/prometheus
    sudo cp -r prometheus-2.41.0.linux-arm64/console_libraries /etc/prometheus
    sudo cp -r prometheus-2.41.0.linux-arm64/prometheus.yml /etc/prometheus
    sudo chown -R prometheus:prometheus /etc/prometheus/consoles
    sudo chown -R prometheus:prometheus /etc/prometheus/console_libraries
    sudo chown -R prometheus:prometheus /etc/prometheus/prometheus.yml
    wget https://raw.githubusercontent.com/adambaczkowski/prometheus-ossec-config/main/prometheus.yml
    sudo cat prometheus.yml | sudo tee /etc/prometheus/prometheus.yml
    sudo mv prometheus-2.41.0.linux-arm64 /etc/prometheus
    sudo chown prometheus:prometheus -R /etc/prometheus
    sudo echo -n "
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target
[Service]
User=root
Group=root
Type=simple
ExecStart=/usr/local/bin/prometheus \
    --config.file /etc/prometheus/prometheus.yml \
    --storage.tsdb.path /var/lib/prometheus/ \
    --web.console.templates=/etc/prometheus/consoles \
    --web.console.libraries=/etc/prometheus/console_libraries
[Install]
WantedBy=multi-user.target
    " | sudo tee /etc/systemd/system/prometheus.service > /dev/null 2>&1
    
    sudo systemctl daemon-reload
    sudo systemctl start prometheus.service
    sudo systemctl enable prometheus.service
}

function node_exporter_installer() {
    echo -ne "\nInstalling node exporter ⚙️\n"
    wget https://github.com/prometheus/node_exporter/releases/download/v1.5.0/node_exporter-1.5.0.linux-arm64.tar.gz
    tar vxfz node_exporter-1.5.0.linux-arm64.tar.gz
    sudo useradd -m node_exporter
    sudo groupadd node_exporter
    sudo usermod -a -G node_exporter node_exporter
    sudo mv node_exporter-1.5.0.linux-arm64/node_exporter /usr/local/bin/
    sudo chown node_exporter:node_exporter /usr/local/bin/node_exporter
    sudo echo -n "
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
    " | sudo tee /etc/systemd/system/node_exporter.service > /dev/null 2>&1
    
    sudo systemctl daemon-reload
    sudo systemctl enable node_exporter
    sudo systemctl start node_exporter
    sudo rm -rf node_exporter-1.5.0.linux-arm64/
}

function loki_installer() {
    echo -ne "\nInstalling Loki 🧭\n"
    sudo apt install unzip -y
    wget https://github.com/grafana/loki/releases/download/v2.7.1/loki-linux-arm64.zip
    unzip loki-linux-arm64.zip
    sudo mkdir /opt/loki
    sudo mv loki-linux-arm64 /opt/loki/
    sudo chmod a+x /opt/loki/loki-linux-arm64
    sudo ln -s /opt/loki/loki-linux-arm64 /usr/local/bin/loki
    wget https://raw.githubusercontent.com/grafana/loki/main/cmd/loki/loki-local-config.yaml
    sudo mv loki-local-config.yaml /opt/loki
    
    sudo echo -n "
[Unit]
Description=Loki - log aggregation system
After=network.target

[Service]
User=root
ExecStart=/opt/loki/loki-linux-arm64 -config.file=/opt/loki/loki-local-config.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
    " | sudo tee /etc/systemd/system/loki.service > /dev/null 2>&1
    
    sudo systemctl daemon-reload
    sudo service loki start
    sudo systemctl enable loki.service
}

function promtail_installer() {
    echo -ne "\nInstalling Promtail 🪁\n"
    wget https://github.com/grafana/loki/releases/download/v2.7.1/promtail-linux-arm64.zip
    unzip promtail-linux-arm64.zip
    sudo mkdir /opt/promtail
    sudo mv promtail-linux-arm64 /opt/promtail/
    sudo chmod a+x /opt/promtail/promtail-linux-arm64
    sudo ln -s /opt/promtail/promtail-linux-arm64 /usr/local/bin/promtail
    wget https://raw.githubusercontent.com/grafana/loki/v2.7.1/clients/cmd/promtail/promtail-local-config.yaml
    sudo mv promtail-local-config.yaml /opt/promtail/
    
    sudo echo -n "
[Unit]
Description=Promtail client for sending logs to Loki
After=loki.service

[Service]
Type=simple
User=root
ExecStart=/opt/promtail/promtail-linux-arm64 -config.file=/opt/promtail/promtail-local-config.yaml
WorkingDirectory=/opt/promtail/
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
    " | sudo tee /etc/systemd/system/promtail.service > /dev/null 2>&1
    
    sudo systemctl daemon-reload
    sudo service promtail start
    sudo systemctl enable promtail
}

function fail2ban_installer() {
    echo -ne "\n${GREEN}Installing Fail2Ban${NO_COLOR} 🚫\n"
    sudo apt-get -y install fail2ban
    sudo cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    
    sudo sed -i 's/#ignoreip = 127.0.0.1\/8 ::1/ignoreip = 127.0.0.1\/8 ::1 '$SSH_CLIENT_IP'/' /etc/fail2ban/jail.local
    sudo sed -i 's/destemail = root@localhost/destemail = '$EMAIL'/' /etc/fail2ban/jail.local
    sudo sed -i 's/sender = root@<fq-hostname>/sender = '$EMAIL'/' /etc/fail2ban/jail.local
    sudo sed -i '285s/port = ssh/port = '$SSH_CUSTOM_PORT_NUMBER'/' /etc/fail2ban/jail.local
    
    echo -n "maxretry = 3" | sudo tee -a /etc/fail2ban/jail.d/defaults-debian.conf
    
    sudo systemctl reload ssh
    sudo systemctl daemon-reload
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
}

function ClamAV_installer() {
    echo -ne "\n${RED}Installing ClamAV - Antivirus${NO_COLOR}👾\n"
    sudo apt-get -y install clamav clamav-daemon
    sudo systemctl stop clamav-freshclam
    sudo freshclam || wget https://database.clamav.net/daily.cvd
    sudo mkdir /var/lib/clamav
    sudo cp daily.cvd /var/lib/clamav/daily.cvd
    sudo systemctl daemon-reload
    sudo systemctl start clamav-freshclam
    sudo systemctl enable clamav-freshclam
    #sudo clamscan --infected --recursive --remove /
}

function mail_setup() {
    echo -ne "\nInsatlling and setting up mail 📧\n"
    sudo apt-get install libio-socket-ssl-perl libnet-ssleay-perl -y
    sudo apt install ssmtp enscript ghostscript mailutils mpack -y
    sudo chown root:mail /etc/ssmtp/ssmtp.conf
    echo -n "
root="$EMAIL"
mailhub=smtp.gmail.com:465
rewriteDomain=gmail.com
AuthUser="$EMAIL"
AuthPass="$EMAIL_PASSWORD"
FromLineOverride=YES
UseTLS=YES
    " | sudo tee -a /etc/ssmtp/ssmtp.conf > /dev/null 2>&1
}

function AuditD_installer() {
    echo -ne "\n${PURPLE}Installing AuditD${NO_COLOR}👓\n"
    sudo apt install auditd expect -y
    sudo rm /etc/audit/rules.d/audit.rules
    sudo wget https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules -P /etc/audit/rules.d/
    sudo systemctl daemon-reload
    sudo service auditd start
    sudo systemctl enable auditd.service
    sudo aureport --summary > AuditD_Report.txt
    enscript AuditD_Report.txt --output=- | ps2pdf - > AuditD_Report.pdf
    mpack -s "AuditD Report summary" -a AuditD_Report.pdf $EMAIL
    rm AuditD_Report.txt #AuditD_Report.pdf
}

function Rkhunter_installer() {
    echo -ne "\n${PINK}Installing Rkhunter - rootkit check engine{$NO_COLOR}🕵️‍♂️\n"
    sudo apt install rkhunter -y
    sudo rkhunter --check --skip-keypress
    sudo cat /var/log/rkhunter.log > rkhunter_report.txt
    enscript rkhunter_report.txt --output=- | ps2pdf - > rkhunter_report.pdf
    mpack -s "Rkhuner log report" -a rkhunter_report.pdf $EMAIL
    rm rkhunter_report.txt #rkhunter_report.pdf
}

function Honeypot_installer() {
    echo -ne "\n${YELLOW}Creating Honeypot{$NO_COLOR}🐝\n"
    sudo iptables -N HONEYPOT
    sudo iptables -A HONEYPOT -j LOG --log-prefix "honeypot: " --log-level 6
    sudo iptables -A HONEYPOT -j DROP
    sudo iptables -A INPUT -p tcp -m tcp --dport 22 --tcp-flags FIN,SYN,RST,ACK SYN -j HONEYPOT
    sudo iptables-save > ~/iptables.save
    
    
    echo -n "
[honeypot]
enabled  = true
filter   = honeypot
logpath  = /var/log/messages
banaction = iptables-allports
bantime  = 604800
maxretry = 3
    " | sudo tee -a /etc/fail2ban/jail.local
    
    echo -n "
[INCLUDES]
# Read common prefixes. If any customizations available -- read them from
# common.local
before = common.conf

[Definition]

_daemon = fail2ban\.actions
_jailname = honeypot
failregex = honeypot: .*? SRC=<HOST>
    " | sudo tee -a /etc/fail2ban/filter.d/honeypot.conf > /dev/null 2>&1
    sudo fail2ban-client reload honeypot
    sudo systemctl reload ssh
    
}

function Lynis_installer() {
    echo -ne "\n${GREEN}Installing Lynis - System security audit${NO_COLOR}🎯\n"
    sudo apt install lynis mpack -y
    sudo lynis audit system
    sudo cat /var/log/lynis.log > lynis_log.txt
    enscript lynis_log.txt --output=- | ps2pdf - > lynis_log.pdf
    mpack -s "Lynis system audit" -a lynis_log.pdf $EMAIL
    rm lynis_log.txt #lynis_log.pdf
}

function Docker_Bench_Installer() {
    echo -ne "\n${BLUE}Installing DockerBench - Docker containers security audit${NO_COLOR}📦\n"
    git clone https://github.com/docker/docker-bench-security.git
    cd docker-bench-security
    sudo ./docker-bench-security.sh > ~/docker_audit.txt
    cd
    enscript docker_audit.txt --output=- | ps2pdf - > docker_audit.pdf
    mpack -s "Docker security audit" -a docker_audit.pdf $EMAIL
    rm docker_audit.txt #docker_audit.pdf
}

function OS_Hardening() {
    echo -ne "\nPerforming OS hardening 🔒\n"
    echo "Disabling Wi-Fi"
    sudo apt install rfkill -y
    sudo rfkill block 1
    echo "Disabling Bluetooth"
    sudo systemctl disable hciuart.service
    echo "Empty password check"
    sudo awk -F: '($2 == "") {print}' /etc/shadow
    echo "Disabling Telnet"
    sudo apt-get remove telnetd -y /dev/null 2>&1
    echo "Turining off shared memory"
    sudo echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" | sudo tee -a /etc/fstab
}

function Kernel_Hardening() {
    echo -ne "\nPerforming Kernel hardening 🔒\n"
    #https://madaidans-insecurities.github.io/guides/linux-hardening.html
    
    #Kernel self-protection
    sudo sysctl sysctl kernel.kptr_restrict=2
    sudo sysctl kernel.dmesg_restrict=1
    sudo sysctl kernel.printk=3 3 3 3
    sudo sysctl kernel.unprivileged_bpf_disabled=1
    sudo sysctl net.core.bpf_jit_harden=2
    sudo sysctl dev.tty.ldisc_autoload=0
    sudo sysctl vm.unprivileged_userfaultfd=0
    sudo sysctl kernel.kexec_load_disabled=1
    sudo sysctl kernel.sysrq=4
    sudo sysctl kernel.unprivileged_userns_clone=0
    sudo sysctl kernel.perf_event_paranoid=3
    
    #Network
    sudo sysctl net.ipv4.tcp_syncookies=1
    sudo sysctl net.ipv4.tcp_rfc1337=1
    sudo sysctl net.ipv4.conf.all.rp_filter=1
    sudo sysctl net.ipv4.conf.default.rp_filter=1
    
    sudo sysctl net.ipv4.conf.all.accept_redirects=0
    sudo sysctl net.ipv4.conf.default.accept_redirects=0
    sudo sysctl net.ipv4.conf.all.secure_redirects=0
    sudo sysctl net.ipv4.conf.default.secure_redirects=0
    sudo sysctl net.ipv6.conf.all.accept_redirects=0
    sudo sysctl net.ipv6.conf.default.accept_redirects=0
    sudo sysctl net.ipv4.conf.all.send_redirects=0
    sudo sysctl net.ipv4.conf.default.send_redirects=0
    
    sudo sysctl net.ipv4.icmp_echo_ignore_all=1
    
    sudo sysctl net.ipv4.conf.all.accept_source_route=0
    sudo sysctl net.ipv4.conf.default.accept_source_route=0
    sudo sysctl net.ipv6.conf.all.accept_source_route=0
    sudo sysctl net.ipv6.conf.default.accept_source_route=0
    
    sudo sysctl net.ipv6.conf.all.accept_ra=0
    sudo sysctl net.ipv6.conf.default.accept_ra=0
    
    sudo sysctl net.ipv4.tcp_sack=0
    sudo sysctl net.ipv4.tcp_dsack=0
    sudo sysctl net.ipv4.tcp_fack=0
    
    #User space
    sudo sysctl kernel.yama.ptrace_scope=2
    
    sudo sysctl vm.mmap_rnd_bits=32
    sudo sysctl vm.mmap_rnd_compat_bits=16
    
    sudo sysctl fs.protected_fifos=2
    sudo sysctl fs.protected_regular=2
    
    # Turn off unnecesary kernel modules
    sudo echo 'blacklist dccp' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist sctp ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist rds ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist tipc ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist n-hdlc ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist ax25 ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist netrom ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist x25 ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist rose ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist decnet ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist econet ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist af_802154 ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist ipx ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist appletalk ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist psnap ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist p8023 ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist p8022 ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist can ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist atm ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist cramfs ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist freevxfs ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist jffs2 ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist hfs ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist hfsplus ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist squashfs ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist udf ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist bluetooth ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist btusb ' | sudo tee -a /etc/modprobe.d/blacklist.conf
    sudo echo 'blacklist uvcvideo ' | sudo tee -a /etc/modprobe.d/blacklist.conf
}

function Firewall() {
    echo -ne "\n${ORANGE}Setting up Firewall 🔥${NO_COLOR}\n"
    sudo systemctl reload ssh
    sudo ufw allow 22
    sudo ufw allow 80
    sudo ufw allow 443
    sudo ufw allow 8080
    sudo ufw allow 8000
    sudo ufw allow 587
    sudo ufw allow 143
    sudo ufw allow 993
    sudo ufw allow 3000
    sudo ufw allow 9090
    sudo ufw allow 9093
    sudo ufw allow 9100
    sudo ufw allow 3100
    sudo ufw allow 9096
    sudo ufw allow 2222
    sudo ufw allow 514
    sudo ufw allow $SSH_CUSTOM_PORT_NUMBER
    sudo echo -ne "y" | sudo ufw enable
    sudo sed -i 's/#   Port 22/    Port '$SSH_CUSTOM_PORT_NUMBER'/' /etc/ssh/ssh_config
    sudo sed -i 's/#Port 22/Port '$SSH_CUSTOM_PORT_NUMBER'/' /etc/ssh/sshd_config
    sudo systemctl daemon-reload
    sudo systemctl reload ssh
    sudo fail2ban-client set sshd unbanip $SSH_CLIENT_IP
}

function DDOS_Mail_Setup() {
    
    echo -n "
#!/bin/bash
# Set the threshold for number of connections per second
THRESHOLD=100

# Get the current number of connections per second
CONNS_PER_SEC=$(sudo iptables -vnL | awk '{print $2}' | tail -n1)

# Check if the number of connections per second is above the threshold
if [ $CONNS_PER_SEC -gt $THRESHOLD ]; then
    echo "DDoS attack detected! Number of connections per second: $CONNS_PER_SEC"
    echo q | htop | aha --black --line-fix > htop.html
    mpack -s "DDoS Alert" -a htop.html $EMAIL
    fi" | sudo tee ddos_cron.sh
    sudo chmod 766 /etc/crontab
    sudo mv ddos_cron.sh /usr/local/bin > /dev/null 2>&1
    sudo chmod +x /usr/local/bin/ddos_cron.sh > /dev/null 2>&1
    sudo echo "1 * * * * root /usr/local/bin/ddos_cron.sh" | sudo tee -a /etc/crontab > /dev/null 2>&1
}

function High_RAM_Mail_Setup() {
    echo -n "
#!/bin/bash
# Set the threshold for RAM usage in %
THRESHOLD=85

# Get the current RAM usage in %
RAM_USAGE=$(free -m | awk '/^Mem:/{print $3/$2 * 100.0}')

# Check if the RAM usage is above the threshold
if [ $(echo "$RAM_USAGE > $THRESHOLD" | bc) -eq 1 ]; then
    echo "RAM usage is above 85%! Current usage: $RAM_USAGE%"
    echo q | htop | aha --black --line-fix > htop.html
    mpack -s "RAM Alert" -a htop.html $EMAIL
    fi" | sudo tee high_ram_cron.sh
    sudo chmod 766 /etc/crontab
    sudo mv high_ram_cron.sh /usr/local/bin > /dev/null 2>&1
    sudo chmod +x /usr/local/bin/high_ram_cron.sh > /dev/null 2>&1
    sudo echo "1 * * * * root /usr/local/bin/high_ram_cron.sh" | sudo tee -a /etc/crontab > /dev/null 2>&1
}

function Cleanup() {
    cd ~/
    echo -ne "\nCleaning home directory...🧹\n"
    sudo rm prometheus-2.41.0.linux-arm64.tar.gz
    sudo rm node_exporter-1.5.0.linux-arm64.tar.gz
    sudo rm loki-linux-arm64.zip
    sudo rm promtail-linux-arm64.zip
    sudo rm prometheus.yml
    sudo rm snort_rules.txt
}

function summary() {
    clear
    echo "SUMMARY:"
    echo "Docker containers status"
    sudo docker ps -a
    echo "SystemD not working/failed units"
    sudo systemctl list-units --type=service --state=failed
    echo "Firewall rules"
    sudo ufw status numbered
    echo -ne "\n🟡 Your SSH Port is switched to: "$SSH_CUSTOM_PORT_NUMBER" remember that during next SSH session. ssh <user>@{server-ip-address} -p "$SSH_CUSTOM_PORT_NUMBER "🟡\n"
}

function reboot_function() {
    read -p "Are you sure you want to reboot the system? [y/n] " -n 1 -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Rebooting system..."
        sleep 2
        sudo reboot
    else
        echo "Reboot cancelled"
    fi
}

function progress_bar() {
    #usage: progress_bar script_name.sh
    iterations=100
    function_name=$1
    i=0
    while [ $i -lt $iterations ]
    do
        echo -n "#"
        $function_name
        if [ $? -eq 0 ]; then
            i=$((i+1))
        else
            echo "Progress bar error - script failed!"
            exit 1
        fi
        # Move cursor to the beginning of the line
        printf "\033[1A"
        # Output the percentage
        printf "%.0f%%" $((i*100/iterations))
    done
    echo ""
}
main
#EOF
