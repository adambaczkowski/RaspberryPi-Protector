#!/bin/bash
#Author: Adam Bączkowski
#Page: github.com/adambaczkowski
#LICENSE: GNUPLv2

#COLORS
RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
PINK='\033[0;35m'

function main() {
    Welcome
    whiptail --title "Information" --msgbox "If you are running this script on a fresh instance of Raspberry Pi, consider running 'sudo apt-get update && sudo apt-get upgrade' followed by a reboot before running the installation script." 10 60
    #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
    #VARIABLES
    HOST_IP_ADDRESS=$(hostname -I | awk '{print $1}')
    HOST_MASK_ADDRESS=$(ip addr show | grep -oP '^[0-9]+: \K(e[^:]*)')
    E_MAIL=$(whiptail --inputbox "Enter your email address:" 8 78 --title "Email" 3>&1 1>&2 2>&3)
    E_MAIL_PASSWORD=$(whiptail --passwordbox "Enter your email password:" 8 78 --title "Password" 3>&1 1>&2 2>&3)
    GRAFANA_LOGIN=$(whiptail --inputbox "Enter your Grafana login:" 8 78 --title "Grafana Login" 3>&1 1>&2 2>&3)
    GRAFANA_PASSWORD=$(whiptail --passwordbox "Enter your Grafana password:" 8 78 --title "Grafana Password" 3>&1 1>&2 2>&3)
    NEXTCLOUD_LOGIN=$(whiptail --inputbox "Enter your Nextcloud login:" 8 78 --title "Nextcloud Login" 3>&1 1>&2 2>&3)
    NEXTCLOUD_PASSWORD=$(whiptail --passwordbox "Enter your Nextcloud password:" 8 78 --title "Nextcloud Password" 3>&1 1>&2 2>&3)
    NEXTCLOUD_DB_PASSWORD=$(whiptail --passwordbox "Enter your Nextcloud Database password:" 8 78 --title "Nextcloud Database Password" 3>&1 1>&2 2>&3)
    OINKCODE=$(whiptail --inputbox "Enter your Oinkcode for Snort. If you don't have Snort account, please register at https://www.snort.org/users/sign_in in order to get newest Snort ules:" 8 78 --title "Snort Oinkcode" 3>&1 1>&2 2>&3)
    SSH_CLIENT_IP=$(echo $SSH_CLIENT | awk '{ print $1}')
    SSH_CUSTOM_PORT_NUMBER=$(whiptail --inputbox "Enter your custom SSH port number between 1024 and 65536 :" 8 78 --title "SSH Port" 3>&1 1>&2 2>&3)
    if [[ $SSH_CUSTOM_PORT_NUMBER -eq 22 || $SSH_CUSTOM_PORT_NUMBER -eq 80 || $SSH_CUSTOM_PORT_NUMBER -eq 443 || $SSH_CUSTOM_PORT_NUMBER -eq 8080 ]]
    then
        echo "Invalid port number. I've chosen port 60001 for You"
        $SSH_CUSTOM_PORT_NUMBER=60001
    else
        echo "Custom SSH port number: $SSH_CUSTOM_PORT_NUMBER"
    fi
    #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
    sleep 5
    check_device_info
    start_time=$(date +%s)
    Update || echo "${RED}Update has failed ❌${RED}"
    snort || echo "${RED}Snort installation has failed ❌${RED}"
    docker_installer || echo "${RED}Dokcer installation has failed ❌${RED}"
    yacht_installer || echo "${RED}Yacht installation has failed ❌${RED}"
    sudo docker update --restart unless-stopped $(sudo docker ps -q)
    grafana_installer || echo "${RED}Grafana installation has failed ❌${RED}"
    prometheus_installer || echo "${RED}Prometheus installation has failed ❌${RED}"
    node_exporter_installer || echo "${RED}Node Exporter installation has failed ❌${RED}"
    loki_installer || echo "${RED}Loki installation has failed ❌${RED}"
    promtail_installer || echo "${RED}Promtail installation has failed ❌${RED}"
    mail_setup || echo "${RED}Setting up mail installation has failed ❌${RED}"
    fail2ban_installer || echo "${RED}Fail2ban installation has failed ❌${RED}"
    ClamAV_installer || echo "${RED}ClamAV installation has failed ❌${RED}"
    AuditD_installer|| echo "${RED}AuditD installation has failed ❌${RED}"
    Rkhunter_installer|| echo "${RED}Rkhunter installation has failed ❌${RED}"
    #Honeypot_installer || echo "${RED}Setting up Honeypot has failed ❌${RED}"
    Lynis_installer || echo "${RED}Lynis installation has failed ❌${RED}"
    Docker_Bench_Installer || echo "${RED}Docker Bench installation has failed ❌${RED}"
    OS_Hardening || echo "${RED}OS Hardening has failed ❌${RED}"
    Kernel_Hardening || echo "${RED}Kernel hardening has failed ❌${RED}"
    sudo apt-get install aha -y
    echo q | crontab -e
    echo "Setting up additional scripts 📜"
    DDOS_Mail_Setup || echo "${RED}Setting DDos mail script has failed ❌${RED}"
    High_RAM_Mail_Setup || echo "${RED}Setting High RAM notification mail script has failed ❌${RED}"
    Cleanup || echo "${RED}Cleanup function has failed ❌${RED}"
    summary
    end_time=$(date +%s)
    elapsed_time=$((end_time - start_time))
    minutes=$((elapsed_time / 60))
    seconds=$((elapsed_time % 60))
    echo "Installation took: $minutes minutes and $seconds seconds ⏰"
    reboot_function
}



function Update() {
    echo "Updating the system 🖥️"
    sudo apt update && sudo apt upgrade -y #/dev/null 2>&1
}

function Welcome() {
    echo "Welcome to RaspberryPi Protector insatllation 👋"
    sudo apt-get install figlet -y # > /dev/null 2>&1
    figlet -f slant "Raspberry Pi Protector"
    echo -ne "
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
    echo "Checking device info 🔍"
    sudo apt-get install neofetch -y #> /dev/null 2>&1
    
    check_device_info_counter=0
    
    # Check the amount of RAM
    ram=$(free -h | awk '/Mem:/ {print $2}' | grep -Eo '[0-9].[0-9]')
    if [ $ram -lt 3.7 ]; then
        echo "This device does not have enough RAM (less than 4 GB)❌"
        let "check_device_info_counter++"
    fi
    
    # Check the Linux distribution
    distro=$(lsb_release -i | awk '{print $3}')
    if [ "$distro" != "Ubuntu" ]; then
        echo "This device is not running an Ubuntu-based system❌"
        let "check_device_info_counter++"
    fi
    
    # Check the CPU architecture
    arch=$(uname -m)
    if [ "$arch" != "aarch64" ]; then
        echo "This device does not have an ARM64 CPU❌"
        let "check_device_info_counter++"
    fi
    
    if [ "$check_device_info_counter" -gt 0 ]; then
        result=$(whiptail --title "This device doesn't meet requirements." --yesno " Are you sure you want proceed with installation?" 8 78 3>&1 1>&2 2>&3)
        if [ $result = 0 ]; then
            echo "This device doesn't meet the requirements for installation❌"
            echo "Running installer, might break the system😟"
        else
            exit 1
        fi
    fi
    
    echo "This device meets the requirements for installation✅"
    neofetch
    sleep 5
}

function snort() {
    echo "${PINK}Installing snort${PINK}🐖"
    sudo apt-get update && sudo apt-get upgrade -y
    echo "\n" | sudo apt-get install snort -y
    sudo systemctl enable snort
    sudo chmod 766 /etc/snort/rules/local.rules
    sudo sed -i 's/ipvar HOME_NET any/ipvar HOME_NET '$HOST_IP_ADDRESS'/' /etc/snort/snort.conf
    wget https://raw.githubusercontent.com/adambaczkowski/snort-local-rules/main/snort_rules.txt
    sudo cat snort_rules.txt >> /etc/snort/rules/local.rules
    sudo snort -T -c /etc/snort/snort.conf
    sudo systemctl daemon-reload
    sudo systemctl restart snort.service
}

function docker_installer() {
    echo "${BLUE}Installing docker${BLUE}🐋"
    sudo apt-get -y install ca-certificates curl gnupg lsb-release
    sudo mkdir -p /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    sudo systemctl enable docker
    sudo chmod 666 /var/run/docker.sock
}

function nextcloud_installer() {
    echo "${CYAN}Installing Nextcloud${CYAN}☁️"
    docker pull nextcloud
    docker pull postgres
    sudo docker network create --driver bridge nextcloud-net
    sudo docker run --name postgres -v /home/pi/nextcloud-db:/var/lib/postgresql/data -e POSTGRES_PASSWORD=$NEXTCLOUD_DB_PASSWORD --network nextcloud-net -d postgres
    sudo docker run --name nextcloud -d -p 8080:80 -v /home/pi/nextcloud:/var/www/html --network nextcloud-net nextcloud
}

function yacht_installer() {
    echo "Installing Yacht ⛵"
    sudo docker volume create yacht
    docker pull selfhostedpro/yacht
    sudo docker run -d -p 8000:8000 -v /var/run/docker.sock:/var/run/docker.sock -v yacht:/config --name yacht selfhostedpro/yacht
}

function grafana_installer() {
    echo "${YELLOW}Installing Grafana${YELLOW}🌞"
    sudo wget -qO /etc/apt/trusted.gpg.d/grafana.asc https://packages.grafana.com/gpg.key
    echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
    sudo apt update
    sudo apt install -y grafana
    sudo service grafana-server start
    sudo systemctl enable grafana-server
    sudo usermod -a -G adm grafana
    
}

function prometheus_installer() {
    echo "${ORANGE}Installing Prometheus${ORANGE}🔥"
    sudo mkdir /etc/prometheus
    sudo useradd --no-create-home --shell /bin/false prometheus
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
    " | sudo tee /etc/systemd/system/prometheus.service
    
    sudo systemctl daemon-reload
    sudo systemctl start prometheus.service
    sudo systemctl enable prometheus.service
}

function node_exporter_installer() {
    echo "Installing node exporter ⚙️"
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
    " | sudo tee /etc/systemd/system/node_exporter.service
    
    sudo systemctl daemon-reload
    sudo systemctl enable node_exporter
    sudo systemctl start node_exporter
    sudo rm -rf node_exporter-1.5.0.linux-arm64/
}

function loki_installer() {
    echo "Installing Loki 🧭"
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
    " | sudo tee /etc/systemd/system/loki.service
    
    sudo systemctl daemon-reload
    sudo service loki start
    sudo systemctl enable loki.service
}

function promtail_installer() {
    echo "Installing Promtail 🪁"
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
    " | sudo tee /etc/systemd/system/promtail.service
    
    sudo systemctl daemon-reload
    sudo service promtail start
    sudo systemctl enable promtail
}

function fail2ban_installer() {
    echo "${GREEN}Installing Fail2Ban${GREEN} 🚫"
    sudo apt-get -y install fail2ban sendmail
    sudo cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    
    sudo sed -i 's/#ignoreip = 127.0.0.1\/8 ::1/ignoreip = 127.0.0.1\/8 ::1 '$SSH_CLIENT_IP'/' /etc/fail2ban/jail.local
    sudo sed -i 's/destemail = root@localhost/destemail = '$E_MAIL'/' /etc/fail2ban/jail.local
    sudo sed -i 's/sender = root@<fq-hostname>/sender = '$E_MAIL'/' /etc/fail2ban/jail.local
    sudo sed -i 's/port = 0:65535/port = 0:'$SSH_CUSTOM_PORT_NUMBER'/' /etc/fail2ban/jail.local
    sudo systemctl enable fail2ban
    sudo systemctl start sendmail
}

function ClamAV_installer() {
    echo "${RED}Installing ClamAV - Antivirus${RED}👾"
    sudo apt-get -y install clamav clamav-daemon
    sudo systemctl stop clamav-freshclam
    sudo freshclam || wget https://database.clamav.net/daily.cvd
    sudo mkdir /var/lib/clamav
    sudo cp daily.cvd /var/lib/clamav/daily.cvd
    sudo systemctl start clamav-freshclam
    sudo systemctl enable clamav-freshclam
    #sudo clamscan --infected --recursive --remove /
}

function mail_setup() {
    echo "Insatlling and setting up mail 📧"
    sudo apt-get install libio-socket-ssl-perl libnet-ssleay-perl sendemail -y
    sudo apt install ssmtp enscript ghostscript mailutils mpack -y
    chmod 640 /etc/ssmtp/ssmtp.conf
    sudo chown root:mail /etc/ssmtp/ssmtp.conf
    
    echo -n "
root="$E_MAIL"
mailhub=smtp.gmail.com:465
rewriteDomain=gmail.com
AuthUser="$E_MAIL"
AuthPass="$E_MAIL_PASSWORD"
FromLineOverride=YES
UseTLS=YES
    " | sudo tee /etc/ssmtp/ssmtp.conf /dev/null 2>&1
    
    sudo systemctl daemon-reload
}

function AuditD_installer() {
    echo "${PURPLE}Installing AuditD${PURPLE}👓"
    sudo apt install auditd expect -y
    sudo rm /etc/audit/rules.d/audit.rules
    sudo wget https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules -P /etc/audit/rules.d/
    sudo service auditd start
    sudo systemctl enable auditd.service
    sudo aureport --summary > AuditD_Report.txt
    enscript AuditD_Report.txt --output=- | ps2pdf - > AuditD_Report.pdf
    mpack -s "AuditD Report summary" -a AuditD_Report.pdf $E_MAIL
    rm AuditD_Report.txt AuditD_Report.pdf
}

function Rkhunter_installer() {
    echo "${PINK}Installing Rkhunter - rootkit check engine{$PINK}🕵️‍♂️"
    sudo apt install rkhunter -y
    sudo rkhunter --check --skip-keypress
    sudo cat /var/log/rkhunter.log > rkhunter_report.txt
    enscript rkhunter_report.txt --output=- | ps2pdf - > rkhunter_report.pdf
    mpack -s "Rkhuner log report" -a rkhunter_report.pdf $E_MAIL
    rm rkhunter_report.txt rkhunter_report.pdf
}

function Honeypot_installer() {
    echo "${YELLOW}Setting up Honeypot${YELLOW}🐝"
    git clone https://github.com/adambaczkowski/RaspberryPi-Honeypot
    cd RaspberryPi-Honeypot
    sudo chmod +x install.sh
    sudo ./install.sh
    sudo sed -i 's/#Port 22/Port '$SSH_CUSTOM_PORT_NUMBER'/' /etc/ssh/sshd_config
}


function Lynis_installer() {
    echo "${GREEN}Installing Lynis - System security audit${GREEN}🎯"
    sudo apt install lynis mpack -y
    sudo lynis audit system
    sudo cat /var/log/lynis.log > lynis_log.txt
    enscript lynis_log.txt --output=- | ps2pdf - > lynis_log.pdf
    mpack -s "Lynis system audit" -a lynis_log.pdf $E_MAIL
    rm lynis_log.txt lynis_log.pdf
}

function Docker_Bench_Installer() {
    echo "${BLUE}Installing DockerBench - Docker containers security audit${BLUE}📦"
    git clone https://github.com/docker/docker-bench-security.git
    cd docker-bench-security
    sudo ./docker-bench-security.sh > ~/docker_audit.txt
    cd
    enscript docker_audit.txt --output=- | ps2pdf - > docker_audit.pdf
    mpack -s "Docker security audit" -a docker_audit.pdf $E_MAIL
    rm docker_audit.txt docker_audit.pdf
}

function OS_Hardening() {
    echo "Perofrming OS hardening 🔒"
    echo "Disabling Wi-Fi"
    sudo apt install rfkill -y
    sudo rfkill block 1
    echo "Disabling Bluetooth"
    sudo systemctl disable hciuart.service
    echo "Empty password check"
    sudo awk -F: '($2 == "") {print}' /etc/shadow
    echo "Disabling Telnet"
    sudo apt-get remove telnetd -y /dev/null 2>&1
}

function Kernel_Hardening() {
    echo "Perofrming Kernel hardening 🔒"
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
    sudo echo 'dccp /bin/false' >> /etc/modprobe.d
    sudo echo 'sctp /bin/false' >> /etc/modprobe.d
    sudo echo 'rds /bin/false' >> /etc/modprobe.d
    sudo echo 'tipc /bin/false' >> /etc/modprobe.d
    sudo echo 'n-hdlc /bin/false' >> /etc/modprobe.d
    sudo echo 'ax25 /bin/false' >> /etc/modprobe.d
    sudo echo 'netrom /bin/false' >> /etc/modprobe.d
    sudo echo 'x25 /bin/false' >> /etc/modprobe.d
    sudo echo 'rose /bin/false' >> /etc/modprobe.d
    sudo echo 'decnet /bin/false' >> /etc/modprobe.d
    sudo echo 'econet /bin/false' >> /etc/modprobe.d
    sudo echo 'af_802154 /bin/false' >> /etc/modprobe.d
    sudo echo 'ipx /bin/false' >> /etc/modprobe.d
    sudo echo 'appletalk /bin/false' >> /etc/modprobe.d
    sudo echo 'psnap /bin/false' >> /etc/modprobe.d
    sudo echo 'p8023 /bin/false' >> /etc/modprobe.d
    sudo echo 'p8022 /bin/false' >> /etc/modprobe.d
    sudo echo 'can /bin/false' >> /etc/modprobe.d
    sudo echo 'atm /bin/false' >> /etc/modprobe.d
    sudo echo 'cramfs /bin/false' >> /etc/modprobe.d
    sudo echo 'freevxfs /bin/false' >> /etc/modprobe.d
    sudo echo 'jffs2 /bin/false' >> /etc/modprobe.d
    sudo echo 'hfs /bin/false' >> /etc/modprobe.d
    sudo echo 'hfsplus /bin/false' >> /etc/modprobe.d
    sudo echo 'squashfs /bin/false' >> /etc/modprobe.d
    sudo echo 'udf /bin/false' >> /etc/modprobe.d
    sudo echo 'cifs /bin/true' >> /etc/modprobe.d
    sudo echo 'nfs /bin/true' >> /etc/modprobe.d
    sudo echo 'nfsv3 /bin/true' >> /etc/modprobe.d
    sudo echo 'nfsv4 /bin/true' >> /etc/modprobe.d
    sudo echo 'ksmbd /bin/true' >> /etc/modprobe.d
    sudo echo 'gfs2 /bin/true' >> /etc/modprobe.d
    sudo echo 'bluetooth /bin/false' >> /etc/modprobe.d
    sudo echo 'btusb /bin/false' >> /etc/modprobe.d
    sudo echo 'uvcvideo /bin/false' >> /etc/modprobe.d
    rfkill block all
}

function Firewall() {
    echo "${ORANGE}Setting up Firewall 🔥${ORANGE}"
    echo "y" | sudo ufw enable
    sudo ufw allow ssh
    sudo ufw allow 80
    sudo ufw allow 443
    sudo ufw allow 8080
    sudo ufw allow 8000
    sudo ufw allow 587
    sudo ufw allow 110
    sudo ufw allow 995
    sudo ufw allow 143
    sudo ufw allow 993
    sudo ufw allow 3000
    sudo ufw allow 9090
    sudo ufw allow 9093
    sudo ufw allow 9100
    sudo ufw allow 3100
    sudo ufw allow 9096
    sudo ufw allow $SSH_CUSTOM_PORT_NUMBER
}

function DDOS_Mail_Setup() {
    
    echo -ne "
#!/bin/bash
# Set the threshold for number of connections per second
THRESHOLD=100

# Get the current number of connections per second
CONNS_PER_SEC=$(sudo iptables -vnL | awk '{print $2}' | tail -n1)

# Check if the number of connections per second is above the threshold
if [ $CONNS_PER_SEC -gt $THRESHOLD ]; then
    echo "DDoS attack detected! Number of connections per second: $CONNS_PER_SEC"
    echo q | htop | aha --black --line-fix > htop.html
    mpack -s "DDoS Alert" -a htop.html $E_MAIL
    fi" | sudo tee ddos_cron.sh
    sudo chmod 766 /etc/crontab
    sudo mv ddos_cron.sh /usr/local/bin > /dev/null 2>&1
    sudo chmod +x /usr/local/bin/ddos_cron.sh > /dev/null 2>&1
    sudo echo "1 * * * * root /usr/local/bin/ddos_cron.sh" >> /etc/crontab
}

function High_RAM_Mail_Setup() {
    echo -ne "
#!/bin/bash
# Set the threshold for RAM usage in %
THRESHOLD=85

# Get the current RAM usage in %
RAM_USAGE=$(free -m | awk '/^Mem:/{print $3/$2 * 100.0}')

# Check if the RAM usage is above the threshold
if [ $(echo "$RAM_USAGE > $THRESHOLD" | bc) -eq 1 ]; then
    echo "RAM usage is above 85%! Current usage: $RAM_USAGE%"
    echo q | htop | aha --black --line-fix > htop.html
    mpack -s "RAM Alert" -a htop.html $E_MAIL
    fi" | sudo tee high_ram_cron.sh
    sudo chmod 766 /etc/crontab
    sudo mv high_ram_cron.sh /usr/local/bin > /dev/null 2>&1
    sudo chmod +x /usr/local/bin/high_ram_cron.sh > /dev/null 2>&1
    sudo echo "1 * * * * root /usr/local/bin/high_ram_cron.sh" >> /etc/crontab
}

function Cleanup() {
    cd ~/
    echo "Cleaning home directory...🧹"
    sudo rm prometheus-2.41.0.linux-arm64.tar.gz
    sudo rm node_exporter-1.5.0.linux-arm64.tar.gz
    sudo rm loki-linux-arm64.zip
    sudo rm promtail-linux-arm64.zip
    sudo rm prometheus.yml
    sudo rm snort_rules.txt
}

function summary() {
    sudo systemctl list-units --type=service --state=failed
    echo "Your SSH Port is switched to: "$SSH_CUSTOM_PORT_NUMBER" remember that during next SSH session. ssh <user>@{server-ip-address} -p "$SSH_CUSTOM_PORT_NUMBER
}

function reboot_function() {
    read -p "Are you sure you want to reboot the system? [y/n] " -n 1 -r
    echo
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
