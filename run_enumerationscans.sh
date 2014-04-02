#!/usr/bin/env bash

# Copyright (c) 2014, Milbot
# https://github.com/milbot/enumerator
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

SOURCE=
TARGET=
CLIENT=
CLEAN=

while getopts "s:c:Ct:S:" OPTIONS
do
            case $OPTIONS in
            s)     SOURCE=$OPTARG;;
            c)     CLIENT=$OPTARG;;
            C)     CLEAN=TRUE;;
            t)     TARGET=$OPTARG;;
        S)     SCANS+=( "${OPTARG}" );;
            ?)     printf "Invalid option: -$OPTARG\n" $0
                          exit 2;;
           esac
done

SOURCE=${SOURCE:=NULL}
CLEAN=${CLEAN:=NULL}
TARGET=${TARGET:=NULL}
SCANS=${SCANS:=NULL}
CLIENT=${CLIENT:=NULL}

BOLD="\e[1m"
DIM="\e[2m"
ENDC="\e[22m"

##########################################
#  ~~~ Cleanup routine just in case ~~~  #
##########################################

if [ $CLEAN = "TRUE" ]
then
    cd ~/assessments/
    rm -rf "$CLIENT"/"$TARGET"
fi

##################
#  ~~~ Menu ~~~  #
##################

if [ $SOURCE = NULL ] || [ $TARGET = NULL ] || [ $CLIENT = NULL ] || [ $SCANS = NULL ]
then
    echo ""
    echo -e "\e[93m--------------------------------------------------------------------\e[39m"
    echo -e "\e[93m|                          Enumeration Scans                       |\e[39m"
    echo -e "\e[93m--------------------------------------------------------------------\e[39m"
    echo -e "|$BOLD USAGE: run_enumerationscans.sh <options>                         $ENDC|"
    echo "|                                                                  |"
    echo -e "|$BOLD OPTIONS: $ENDC                                                        |"
    echo "|         -c  Client name                                          |"
    echo "|         -t  Target IP/range <192.168.11.200-254>                 |"
    echo "|         -S  Scans to run against target, options:                |"
    echo "|               dns = DNS Discovery and zone transfer              |"
    echo "|               low = Low hanging fruit NMAP scan                  |"
    echo "|               smb = Samba/Netbios scans                          |"
    echo "|               snmp = SNMP snooping and attacks                   |"
    echo "|               smtp = Attempts SMTP user enumeration              |"
    echo "|               nmap = FULL TCP & UDP NMAP Sweep (be patient)      |"
    echo "|                                                                  |"
    echo "|               Can be passed as multiple -S flags, or using the   |"
    echo "|               format -S{dns,low,smb,snmp,smtp,nmap}              |"
    echo -e "|         -s  Source IP address                                    |"
    echo -e "|$DIM         -C  (optional) Clean up previous scans                   $ENDC|"
    echo "--------------------------------------------------------------------"
    echo ""
else

    if (( ${#SCANS} > 0 ))
    then
        for scan in "${SCANS[@]}"
        do
            if [ $scan = "dns" ] || [ $scan = "DNS" ]
            then
                RUNDNS=TRUE
            fi
                        if [ $scan = "low" ] || [ $scan = "LOW" ]
                        then
                                RUNLOW=TRUE
                        fi
                        if [ $scan = "smb" ] || [ $scan = "SMB" ]
                        then
                                RUNSMB=TRUE
                        fi
                        if [ $scan = "snmp" ] || [ $scan = "SNMP" ]
                        then
                                RUNSNMP=TRUE
                        fi
                        if [ $scan = "smtp" ] || [ $scan = "SMTP" ]
                        then
                                RUNSMTP=TRUE
                        fi
                        if [ $scan = "nmap" ] || [ $scan = "NMAP" ]
                        then
                                RUNNMAP=TRUE
                        fi
        done
    fi


    ######################
    #  ~~~ Scanning ~~~  #
    ######################

    echo $(date)

    # Setup Folder Structure
    echo "[*] Setting up pen-test environment"
    mkdir -p ~/assessments/"$CLIENT"/"$TARGET"
    cd "$CLIENT"/"$TARGET"

    # Scan for live hosts
    echo $SOURCE > SOURCE
    echo "[+] Scanning network for alive hosts...."
    nmap -S $SOURCE -sn -n -oA nmap_hosts_alive $TARGET >/dev/null 2>&1
    cat nmap_hosts_alive.gnmap | grep "Status: Up" | cut -d" " -f2 > ip_addresses_alive.txt

    # Count total hosts
    HOSTCOUNT=$(wc -l ip_addresses_alive.txt)

    # DNS Discovery
    if [ $RUNDNS = "TRUE" ]
    then
        cd ~/assessments/"$CLIENT"/"$TARGET"
        mkdir dns_scans    
    
        echo "[*] Attempting to find name servers (port 53)......"
        nmap -S $SOURCE -n -p 53 $TARGET -oA dns_scans/nmap_possible_dns >/dev/null 2>&1
        echo "[+] Possible domain names:"
        for host in $(cat dns_scans/nmap_possible_dns.gnmap | grep "open" | cut -d" " -f2)
        do 
            nslookup $host $host | grep "name = "
        done
    
        # Attempt zone transfer
        echo -e "\e[1;33mWould you like to attempt a zone transfer and DNS brute force? Note: Brute force scan will be spawned silently [Y/N] \e[00m"
        read ZONE
        if [ $ZONE = "Y" ] || [ $ZONE = "y" ]
        then
            echo "[*] Please enter zone/domain to transfer:"
            read ZONE
            echo $ZONE > ZONE
            echo "[+] Attempting zone transfer - $ZONE"
            #for host in $(head -n1 dns_scans/nmap_possible_dns.gnmap | grep "open" | cut -d" " -f2); do host -l $ZONE $host >> dns_scans/"$ZONE"_attempted_zone_transfer.txt; done
            # Scan zone for vulnerabilities and attempt a transfer using dnsrecon
            dnsrecon -a -d $ZONE -n $host --xml dns_scans/"$ZONE"_axfr.xml --csv dns_scans/"$ZONE"_axfr.csv

            # Run fierce in the background to brute force additional hostnames
            fierce -threads 8 -dns $ZONE -file dns_scans/"$ZONE"_fierce_brute_dns_lookup.txt >/dev/null 2>&1 &
        fi
        # Backup just in case the transfer doesn't work, or isn't selected - host names are important after all!
        for host in $(cat ip_addresses_alive.txt); do for ns in $(cat dns_scans/nmap_possible_dns.gnmap | grep "open" | cut -d" " -f2); do host $host $ns | grep "pointer" | cut -d" " -f1,5 >> tmp.hostnames; done; done; cat tmp.hostnames | sort -u > dns_scans/"$ZONE"_hostnames; rm tmp.hostnames
    fi

    if [ $RUNLOW = "TRUE" ]
    then
        # Low hanging fruit 
        cd ~/assessments/"$CLIENT"/"$TARGET"
        mkdir low_hanging_fruit

        echo "[*] Looking for low hanging fruit (anon-ftp,default accounts,backdoors) to help get started while other scans run...."
        cat ip_addresses_alive.txt | parallel -j2 "nmap -vv -T4 -F -O -Pn -sV --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,http-default-accounts {} -oA low_hanging_fruit/low_hanging_fruit_{} && echo '[+]     Completed NMAP Low Hanging Fruit: {}'" >/dev/null 2>&1
    fi

    if [ $RUNSMB = "TRUE" ]
    then    
        cd ~/assessments/"$CLIENT"/"$TARGET"
        mkdir nbt_smb_scans

        # NBT/NetBIOS Scan
        echo "[*] Running NetBIOS/NBT Scans"
        nbtscan -v -s, -f ip_addresses_alive.txt > nbt_smb_scans/nbtscan_netbios.txt

        # Run parallel enum4linux processes
        echo "[*] Running Samba/SMB Scans"
        echo "[+]   Running NMAP --script=smb-check-vulns --script=smb-enum-shares"
        cat nbt_smb_scans/nbtscan_netbios.txt | cut -f1 -d"," | sort -u | parallel -j6 "echo '[+]     Completed Host: {}' && nmap -S $SOURCE -vv -p 135,139,445 --script=smb-check-vulns --script-args=unsafe=1 {} -oA nbt_smb_scans/"{}"_nmap_smbvulns >/dev/null 2>&1"

        echo "[+]   Backgrounding enum4linux"
        cat nbt_smb_scans/nbtscan_netbios.txt | cut -f1 -d"," | sort -u | parallel -j4 "echo '[+]     Backgrounding enum4linux Host: {}' && /usr/share/enum4linux/enum4linux.pl -v -a {} > nbt_smb_scans/{}_enum4linux.txt &"
    fi

    if [ $RUNSNMP = "TRUE" ]
    then
        # SNMP
        echo "[*] Running SNMP Scans"
        cd ~/assessments/"$CLIENT"/"$TARGET"
        mkdir snmp_scans
        echo "[+]   Running onesixtyone"
        onesixtyone -c ~/wordlists/snmp-community-strings.txt -i ip_addresses_alive.txt -o snmp_scans/snmp_strings_found.txt

        cat snmp_scans/snmp_strings_found.txt | sed -e 's/\[//g' | sed -e 's/\]//g' > snmp_scans/snmp_strings_found_clean.txt
        echo "[+]   Running snmpcheck"
        while read -r -a array; do (snmpcheck -c ${array[1]} -t ${array[0]} > snmp_scans/${array[0]}_snmpcheck.txt &); done < snmp_scans/snmp_strings_found_clean.txt
    
        sleep 60
    fi

    if [ $RUNSMTP = "TRUE"]
    then
        # SMTP
           echo "[*] Running SMTP enumeration"
           cd ~/assessments/"$CLIENT"/"$TARGET"
           mkdir smtp_scans
        for host in $(cat low_hanging_fruit.gnmap | grep "25/open/tcp//smtp///" | cut -d" " -f2)
            do
                    patator smtp_vrfy host=$host user=FILE0 0=/usr/share/wordlists/userlist.txt -x ignore:fgrep='User unknown' -x ignore,reset,retry:code=421 > smtp_scans/"$host"_smtpvrfy.txt
            sleep 3
            done
    fi

    if [ $RUNNMAP = "TRUE" ]
    then
        cd ~/assessments/"$CLIENT"/"$TARGET"
        mkdir unicornscans
        mkdir nmapscans

        # Full TCP & UDP Scan
        echo "[*] Unicornscan to identify open ports..."
    
        # Loop over IP addresses and pass them to 4 parallel Unicornscan processes
        cat ip_addresses_alive.txt | parallel -j3 "unicornscan -I -v -mT -R1 -r 350 {} -l unicornscans/{}-tcp.txt && echo '[+]     Completed TCP Host: {}'"
        cat ip_addresses_alive.txt | parallel -j3 "unicornscan -I -v -mU -R1 -r 350 {} -l unicornscans/{}-udp.txt && echo '[+]     Completed UDP Host: {}'"

        for host in $(cat ip_addresses_alive.txt)
        do
            tcpports=$(cat unicornscans/$host-tcp.txt | grep "from" | cut -d"[" -f2 | cut -d"]" -f1 | sed 's/ //g' | tr '\n' ',')
            udpports=$(cat unicornscans/$host-udp.txt | grep "from" | cut -d"[" -f2 | cut -d"]" -f1 | sed 's/ //g' | tr '\n' ',')
            if [[ ! -z $tcpports ]]
            then
                echo "[*]     NMAP TCP Scan against ports: $tcpports"
                nmap -S $SOURCE -vv -sS -n -T4 -A --script=vuln -Pn $host -p $tcpports -oA nmapscans/"$host"_fulltcpscan >/dev/null 2>&1
            fi
                    if [[ ! -z $udpports ]]
                    then
                echo "[*]     NMAP Scan against ports: $udpports"
                        nmap -S $SOURCE -vv -sU -n -T4 -A -Pn $host -p $udpports -oA nmapscans/"$host"_fulltcpscan >/dev/null 2>&1
                    fi
            done
    fi

    echo -e "$BOLD[*] ALL SCANS COMPLETE !!$ENDC"
    echo ""
    echo $(date)
    echo ""
    echo -e "** Importing into PBNJ **"
    cd ~/assessments/"$CLIENT"/"$TARGET"
    for file in $(ls nmapscans/*full*.xml | cut -d"/" -f1 | sort -bt . -k 1,1n -k 2,2n -k 3,3n -k 4,4n | uniq)
    do
        scanpbnj -x $file
    done
    echo ""
    echo -e " \e[1;33mPlease review all FILES AND FOLDERS that have been created to help identify potential \"easy\" targets\e[00m"
fi

exit 1  
