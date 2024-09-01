import dpkt
import datetime
from dpkt.utils import mac_to_str, inet_to_str
import urllib.request
import re
import numpy as np
import sys
import os

fileName = sys.argv[1];
baseName = sys.argv[2];


maliciousPortNumbers = [31, 1170, 1234, 1243, 1981, 2001, 2023, 2140, 2989, 3024, 3150, 3700, 4950, 6346, 6400, 6667, 6670, 12345, 49209]
ipAd = ""
malicious_strings = ["'or1=1--", b"'UNIONSELECTNULL--", "1';DROPTABLEusers;--", ";ls", "&&rm-rf/", "|cat/etc/passwd", "<script>alert('XSS')</script>", "<imgsrc=\"javascript:alert('XSS')\">", "<iframesrc=\"malicious-website.com\"></iframe>", "eval(base64_decode(\"...\"))>
failedAuth = 0
malCount = 0                                                                                    # can delete this... its there for seeing stuff
malDict = {"Suspicious IP": 0, "Suspicious Port": 0, "Suspicious Flag": 0, "Suspicious Authentication": 0, "Suspicious Payload": 0}                # can delete this... its there for seeing stuff

for line in urllib.request.urlopen("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"):
    ipAd += line.decode('utf-8')
MalIpAdList = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ipAd)


#########start of new code
def is_suspicious_packet(pkt):
    global failedAuth, malCount, malDict #, counter #, data_string
    if isinstance(pkt.data, dpkt.tcp.TCP):
        if inet_to_str(pkt.src) in MalIpAdList:
            malCount += 1 ##//
            malDict["Suspicious IP"] = malDict["Suspicious IP"]+1 ##//
            return True
        if pkt.data.sport in maliciousPortNumbers:
            malCount += 1 ##//
            malDict["Suspicious Port"] = malDict["Suspicious Port"]+1 ##//
            return True
    try:
        dstr = pkt.data.data.decode('utf-8')
        for s in malicious_strings:
            if str(s) in dstr:
                malCount += 1 ##//
                malDict["Suspicious Payload"] = malDict["Suspicious Payload"]+1 ##//
                return True
    except (UnicodeDecodeError, AttributeError) as e:
        pass
    if isinstance(pkt, dpkt.http.Request):
        if pkt.tcp.flags == 0x02:
            malCount += 1 ##//
            malDict["Suspicious Flag"] = malDict["Suspicious Flag"]+1 ##//
            return True
        if b'login' in pkt.lower() and b'failed' in pkt.lower():
            failedAuth += 1
            if failedAuth > 5:
                malCount += 1 ##//
                malDict["Suspicious Authentication"] = malDict["Suspicious Authentication"]+1 ##//
                return True
        else:
            failedAuth = 0
    return (
        isinstance(pkt, dpkt.icmp6.ICMP6) or
        isinstance(pkt, dpkt.igmp.IGMP) or
        isinstance(pkt, dpkt.sctp.SCTP) or
        isinstance(pkt, dpkt.gre.GRE) or
        isinstance(pkt, dpkt.pim.PIM)
    )


### this code works
def processMalPackets(pcap):
    counter = 0
    packetInfo = "No,Time,Source,Destination,Protocol,Length,Info,Malicious"
    malPacketNumbers = "Packet numbers of potentially malicious packets:\t\n\t";
    malCounter = 0

    for timestamp, buf in pcap:
        counter += 1
        eth = dpkt.ethernet.Ethernet(buf)

        if not isinstance(eth.data, dpkt.ip.IP):
            packetInfo += (f"\n{counter},{timestamp},0.0.0.0,0.0.0.0,unknown,{len(buf)},unknown,false");
            continue

        ip = eth.data
        try:
            data_bytes = ip.data.data
            data_string = data_bytes.decode('utf-8')
            if not data_string.isascii():
                data_string = "unknown"
            data_string = data_string.replace(",", "")
            #data_string = data_string.replaceAll(' ', '');
            #data_string = re.sub(r'[^\x00-\x7f]',r'', your-non-ascii-string)
            #data_string = data_string.encode("ascii", errors="ignore").decode() #### new line
        except (UnicodeDecodeError, AttributeError) as e:
            data_string = "unknown"
        data_string = data_string.replace(' ', '').replace('\n', ' ').replace('\r', '').replace('\t', '');
        isMal = is_suspicious_packet(ip);
        packetInfo += (f"\n{counter},{timestamp},{inet_to_str(ip.src)},{inet_to_str(ip.dst)},{ip.get_proto(ip.p).__name__},{len(buf)},{data_string},{isMal}");
        #if isMal:
        #    malPacketNumbers = malPacketNumbers + f"{counter}, "
        if isMal:
            malCounter += 1
            malPacketNumbers += f"{counter}, "
            if malCounter % 10 == 0:
                malPacketNumbers += "\n\t"  # Start a new line with a tab after every 10 packets
    #print(packetInfo);
    #print(malDict)
    if malPacketNumbers.endswith("\n\t"):
        malPacketNumbers = malPacketNumbers[:-2]

    allMalPackets = 0
    reasons = ""
    for category, value in malDict.items():
        if value != 0:
            allMalPackets += value
            reasons += f"{category}: {value} packets\n\t"
    suspiciousStuff = f"{allMalPackets} potentially malicious packets have been detected due to:\n{reasons}\n"
    suspiciousStuff += malPacketNumbers[:-2]
    with open(f"./results/{baseName}_suspiciousPackets.txt", 'w') as rawFile:
        rawFile.write(f"{suspiciousStuff}\n");
    with open(f"./results/{baseName}_packetInfo.csv", 'w') as rawFile:
        rawFile.write(f"{packetInfo}\n");

#def test():
#    with open(fileName, 'rb') as f:
#        pcap = dpkt.pcap.Reader(f)
#        processMalPackets(pcap)
#
#if __name__ == '__main__':
#    test()



#######end of new code
def processPackets(pcap):
    counter = 0
    srcIPAddr = "number,ip"
    destIPAddr = "number,ip"
    protocols = "number,protocol"

    for timestamp, buf in pcap:
        counter += 1
        eth = dpkt.ethernet.Ethernet(buf)


        if not isinstance(eth.data, dpkt.ip.IP):
            srcIPAddr += (f"\n{counter}, no IP address");
            destIPAddr += (f"\n{counter}, no IP address");
            protocols += (f"\n{counter}, Unknown protocol");
            continue

        ip = eth.data
        srcIPAddr += (f"\n{counter}, {inet_to_str(ip.src)}");
        destIPAddr += (f"\n{counter}, {inet_to_str(ip.dst)}");
        protocols += (f"\n{counter}, {ip.get_proto(ip.p).__name__}");

    with open(f"./results/{baseName}_rawSrcIP.csv", 'w') as rawResultsFile:
        rawResultsFile.write(f"{srcIPAddr}\n");
    with open(f"./results/{baseName}_rawDestIP.csv", 'w') as rawResultsFile:
        rawResultsFile.write(f"{destIPAddr}\n");
    with open(f"./results/{baseName}_rawProtocol.csv", 'w') as rawFile:
        rawFile.write(f"{protocols}\n");

def processTimLen(pcap,c):
    timeLen = "time,length"
    digits = len(str(c))
    number = 10**(digits-2)
    count = 0;
    startTime = 0

    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        startTime = timestamp
        break
    for timestamp, buf in pcap:
        if(count%number==0):
            try:
                timeLen += (f"\n{round((timestamp-startTime), 6)}, {len(buf)}"); # FIX THE SECOND AND TEST THIS FIRST
            except Exception as e:
                timeLen += ("time, len");
        count += 1
    with open(f"./results/{baseName}_timLen.csv", 'w') as rawFile:
        rawFile.write(f"{timeLen}\n");

def processMalPorts(pcap):
    maliciousPortNumbers = [31, 1170, 1234, 1243, 1981, 2001, 2023, 2140, 2989, 3024, 3150, 3700, 4950, 6346, 6400, 6667, 6670, 12345, 12346, 16660, 18753, 20034, 20432, 20433, 27374, 27444, 27665, 30100, 31335, 31337, 33270, 33567, 33568, 40421, 60008, 65000]
    malPortList = []
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        try:
            ip = eth.data
            ipA = inet_to_str(ip.src)
        except Exception as e:
            ipA = "No IP"
        try:
            malMiniDict = {'ip': ipA, 'port': ip.data.sport}
        except Exception as e:
            malMiniDict = {'ip': ipA, 'port': "Unknown Port"}
        malPortList.append(malMiniDict.copy())


    malPorts = "ip,port"
    for item in malPortList:
        ip = item['ip']
        if(item['port'] != "Unknown Port"):
            port = int(item['port'])
            for malP in maliciousPortNumbers:
                if (port == malP):
                    malPorts += (f"\n{ip}, {port}");
    #print(malPorts)
    with open(f"./results/{baseName}_rawMalPorts.csv", 'w') as rawResultsFile:
        rawResultsFile.write(f"{malPorts}\n");

    #nextStatement = f'python3 dataAnalyze.py {baseName}';
    #os.system(nextStatement);



def test():
    c = ""
    with open(fileName, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        c = processPackets(pcap)
    with open(fileName, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        processTimLen(pcap, c)
    with open(fileName, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        processMalPorts(pcap)
    with open(fileName, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        processMalPackets(pcap)
    aiStatement = f'python3 ai.py {baseName} results/{baseName}_packetInfo.csv';
    # sudo python3 ai.py bruteforce results/bruteforce_packetInfo.csv
    os.system(aiStatement);

    nextStatement = f'python3 dataAnalyze.py {baseName}';
    os.system(nextStatement);


if __name__ == '__main__':
    test()
