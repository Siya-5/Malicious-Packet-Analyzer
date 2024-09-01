import sys
import os
import csv
from collections import Counter
import pprint
from ip2geotools.databases.noncommercial import DbIpCity


##### defining variables #####
baseFileName = sys.argv[1];

##### function to process IPO addresses #####
def processIP(input, output):
        with open(f"/var/www/html/{input}", 'r') as resFile:
                csv2dict = csv.DictReader(resFile)
                ipList = list(csv2dict)
        ipDict = {}
        for item in ipList:
                key = item['number']
                val = item['ip']
                ipDict[key] = val
        #print(ipDict)
        ipCount = dict(Counter(ipDict.values()))
        sorted_ipCount = sorted(ipCount.items(), key=lambda x:x[1], reverse=True)

        counter = 0;
        other_sum = 0;
        ipCountToCSV = "ip,frequency"

        for item in sorted_ipCount:
                if(counter < 5):
                        ipCountToCSV += f"\n{item[0][1:]},{item[1]}"
                else:
                        other_sum += item[1]
                counter += 1;

        ipCountToCSV += f"\nother,{other_sum}"

        with open(f"/var/www/html/{output}", 'w') as outFile:
                outFile.write(f"{ipCountToCSV}\n");



processIP(f"results/{baseFileName}_rawSrcIP.csv", f"results/{baseFileName}_processedSrcIPs.csv")
processIP(f"results/{baseFileName}_rawDestIP.csv", f"results/{baseFileName}_processedDestIPs.csv")


##### process protocols #####
with open(f"/var/www/html/results/{baseFileName}_rawProtocol.csv", 'r') as resFile:
        csv2dict = csv.DictReader(resFile)
        protList = list(csv2dict)

protDict = {}
for item in protList:
        key = item['number']
        val = item['protocol']
        protDict[key] = val

protCount = dict(Counter(protDict.values()))
sorted_protCount = sorted(protCount.items(), key=lambda x:x[1], reverse=True)

counter = 0;
other_sum = 0;
protCountToCSV = "protocol,frequency"

for item in sorted_protCount:
        if(counter < 5):
                protCountToCSV += f"\n{item[0][1:]},{item[1]}"
        else:
                other_sum += item[1]
        counter += 1;

protCountToCSV += f"\nother,{other_sum}"

with open(f"/var/www/html/results/{baseFileName}_processedProtocol.csv", 'w') as outFile:
        outFile.write(f"{protCountToCSV}\n");

##### malicious port count #####
with open(f"/var/www/html/results/{baseFileName}_rawMalPorts.csv", 'r') as resFile:
        csv2dict = csv.DictReader(resFile)
        malPortList = list(csv2dict)

malPortDict = {}
for item in malPortList:
        ip = item['ip']
        port = item['port'][1:]
        if port in malPortDict:
                malPortDict[port] = malPortDict[port]+1
        else:
                malPortDict[port] = 1
#print(malPortDict)


malPortCSVData = "port,frequency"
for item in malPortDict:
        malPortCSVData += f"\n{item},{malPortDict[item]}"

with open(f"/var/www/html/results/{baseFileName}_processedMalPorts.csv", 'w') as outFile:
        outFile.write(f"{malPortCSVData}\n");



##### geolocate source IP addresses #####
def getLocation(ip):
        res = DbIpCity.get(ip, api_key="free");
        return f"{res.longitude},{res.latitude}"
def getLabel(ip):
        res = DbIpCity.get(ip, api_key="free");
        return f"{res.country}: {ip}"


with open(f"/var/www/html/results/{baseFileName}_processedSrcIPs.csv", 'r') as resFile:
        csv2dict = csv.DictReader(resFile)
        rawSrcList = list(csv2dict)
with open(f"/var/www/html/results/{baseFileName}_processedDestIPs.csv", 'r') as resFile:
        csv2dict = csv.DictReader(resFile)
        rawDestList = list(csv2dict)

rawSrcList.pop()
rawDestList.pop()
locList = rawSrcList + rawDestList

geoLocToCSV = "lon,lat,data,label"
for item in locList:
        key = item['ip']
        if (key[0:3] == "10." or key[0:8] == "192.168." or not(key[0].isnumeric())):
                pass
        else:
                val = getLocation(key)
                lab = getLabel(key)
                geoLocToCSV += f"\n{val},1,{lab}"

#print(geoLocationToCSV)
with open(f"/var/www/html/results/{baseFileName}_processedGeo.csv", 'w') as outFile:
        outFile.write(f"{geoLocToCSV}\n");
