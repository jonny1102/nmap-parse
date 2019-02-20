#!/usr/bin/python3
#
# Script to help extract useful information from one or more nmap files
# Also provides interactive prompt with filtering
#
# Created By: Jonathon Orr
# Email: scripts@jonathonorr.co.uk

from __future__ import print_function
import os, glob, sys, re, subprocess
import xml.etree.ElementTree as ET
import random
from optparse import OptionParser
from subprocess import Popen,PIPE
from IPy import IP
from tabulate import tabulate
from bs4 import BeautifulSoup
from cmd2 import Cmd, with_category, argparse_completer

VERSION = "0.1"
RELEASE_DATE = "19/02/2019"

PROTOCOLS = ['tcp','udp']

OPT_SERVICE_FILTER = "service_filter"
OPT_PORT_FILTER = "port_filter"
OPT_HOST_FILTER = "host_filter"
OPT_VERBOSE = "verbose"
OPT_RAW = "raw"

PORT_OPT_DEFAULT = "default"
PORT_OPT_TCP = "tcp"
PORT_OPT_UDP = "udp"
PORT_OPT_COMBINED = "combined"
PORT_OPTIONS = [PORT_OPT_DEFAULT, PORT_OPT_TCP, PORT_OPT_UDP, PORT_OPT_COMBINED]

printHumanFriendlyText = True
filesFailedToImport = []
filesImported = []
mAllHosts = {}
services = []

######################
# services structure #
######################
# services = [
#   {
#     'name' : 'SMTP',
#     'hosts' : [ {
#                   'ip' : 127.0.0.1',
#                   'ports' : [123, 161]
#                 },{
#                   'ip' : 127.0.0.2',
#                   'ports' : [123, 161]
#                 }],
#     'ports' : [123, 124, 125],
#   }
# ]

def parseNmapXmlFiles(nmapXmlFilenames):
    # Store list of successfully loaded files and failed to load files
    global filesFailedToImport, filesImported
    count = 0
    colourSupport = supportsColour()
    # Loop through all nmap xml files
    iMaxStatusLen = 0
    for nmapXmlFilename in nmapXmlFilenames:
        count += 1
        # Output stats
        sStatus = "Loading [%s of %s] %s" % (str(count),str(len(nmapXmlFilenames)),nmapXmlFilename)
        if(colourSupport):
            sStatus = "\033[1;30m" + sStatus + "\033[1;m"
        # Pad short lines to overwrite previous text
        if(len(sStatus) < iMaxStatusLen):
            sStatus += " " * (iMaxStatusLen - len(sStatus))
        else:
            iMaxStatusLen = len(sStatus)
        if(count < len(nmapXmlFilenames)):
            hprint(sStatus, end='\r')
        else:
            hprint(sStatus)

        # Try to parse xml and record any failures
        nmap_xml = ""
        try:
            nmap_xml = ET.parse(nmapXmlFilename)
        except:
            filesFailedToImport.append(nmapXmlFilename)
            continue
        # Record that file successfully loaded
        filesImported.append(nmapXmlFilename)
        # Find all hosts within xml file
        for xHost in nmap_xml.findall('.//host'):
            # Get IP address
            ip = xHost.find("address[@addrtype='ipv4']").get('addr')
            # Add host to dictionary
            if ip not in mAllHosts:
                mAllHosts[ip] = NmapHost(ip)
            curHost = mAllHosts[ip]

            # Attempt to get hostname
            try:
                curHost.hostname = xHost.find('.//hostname').get('name') # hostname will be in nmap xml if PTR (reverse lookup) record present
            except:
                curHost.hostname = ip
            
            # Store host up status 
            curHost.alive = (xHost.find("status").get('state') == 'up')

            # Parse ports
            for xPort in xHost.findall('.//port'):
                # Only parse open ports
                if xPort.find('.//state').get('state') == 'open':
                    curPortId = int(xPort.get('portid'))
                    curProtocol = xPort.get('protocol')
                    curService = ''
                    if(None != xPort.find('.//service')):
                        curService = xPort.find('.//service').get('name')                        
                    # Store port details
                    curHost.addPort(curProtocol, curPortId, curService)
                    # Store service details in global variable
                    addService(curService, ip, curPortId)
    
    # Output successfully loaded and any failed files
    printImportSummary(False)

def printImportSummary(detailed=True):
    if(detailed):
        for file in filesImported:
            sprint("Successfully loaded " + file)
    sprint("Successfully loaded " + str(len(filesImported)) + " files")
    if len(filesFailedToImport) > 0:
        eprint("The following files failed to parse:")
        for file in filesFailedToImport:
            eprint("\t" + file)

# Add specified service to global variable
def addService(svcName, ip, port):
    curService = getService(svcName)
    curServiceHost = getServiceHost(curService, ip)
    if port not in curServiceHost['ports']:
        curServiceHost['ports'].append(port)
    if port not in curService['ports']:
        curService['ports'].append(port)

# Get host or create if necessary
def getServiceHost(service, ip):
    for host in service['hosts']:
        if host['ip'] == ip:
            return host
    
    service['hosts'].append({
            'ip' : ip,
            'ports' : []
        })
    return getServiceHost(service, ip)

# Get service or create if necessary
def getService(svcName):
    for service in services:
        if service['name'] == svcName:
            return service
    
    services.append({
            'name' : svcName,
            'hosts' : [],
            'ports' : []
        })
    return getService(svcName)

# Print service list
def printServiceList(options):
    hprint('\nService List\n------------')
    first = True
    for service in services:
        if(options.verbose):
            if first:
                first = False
            else:
                print("")
        print(service['name'] + " " + str(sorted(service['ports'])))
        if options.verbose:
            for host in service['hosts']:
                print('  ' + host['ip'] + " " + str(sorted(host['ports'])))

# Print hosts
def printHosts():
    count = 0
    hprint('\nIP and port list\n----------------\n')
    for ip in sortIpList(mAllHosts):
        host = mAllHosts[ip]
        uniquePorts = host.getUniquePortIds()
        if(len(uniquePorts) > 0):
            count += 1
            if ip == host.hostname:
                print("%s %s" % (ip,uniquePorts))
            else:
                print("%s[%s] %s" % (ip,host.hostname,uniquePorts))      
    return count

def printUniquePorts(option=PORT_OPT_DEFAULT):
    tcpPorts = set()
    udpPorts = set()
    allPorts = set()
    for ip in mAllHosts.keys():
        host = mAllHosts[ip]
        tcpPorts = tcpPorts.union(host.getUniquePortIds('tcp'))
        udpPorts = udpPorts.union(host.getUniquePortIds('udp'))
    allPorts = tcpPorts.union(udpPorts)

    hprint('\nUnique open port list\n---------------------')
    if option == PORT_OPT_DEFAULT:
        print("TCP:\n----\n" + re.sub('[\[\] ]','',str(sorted(tcpPorts))))
        print("\nUDP:\n----\n" + re.sub('[\[\] ]','',str(sorted(udpPorts))))
        print("\nCombined:\n---------\n" + re.sub('[\[\] ]','',str(sorted(allPorts))))
    elif option == PORT_OPT_TCP:
        print(re.sub('[\[\] ]','',str(sorted(tcpPorts))))
    elif option == PORT_OPT_UDP:
        print(re.sub('[\[\] ]','',str(sorted(udpPorts))))
    elif option == PORT_OPT_COMBINED:
        print(re.sub('[\[\] ]','',str(sorted(allPorts))))

# Execute commands
def executeCommands(cmd, filters={}):
    hprint('\nRunning Commands\n----------------\n')
    for ip in getHostsThatMatchFilters(filters):
        host = mAllHosts[ip]
        if len(host.ports) > 0:
            executeCommand(cmd, ip)

# Execute Single Command
def executeCommand(cmd, ip):
    curCommand = cmd + " " + ip
    hprint("Running command: " + cmd)
    process = Popen(curCommand, shell=True, stdout=PIPE)
    output = process.stdout.read()
    hprint("Finished running command: " + cmd)
    print('OUTPUT: ')
    if output == '':
        print('<none>\n')
    else:
        print(output)

def printMatchedIps(includePorts = True, filters={}):
    matchedHosts = []

    colourSupported = supportsColour()
    
    filterByHost = False 
    filterByService = False 
    filterByPort = False 

    hostFilter = [] 
    serviceFilter = [] 
    portFilter = []

    if OPT_HOST_FILTER in filters and len(filters[OPT_HOST_FILTER]) > 0:
        filterByHost = True
        hostFilter = filters[OPT_HOST_FILTER]

    if OPT_SERVICE_FILTER in filters and len(filters[OPT_SERVICE_FILTER]) > 0:
        filterByService = True
        serviceFilter = filters[OPT_SERVICE_FILTER]

    if OPT_PORT_FILTER in filters and len(filters[OPT_PORT_FILTER]) > 0:
        filterByPort = True
        portFilter = filters[OPT_PORT_FILTER]

    if filterByHost or filterByService or filterByHost:
        hprint("\nOutput filtered by:")
        if filterByHost:
            hprint("  Host filter: %s" % (hostFilter))
        if filterByService:
            hprint("  Service filter: %s" % (serviceFilter))
        if filterByPort:
            hprint("  Port filter: %s" % (portFilter))

    header('Matched IP list')

    # Get all hosts that are up and matched filters
    for ip in getHostsThatMatchFilters(filters=filters):
        host = mAllHosts[ip]
        if (not host.alive) or (filterByHost and ip not in hostFilter):
            continue

        curHostOutput = [ip, '']
        portsByProto = {}
        matched = False
        # Check ports
        for protocol in PROTOCOLS: 
            fullPortsString = ''
            for port in [port for port in host.ports if port.protocol == protocol]:
                tmpPortString = str(port.portId) 
                portMatched = True
                if filterByPort and (portFilter == [] or port.portId not in portFilter):
                    portMatched = False
                if filterByService and (serviceFilter == [] or port.service not in serviceFilter):
                    portMatched = False
                if(portMatched):
                    matched = True
                    if colourSupported:
                        tmpPortString = "\033[1;32m" + tmpPortString + "\033[1;m"
                if len(fullPortsString) > 0:
                    fullPortsString += ","
                fullPortsString += tmpPortString
            curHostOutput[1] += "%s:[%s]  " % (protocol,fullPortsString)
        if matched:
            matchedHosts.append(curHostOutput)
    
    for host in matchedHosts:
        if includePorts:
            print(host[0] + "\t" + host[1])
        else:
            print(host[0])

def getHostsThatMatchFilters(filters={}):
    filterByHost = False 
    filterByService = False 
    filterByPort = False 

    hostFilter = [] 
    serviceFilter = [] 
    portFilter = []

    if OPT_HOST_FILTER in filters and len(filters[OPT_HOST_FILTER]) > 0:
        filterByHost = True
        hostFilter = filters[OPT_HOST_FILTER]

    if OPT_SERVICE_FILTER in filters and len(filters[OPT_SERVICE_FILTER]) > 0:
        filterByService = True
        serviceFilter = filters[OPT_SERVICE_FILTER]

    if OPT_PORT_FILTER in filters and len(filters[OPT_PORT_FILTER]) > 0:
        filterByPort = True
        portFilter = filters[OPT_PORT_FILTER]

    matchedHosts = []
    for ip in sortIpList(mAllHosts):
        host = mAllHosts[ip]
        if (not host.alive) or (filterByHost and ip not in hostFilter):
            continue

        matched = False
        # Check ports
        for protocol in PROTOCOLS: 
            for port in [port for port in host.ports if port.protocol == protocol]:
                matchedPort = True
                if filterByPort and (portFilter == [] or port.portId not in portFilter):
                    matchedPort = False
                if filterByService and (serviceFilter == [] or port.service not in serviceFilter):
                    matchedPort = False
                if matchedPort:
                    matched = True
        if matched:
            matchedHosts.append(ip)
    return matchedHosts

def printAliveIps():
    hprint('\nAlive IP list\n-------------')
    # Get all hosts that are up and matched filters
    tmpParsedHosts = [ip for ip in mAllHosts if mAllHosts[ip].alive]
    for ip in sortIpList(tmpParsedHosts):
        print("%s" % (ip))

def enterInteractiveShell():
    prompt = InteractivePrompt()
    prompt.cmdloop()

# Colour output green (successprint)
def sprint(*args, **kwargs):
    colouredPrint("\033[1;32m", args, kwargs)

# Print to stderr
def eprint(*args, **kwargs):
    colouredPrint("\033[1;31m", args, kwargs)

# Print text with specified colour code
def colouredPrint(colour, args, kwargs):
    if(not supportsColour()):
        print(args, kwargs)
        return

    colouredArgs = []
    for arg in args:
        if arg == None or not isinstance(arg, str):
            colouredArgs.append('')
            continue
        colouredArgs.append(colour + arg + "\033[1;m")
    print(*colouredArgs, file=sys.stderr, **kwargs)

# Print only if raw option hasnt been set
def hprint(*args, **kwargs):
    global printHumanFriendlyText
    if(printHumanFriendlyText):
        print(*args, **kwargs)
        
# Order array of IPs
def sortIpList(ip_list):
    ipl = [(IP(ip).int(), ip) for ip in ip_list]
    ipl.sort()
    return [ip[1] for ip in ipl]

def header(text):
    print("\n" + text)
    print('-' * len(text))

# Print list to console and save to optional filename
def printList(list, filename=''):
    try:
        fhOutput = None
        if(len(filename) > 0):
            fhOutput = open(filename, 'w')
        for item in list:
            if(fhOutput):
                fhOutput.write(item + "\n")
            else:
                print(item)
        if(fhOutput):
            print("Output saved to " + filename)
            fhOutput.close()

    except:
        eprint("Failed to save output to file: " + filename)

def combineFiles(filename):
    # create the file structure
    xNmapParse = ET.Element('nmapparse')
    for ip in mAllHosts:
        curHost = mAllHosts[ip]
        # Create host element
        xHost = ET.SubElement(xNmapParse, "host")
        # Create status element
        xStatus = ET.SubElement(xHost, "status")
        xStatus.set("state", "up" if curHost.alive else "down")
        # Create address element
        xAddress = ET.SubElement(xHost, "address")
        xAddress.set("addr", curHost.ip)
        xAddress.set("addrtype", "ipv4")
        # Create hostname element
        xHostnames = ET.SubElement(xHost, "hostnames")
        if(curHost.hostname != ip):
            xHostname = ET.SubElement(xHostnames, "hostname")
            xHostname.set("name", curHost.hostname)
        # Create ports element
        xPorts = ET.SubElement(xHost, "ports")
        for port in curHost.ports:
            xPort = ET.SubElement(xPorts, "port")
            xPort.set("portid", str(port.portId))
            xPort.set("protocol", port.protocol)
            xState = ET.SubElement(xPort, "state")
            xState.set("state", "open")
            xService = ET.SubElement(xPort, "service")
            xService.set("name", port.service)

    # create a new XML file with the results
    try:
        # Convert XML to string
        xmlData = ET.tostring(xNmapParse)
        # Format with indets
        bs = BeautifulSoup(xmlData, 'lxml-xml')
        xmlData = bs.prettify()
        # Write to file
        fhXml = open(filename, "w")
        fhXml.write(str(xmlData))
        fhXml.close()
        sprint("Combined file saved to: " + filename)
    except Exception as ex:
        eprint("Failed to combine files")
        eprint(str(ex))

# Source: https://github.com/django/django/blob/master/django/core/management/color.py
def supportsColour():
    """
    Return True if the running system's terminal supports color,
    and False otherwise.
    """
    plat = sys.platform
    supported_platform = plat != 'Pocket PC' and (plat != 'win32' or 'ANSICON' in os.environ)

    # isatty is not always implemented, #6223.
    is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    return supported_platform and is_a_tty

class NmapHost():
    def __init__(self, ip):
        self.ip = ip
        self.hostname = ''
        self.alive = False
        self.ports = []
        self.services = []

    def addPort(self, protocol, portId, service):
        self.addService(service)
        for port in self.ports:
            if port.portId == portId and port.protocol == protocol:
                # Port already exists, check if service is blank and add if possible
                if(len(port.service.strip()) == 0):
                    port.service = service
                return
        # Add port if function hasn't already exited
        self.ports.append(NmapPort(protocol, portId, service))

    def addService(self, service):
        if service not in self.services:
            self.services.append(service)

    def getUniquePortIds(self,protocol=''):
        allPortIds = [port.portId for port in self.ports if len(protocol) == 0 or port.protocol == protocol]
        uniquePortIds = set(allPortIds)
        return sorted(uniquePortIds)

class NmapPort():
    def __init__(self, protocol, port, service):
        self.protocol = protocol
        self.portId = port
        self.service = service

class InteractivePrompt(Cmd):  
    CMD_CAT_NMAP = "Nmap Commands"

    prompt = '\n\033[1;30mnp> \033[1;m'
    intro = """\nWelcome to nmap parse! Type ? to list commands
  \033[1;30mTip: You can send output to clipboard using the redirect '>' operator without a filename\033[1;m"""
    allow_cli_args = False

    userOptions = [
        [OPT_SERVICE_FILTER, "string", "", "Comma seperated list of services to show, e.g. \"http,ntp\""],
        [OPT_PORT_FILTER, "string", "", "Comma seperated list of ports to show, e.g. \"80,123\""],
        [OPT_HOST_FILTER, "string","", "Comma seperated list of hosts to show, e.g. \"127.0.0.1,127.0.0.2\""],
        [OPT_VERBOSE, "bool", "False", "Shows verbose service information"],
        [OPT_RAW, "bool", "False", "Shows raw output (no headings)"]
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.printRandomBanner()
        
    def printRandomBanner(self):
        banners = ["""                               .         .                                                      
    b.             8          ,8.       ,8.                   .8.          8 888888888o         
    888o.          8         ,888.     ,888.                 .888.         8 8888    `88.       
    Y88888o.       8        .`8888.   .`8888.               :88888.        8 8888     `88       
    .`Y888888o.    8       ,8.`8888. ,8.`8888.             . `88888.       8 8888     ,88       
    8o. `Y888888o. 8      ,8'8.`8888,8^8.`8888.           .8. `88888.      8 8888.   ,88'       
    8`Y8o. `Y88888o8     ,8' `8.`8888' `8.`8888.         .8`8. `88888.     8 888888888P'        
    8   `Y8o. `Y8888    ,8'   `8.`88'   `8.`8888.       .8' `8. `88888.    8 8888               
    8      `Y8o. `Y8   ,8'     `8.`'     `8.`8888.     .8'   `8. `88888.   8 8888               
    8         `Y8o.`  ,8'       `8        `8.`8888.   .888888888. `88888.  8 8888               
    8            `Yo ,8'         `         `8.`8888. .8'       `8. `88888. 8 8888               
                                                                                                
    8 888888888o      .8.          8 888888888o.     d888888o.   8 8888888888    
    8 8888    `88.   .888.         8 8888    `88.  .`8888:' `88. 8 8888          
    8 8888     `88  :88888.        8 8888     `88  8.`8888.   Y8 8 8888          
    8 8888     ,88 . `88888.       8 8888     ,88  `8.`8888.     8 8888          
    8 8888.   ,88'.8. `88888.      8 8888.   ,88'   `8.`8888.    8 888888888888  
    8 888888888P'.8`8. `88888.     8 888888888P'     `8.`8888.   8 8888          
    8 8888      .8' `8. `88888.    8 8888`8b          `8.`8888.  8 8888          
    8 8888     .8'   `8. `88888.   8 8888 `8b.    8b   `8.`8888. 8 8888          
    8 8888    .888888888. `88888.  8 8888   `8b.  `8b.  ;8.`8888 8 8888          
    8 8888   .8'       `8. `88888. 8 8888     `88. `Y8888P ,88P' 8 888888888888  
""","""
    888b    888                                        
    8888b   888                                        
    88888b  888                                        
    888Y88b 888 88888b.d88b.   8888b.  88888b.         
    888 Y88b888 888 "888 "88b     "88b 888 "88b        
    888  Y88888 888  888  888 .d888888 888  888        
    888   Y8888 888  888  888 888  888 888 d88P        
    888    Y888 888  888  888 "Y888888 88888P"         
                                       888             
                                       888             
                                       888             
          8888888b.                                    
          888   Y88b                                   
          888    888                                   
          888   d88P 8888b.  888d888 .d8888b   .d88b.  
          8888888P"     "88b 888P"   88K      d8P  Y8b 
          888       .d888888 888     "Y8888b. 88888888 
          888       888  888 888          X88 Y8b.     
          888       "Y888888 888      88888P'  "Y8888  
""","""
     /$$   /$$                                             
    | $$$ | $$                                             
    | $$$$| $$ /$$$$$$/$$$$   /$$$$$$   /$$$$$$            
    | $$ $$ $$| $$_  $$_  $$ |____  $$ /$$__  $$           
    | $$  $$$$| $$ \\ $$ \\ $$  /$$$$$$$| $$  \\ $$           
    | $$\\  $$$| $$ | $$ | $$ /$$__  $$| $$  | $$           
    | $$ \\  $$| $$ | $$ | $$|  $$$$$$$| $$$$$$$/           
    |__/  \\__/|__/ |__/ |__/ \\_______/| $$____/            
                                      | $$                 
                                      | $$                 
                                      |__/                 
           /$$$$$$$                                        
          | $$__  $$                                       
          | $$  \\ $$ /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$ 
          | $$$$$$$/|____  $$ /$$__  $$ /$$_____/ /$$__  $$
          | $$____/  /$$$$$$$| $$  \\__/|  $$$$$$ | $$$$$$$$
          | $$      /$$__  $$| $$       \\____  $$| $$_____/
          | $$     |  $$$$$$$| $$       /$$$$$$$/|  $$$$$$$
          |__/      \\_______/|__/      |_______/  \\_______/
"""]
        curBanner = random.choice(banners)
        maxLen = 0
        for line in curBanner.split('\n'):
            if len(line) > maxLen:
                maxLen = len(line)
        curBanner = ("-" * maxLen) + "\n\033[1;30m" + curBanner + "\033[0;m \n" + ("-" * maxLen)
        print(curBanner)
    
    def do_exit(self, inp):
        '''Exit the interactive prompt'''
        print("Bye")
        return True
 
    @with_category(CMD_CAT_NMAP)
    def do_list(self, inp):
        '''List all IP's matching filter'''
        tmpSearchFilter = self.getServiceFilter()
        tmpPortFilter = self.getPortFilter()
        printMatchedIps(includePorts=True, filters=self.getFilters())


    def complete_show(self, text, line, begidx, endidx):
        return ['options']

    @with_category(CMD_CAT_NMAP)
    def do_show(self, inp):
        '''"show options" will list current user options'''
        if(inp.lower() == 'options'):
            print()
            print(tabulate(self.userOptions, headers=['Setting', "Type", 'Value', 'Description'], tablefmt="github"))
            print()
        else:
            print('"show options" will list current user options')
 
    
    def complete_set(self, text, line, begidx, endidx):
        # remove 'set' from first array slot
        splitText = line.split()[1:]
        if(len(text.strip()) == 0):
            return [option[0] for option in self.userOptions]
        if(len(splitText) == 1):
            return [option[0] for option in self.userOptions if option[0].startswith(splitText[0].lower()) and not (option[0] == splitText[0].lower())]
        if(len(splitText) == 2):
            if splitText[0] == OPT_SERVICE_FILTER:
                # need to split this value on comma incase user specified more than one service
                # then use last split. Also remove quotes
                tmpText = splitText[1].replace("\"","")
                tmpServices = tmpText.split(',')
                curService = tmpServices[-1:][0]
                return self.tryMatchService(curService)
            elif splitText[0] == OPT_HOST_FILTER:
                # need to split this value on comma incase user specified more than one IP
                # then use last split. Also remove quotes
                tmpText = splitText[1].replace("\"","")
                tmpHosts = tmpText.split(',')
                curHost = tmpHosts[-1:][0]
                return self.basic_complete(curHost, line, begidx, endidx, mAllHosts)
        return [text]

    @with_category(CMD_CAT_NMAP)
    def do_set(self, inp):
        '''"set [option] [value]" will set the specified user option'''
        splitText = inp.split()
        if(len(splitText) != 2):
            print ("Invalid use of set command")
        else:
            for option in self.userOptions:
                if(option[0] == splitText[0].lower()):
                    self.setOption(option[0],splitText[1])
                    print("Set [" + option[0] + "] ==> '" + option[2] + "'")
                    break

    def complete_ports(self, text, line, begidx, endidx):
        return self.basic_complete(text, line, begidx, endidx,PORT_OPTIONS)

    @with_category(CMD_CAT_NMAP)
    def do_ports(self, inp):
        '''Lists unique ports. Usage "ports [default/tcp/udp/combined]"'''
        option = PORT_OPT_DEFAULT
        userOp = inp.strip().lower() 
        if(userOp in PORT_OPTIONS):
            option = userOp
        printUniquePorts(option)


    @with_category(CMD_CAT_NMAP)
    def do_import_summary(self, inp):
        '''Displays list of imported files'''
        
        header("Successfully Imported Files")
        if(len(filesImported) > 0):
            for file in filesImported:
                print (file)
        else:
            eprint("No files were imported successfully")
        print()

        if(len(filesFailedToImport) > 0):
            header("Failed Imports")
            for file in filesFailedToImport:
                eprint (file)


    def complete_unset(self, text, line, begidx, endidx):
        # remove 'unset' from first array slot
        splitText = line.split()[1:]
        if(len(text.strip()) == 0):
            return [option[0] for option in self.userOptions]
        if(len(splitText) == 1):
            return [option[0] for option in self.userOptions if option[0].startswith(splitText[0].lower()) and not (option[0] == splitText[0].lower())]
        return [text]

    @with_category(CMD_CAT_NMAP)
    def do_scanned_hosts(self, inp):
        '''List all hosts scanned'''
        header('Scanned hosts')
        printList(mAllHosts,filename=inp)

    @with_category(CMD_CAT_NMAP)
    def do_alive_hosts(self, inp):
        '''List alive hosts\nUseage: alive_hosts [filename_output]'''
        header('Alive hosts')
        printList([host for host in mAllHosts if mAllHosts[host].alive],filename=inp)

    @with_category(CMD_CAT_NMAP)
    def do_unset(self, inp):
        '''"unset [option]" will unset the specified user option'''
        splitText = inp.split()
        if(len(splitText) != 1):
            print ("Invalid use of unset command")
        else:
            for option in self.userOptions:
                if(option[0] == splitText[0].lower()):
                    self.setOption(option[0],"")
                    print("Unset [" + option[0] + "] ==> ''")
                    break

    # def do_shell(self, s):
    #     '''Execute shell commands'''
    #     os.system(s)

    # def default(self, inp):
    #     if inp == 'exit' or inp == 'quit':
    #         return self.do_exit(inp)
    #     else:
    #         print("\033[1;31m'" + inp + "' is not a recognized command\033[1;m")
    #         self.do_help("")


    # Prevent last command being repeated on newline
    # def emptyline(self):
    #     pass

    def setOption(self, specifiedOption, value):
        for option in self.userOptions:
            if option[0] == specifiedOption.lower():
                if (option[1] == "bool"):
                    self.setBoolOption(option, specifiedOption, value)
                else:
                    option[2] = value.replace('"', '')

    def setBoolOption(self, cmdOption, userOption, value):
        trueStrings = ["true", "yes", "t", "y", "on", "enabled", "1"]
        tmpValue = value.lower().strip()
        result = (tmpValue in trueStrings)
        cmdOption[2] = True
        if(cmdOption[0] == OPT_RAW):
            global printHumanFriendlyText
            printHumanFriendlyText = not result


    def getOption(self, specifiedOption):
        for option in self.userOptions:
            if(option[0] == specifiedOption.lower()):
                return option[2]
    
    def getPortFilter(self):
        portFilter = []
        rawPortFilterString = self.getOption(OPT_PORT_FILTER)
        # Check only contains valid chars
        if(re.match(r'^([\d\s,]+)$', rawPortFilterString)):
            # Remove any excess white space (start/end/between commas)
            curPortFilterString = re.sub(r'[^\d,]', '', rawPortFilterString)
            # Split filter on comma, ignore empty entries and assign to filter
            portFilter = [int(port) for port in curPortFilterString.split(',') if len(port) > 0]
        return portFilter
        
    def getHostFilter(self):
        hostFilter = []
        rawHostFilterString = self.getOption(OPT_HOST_FILTER)
        # Check only contains valid chars
        if(re.match(r'^([\d\s\.,]+)$', rawHostFilterString)):
            # Remove any excess white space (start/end/between commas)
            curHostFilterString = re.sub(r'[^\d\.,]', '', rawHostFilterString)
            # Split filter on comma, ignore empty entries and assign to filter
            hostFilter = [ip for ip in curHostFilterString.split(',') if len(ip) > 0]
        return hostFilter
    
    def getServiceFilter(self):
        return [option for option in self.getOption(OPT_SERVICE_FILTER).split(',') if len(option.strip()) > 0]
    
    def getFilters(self):
        return {
            OPT_SERVICE_FILTER : self.getServiceFilter(),
            OPT_PORT_FILTER : self.getPortFilter(),
            OPT_HOST_FILTER : self.getHostFilter()
        }

    def tryMatchService(self, text):
        matches = []
        try:
            serviceFiles = ['/usr/share/nmap/nmap-services', '/etc/services', 'C:\\windows\\system32\\drivers\\etc\\services']
            for serviceFile in serviceFiles:
                if(os.path.isfile(serviceFile)):
                    fhServices = open(serviceFile, 'r')
                    tmpRegex = '(' + text + r'\S*)\s+\d+/(?:tcp|udp)'
                    reg = re.compile(tmpRegex)
                    for line in fhServices:
                        matches += [match for match in reg.findall(line) if match not in matches]
                    fhServices.close()
                    break
        except Exception as ex:
            pass
        return matches

    def ipsThatMatchFilter(self):
        portFilter = self.getPortFilter()
        serviceFilter = self.getServiceFilter()
        matchedHosts = []
        for ip in mAllHosts:
            host = mAllHosts[ip]
            for port in host.ports:
                print("SVCFILTER:" + str(serviceFilter))
                if ((portFilter == [0] or port.portId in portFilter) and (serviceFilter == [''] or port.service in serviceFilter)):
                    matchedHosts.append(ip)
                    break
        return matchedHosts


def getFilesInDir(directory, filter='', recurse=False):
    allFiles = []
    regex = re.compile(filter)
    if(recurse):
        for root, dirs, files in os.walk(directory):
            allFiles.extend([os.path.join(root, file) for file in files if regex.match(os.path.join(root, file))])
    else:
        allFiles.extend([os.path.join(directory, file) for file in os.listdir(directory) if regex.match(os.path.join(directory, file))])
    return allFiles

def main():
    parser = OptionParser(usage="%prog [options] [list of nmap xml files or directories containing xml files]")
    parser.add_option("-p", "--port", dest="ports", help="Optional port filter argument e.g. 80 or 80,443", metavar="PORTS")
    parser.add_option("--service", dest="svcFilter", help="Optional service filter argument e.g. http or ntp,http (only used in conjunction with -s)")
    parser.add_option("-e","--exec", dest="cmd", help="Script or tool to run on each IP remaining after port filter is applied. IP will be appended to end of script command line", metavar="CMD")
    parser.add_option("-l","--iplist", dest="ipList", action="store_true", help="Print plain list of matching IPs")
    parser.add_option("-a","--alive-hosts", dest="aliveHosts", action="store_true", help="Print plain list of all alive IPs")
    parser.add_option("-s","--service-list", dest="servicelist", action="store_true", help="Also print list of unique services with names")
    parser.add_option("-S","--host-summary", dest="hostSummary", action="store_true", help="Show summary of scanned/alive hosts")
    parser.add_option("-v","--verbose", dest="verbose", action="store_true", help="Verbose service list")
    parser.add_option("-u", "--unique-ports", dest="uniquePorts", action="store_true", default=False, help="Print list of unique open ports")
    parser.add_option("-R","--raw", dest="raw", action="store_true", help="Only print raw output (no headers)")
    parser.add_option("-r","--recurse", dest="recurse", action="store_true", help="Recurse subdirectories if directory provided for nmap files")
    parser.add_option("-i","--interactive", dest="interactive", action="store_true", help="Enter interactive shell")
    parser.add_option("-c","--combine", dest="combine", help="Combine all input files into single nmap-parse compatible xml file")
    parser.add_option("--imported-files", dest="importedFiles", action="store_true", help="List successfully imported files")
    parser.add_option("-V","--version", dest="version", action="store_true", help="Print version info")
    (options, args) = parser.parse_args()

    if(options.version):
        print("Nmap Parse Version %s\nReleased: %s" % (VERSION,RELEASE_DATE))
        return

    # Determine whether to output headings
    global printHumanFriendlyText
    printHumanFriendlyText = not options.raw

    # Find all XML files
    nmapXmlFilenames = []
    for arg in args:
        if os.path.isdir(arg):
            nmapXmlFilenames.extend(getFilesInDir(arg, filter=r'.*\.xml$', recurse=options.recurse))
        else:
            nmapXmlFilenames.append(arg)

    # Exit if no XML files found
    if nmapXmlFilenames == []:
        eprint('No Nmap XML files found.\n')
        parser.print_help()
        sys.exit(1)

    portFilter = []
    serviceFilter = []
    if not options.interactive:
        # Check if only specific ports should be parsed
        if options.ports:
            portFilter = list(map(int,options.ports.split(',')))
            hprint('Set port filter to %s' % portFilter)

        # Check if only specific ports should be parsed
        if options.svcFilter:
            serviceFilter = options.svcFilter.split(',')
            hprint('Set service filter to %s' % serviceFilter)

    # Parse nmap files
    parseNmapXmlFiles(nmapXmlFilenames)

    # Print import summary if requested
    if options.importedFiles:
        print()
        printImportSummary(True)

    # Check if default flags were used
    defaultFlags = not options.ipList and not options.aliveHosts and not options.servicelist and not options.verbose and not options.cmd and not options.combine

    if options.combine:
        combineFiles(options.combine)

    if not options.interactive:
        if(defaultFlags):
            printHosts()
            printUniquePorts()
        elif(options.uniquePorts):
            printUniquePorts()

        if options.ipList:
            printMatchedIps(filters={OPT_SERVICE_FILTER : serviceFilter, OPT_PORT_FILTER : portFilter, OPT_HOST_FILTER : []})
            
        if options.aliveHosts:
            printAliveIps()

        if options.servicelist or options.verbose:
            printServiceList(options)

        if options.cmd:
            executeCommands(options.cmd, filters={OPT_SERVICE_FILTER : serviceFilter, OPT_PORT_FILTER : portFilter, OPT_HOST_FILTER : []})

        if printHumanFriendlyText and (defaultFlags or options.hostSummary):
            hprint("\nSummary\n-------")
            hprint("Total hosts: %s" % str(len(mAllHosts)))
            hprint("Alive hosts: %s" % str(len([host for host in mAllHosts if mAllHosts[host].alive])))
    else:
        enterInteractiveShell()

if __name__ == "__main__":
    #try:
        main()
    #except (KeyboardInterrupt, SystemExit):
    #    print("User terminated")
    #except Exception as ex:
    #    print("An unknown error occurred")



