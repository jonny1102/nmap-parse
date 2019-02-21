import copy
import ipaddress

import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

from modules import constants
from modules import helpers

class NmapOutput():
    def __init__(self, xmlFiles):
        self.FilesFailedToImport = []
        self.FilesImported = []
        self.Hosts = {}
        self.Services = []
        # Import xml files
        self.parseNmapXmlFiles(xmlFiles)
    
    def parseNmapXmlFiles(self, nmapXmlFilenames):
        count = 0
        colourSupport = helpers.supportsColour()
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
                helpers.hprint(sStatus, end='\r')
            else:
                helpers.hprint(sStatus)

            # Try to parse xml and record any failures
            nmap_xml = ""
            try:
                nmap_xml = ET.parse(nmapXmlFilename)
            except:
                self.FilesFailedToImport.append(nmapXmlFilename)
                continue
            # Record that file successfully loaded
            self.FilesImported.append(nmapXmlFilename)
            # Find all hosts within xml file
            for xHost in nmap_xml.findall('.//host'):
                # Get IP address
                ip = xHost.find("address[@addrtype='ipv4']").get('addr')
                # Add host to dictionary
                if ip not in self.Hosts:
                    self.Hosts[ip] = NmapHost(ip)
                curHost = self.Hosts[ip]

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
                        self.addService(curService, ip, curPortId)
    
    # Ger or create new service with host/ip/port details
    def addService(self, svcName, ip, port):
        curService = self.getService(svcName)
        curServiceHost = self.getServiceHost(curService, ip)
        if port not in curServiceHost.ports:
            curServiceHost.ports.append(port)
        if port not in curService.ports:
            curService.ports.append(port)

    # Get service host or create if necessary
    def getServiceHost(self, service, ip):
        for host in service.hosts:
            if host.ip == ip:
                return host
        
        newServiceHost = NmapHost(ip)
        service.hosts.append(newServiceHost)
        return newServiceHost

    # Get service or create if necessary
    def getService(self, svcName):
        for service in self.Services:
            if service.name == svcName:
                return service
        
        newService = NmapService(svcName)
        self.Services.append(newService)
        return newService

    def getHostDictionary(self, filters=None):
        hostDict = {}
        for host in self.getHosts(filters):
            hostDict[host.ip] = host
        return hostDict

    def getHosts(self, filters=None):
        if filters == None:
            filters = NmapFilters()

        matchedHosts = []
        for ip in helpers.sortIpList(self.Hosts):
            host = copy.deepcopy(self.Hosts[ip])
            if ((not host.alive) and filters.onlyAlive) or not filters.checkHost(ip):
                continue

            matched = False
            # Check ports
            for protocol in constants.PROTOCOLS: 
                for port in [port for port in host.ports if port.protocol == protocol]:
                    port.matched = True
                    if (
                        (filters.portFilterSet() and (filters.ports == [] or port.portId not in filters.ports)) or 
                        (filters.serviceFilterSet() and (filters.services == [] or port.service not in filters.services))
                    ):
                        port.matched = False
                        
                    if port.matched:
                        matched = True
            
            if filters.mustHavePorts and len(host.ports) == 0:
                matched = False

            if matched or (not filters.onlyAlive):
                matchedHosts.append(host)
        return matchedHosts

    def getAliveHosts(self, filters):
        return [host.ip for host in self.getHosts(filters) if host.alive]

    def getServices(self, filters=None):
        if filters == None:
            filters = NmapFilters()
        matchedServices = []
        for service in self.Services:
            # Check if service matches filter
            if not (
                (filters.serviceFilterSet() and (filters.services == [] or service.name not in filters.services)) or
                (filters.portFilterSet() and (filters.ports == [] or not [port for port in service.ports if port in filters.ports])) or
                (filters.hostFilterSet() and (filters.hosts == [] or not [host for host in service.hosts if host in filters.hosts]))
            ):
                matchedServices.append(service)
        return matchedServices

    def generateNmapParseXml(self, filename):
        # create the file structure
        xNmapParse = ET.Element('nmapparse')
        for ip in self.Hosts:
            curHost = self.Hosts[ip]
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
            helpers.sprint("Combined file saved to: " + filename)
        except Exception as ex:
            helpers.eprint("Failed to combine files")
            helpers.eprint(str(ex))

class NmapService():
    def __init__(self, name):
        self.name = name
        self.hosts = []
        self.ports = []

class NmapHost():
    def __init__(self, ip):
        self.ip = ip
        self.hostname = ''
        self.alive = False
        self.ports = []
        self.services = []
        self.matched = True # Used for filtering

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
        self.matched = True # Used for filtering

class NmapFilters():
    def __init__(self):
        self.hosts = []
        self.ports = []
        self.services = []
        self.mustHavePorts = True
        self.onlyAlive = True

    def isFilterSet(self):
        return self.hostFilterSet() or self.portFilterSet() or self.serviceFilterSet()

    def hostFilterSet(self):
        return len(self.hosts) > 0

    def portFilterSet(self):
        return len(self.ports) > 0

    def serviceFilterSet(self):
        return len(self.services) > 0

    def checkHost(self, ip):
        # Always return true if no filter is set
        if not self.hostFilterSet():
            return True
        
        # Check if host matches any ips first
        matched = ip in [filter.filter for filter in self.hosts if filter.isIp]

        # If no match found, check if host matches any network range
        if not matched:
            for filter in [filter for filter in self.hosts if filter.isNetwork]:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(filter.filter):
                    matched = True
                    break
        
        return matched
        # CHECKCKKDSFHDIUGJIUDSG and ip not in filters.hosts)

class NmapHostFilter():
    def __init__(self, filter, isIp):
        self.filter = filter
        self.isIp = isIp
        self.isNetwork = not isIp