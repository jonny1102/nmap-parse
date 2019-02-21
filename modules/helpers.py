import os, re, sys, subprocess, ipaddress
from subprocess import Popen,PIPE
import xml.etree.ElementTree as ET

from IPy import IP

from modules import constants
from modules import settings
from modules import common
from modules import nmap

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
    

# Colour output green (successprint)
def sprint(*args, **kwargs):
    colouredPrint("\033[1;32m", args, kwargs)

# Print to stderr
def eprint(*args, **kwargs):
    colouredPrint("\033[1;31m", args, kwargs)

# Print text with specified colour code
def colouredPrint(colour, args, kwargs):
    if(not settings.colourSupported):
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
    settings.printHumanFriendlyText
    if(settings.printHumanFriendlyText):
        print(*args, **kwargs)

def getHeader(text):
    header = os.linesep + text + os.linesep
    header += '-' * len(text) + os.linesep
    return header

def header(text):
    hprint(getHeader(text))

def printUniquePorts(hosts, option=constants.PORT_OPT_DEFAULT):
    textOutput = getUniquePortsOutput(hosts, option)
    textOutput.printToConsole()

def getUniquePortsOutput(hosts, option=constants.PORT_OPT_DEFAULT):
    tcpPorts = set()
    udpPorts = set()
    allPorts = set()
    for ip in hosts:
        host = hosts[ip]
        tcpPorts = tcpPorts.union(host.getUniquePortIds('tcp'))
        udpPorts = udpPorts.union(host.getUniquePortIds('udp'))
    allPorts = tcpPorts.union(udpPorts)

    output = common.TextOutput()
    output.addHumn(getHeader('Unique open port list (%s)' % (option)))
    if option == constants.PORT_OPT_DEFAULT:
        output.addHumn(getHeader("TCP:"))
        output.addMain(re.sub(r'[\[\] ]','',str(sorted(tcpPorts))))
        output.addHumn(getHeader("UDP:"))
        output.addMain(re.sub(r'[\[\] ]','',str(sorted(udpPorts))))
        output.addHumn(getHeader("Combined:"))
        output.addMain(re.sub(r'[\[\] ]','',str(sorted(allPorts))))
    elif option == constants.PORT_OPT_TCP:
        output.addMain(re.sub(r'[\[\] ]','',str(sorted(tcpPorts))))
    elif option == constants.PORT_OPT_UDP:
        output.addMain(re.sub(r'[\[\] ]','',str(sorted(udpPorts))))
    elif option == constants.PORT_OPT_COMBINED:
        output.addMain(re.sub(r'[\[\] ]','',str(sorted(allPorts))))
    return output

def getNmapFiltersString(filters):
    filterString = ""
    if filters.isFilterSet():
        filterString += getHeader("Output filtered by:")
        if filters.hostFilterSet():
            filterString += ("Host filter: %s" % ([filter.filter for filter in filters.hosts])) + os.linesep
        if filters.serviceFilterSet():
            filterString += ("Service filter: %s" % (filters.services)) + os.linesep
        if filters.portFilterSet():
            filterString += ("Port filter: %s" % (filters.ports)) + os.linesep
    return filterString

def printNmapFilters(filters):
    filterString = getNmapFiltersString(filters)
    if(len(filterString) > 0):
        hprint(filterString)
    

def getHostListOutput(nmapOutput, includePorts = True, filters = None):
    '''Returns string representations of filtered hosts output'''
    if filters == None:
        filters = nmap.NmapFilters()

    output = common.TextOutput()
    output.addHumn(getNmapFiltersString(filters))
    output.addHumn(getHeader('Matched IP list'))

    # Get all hosts that are up and matched filters
    hostsOutput = []
    for host in nmapOutput.getHosts(filters=filters):
        curHostOutput = [host.ip, '']
        for protocol in constants.PROTOCOLS: 
            fullPortsString = ''
            for port in [port for port in host.ports if port.protocol == protocol]:
                tmpPortString = str(port.portId) 
                if(settings.colourSupported and port.matched):
                    tmpPortString = "\033[1;32m" + tmpPortString + "\033[1;m"
                if len(fullPortsString) > 0:
                    fullPortsString += ","
                fullPortsString += tmpPortString
            curHostOutput[1] += "%s:[%s]  " % (protocol,fullPortsString)
        hostsOutput.append(curHostOutput)
    
    for hostOutput in hostsOutput:
        if includePorts:
            output.addMain("%s\t%s" % (hostOutput[0], hostOutput[1]))
        else:
            output.addMain(hostOutput[0])
    return output

def printHosts(nmapOutput, includePorts = True, filters=None):
    textOutput = getHostListOutput(nmapOutput, includePorts=includePorts, filters=filters)
    textOutput.printToConsole()

# Order array of IPs
def sortIpList(ip_list):
    ipl = [(IP(ip).int(), ip) for ip in ip_list]
    ipl.sort()
    return [ip[1] for ip in ipl]

def printImportSummary(nmapOutput, detailed=True):
    if(detailed):
        for file in nmapOutput.FilesImported:
            sprint("Successfully loaded " + file)
    sprint(os.linesep + "Successfully loaded " + str(len(nmapOutput.FilesImported)) + " files")
    if len(nmapOutput.FilesFailedToImport) > 0:
        eprint("The following files failed to parse:")
        for file in nmapOutput.FilesFailedToImport:
            eprint("\t" + file)

def getServiceListOutput(nmapOutput, filters=None, verbose=False, includePorts=True):
    services = nmapOutput.getServices(filters)
    output = common.TextOutput()
    output.addHumn(getHeader('Service List'))
    first = True
    for service in services:
        if(verbose):
            if first:
                first = False
            else:
                output.addMain("")
        svcString = service.name
        if(includePorts):
            svcString += " " + str(sorted(service.ports))
        output.addMain(svcString)
        if verbose:
            for host in service.hosts:
                hostString = '  ' + host.ip 
                if(includePorts):
                    hostString += " " + str(sorted(host.ports))
                output.addMain(hostString)
    return output

def printServiceList(nmapOutput, filters=None, verbose=False):
    textOutput = getServiceListOutput(nmapOutput, filters=filters, verbose=verbose)
    textOutput.printToConsole()

# Execute commands
def executeCommands(cmd, nmapOutput, filters=None):
    if(filters == None):
        filters = nmap.NmapFilters()
    header('Running Commands')
    for host in nmapOutput.getHosts(filters):
        if len(host.ports) > 0:
            executeCommand(cmd, host.ip)

# Execute Single Command
def executeCommand(cmd, ip):
    curCommand = cmd + " " + ip
    hprint("Running command: '%s'" % curCommand)
    process = Popen(curCommand, shell=True, stdout=PIPE)
    output = process.stdout.read()
    hprint("Finished running command: %s" % curCommand)
    header("OUTPUT for '%s':" % curCommand)
    if output == '':
        print('<none>')
    else:
        print(output)
    print('')

def printAliveIps(nmapOutput):
    header('Alive IP list')
    # Get all hosts that are up and matched filters
    tmpParsedHosts = nmapOutput.getAliveHosts()
    for ip in sortIpList(tmpParsedHosts):
        print("%s" % (ip))

def getFilesInDir(directory, filter='', recurse=False):
    allFiles = []
    regex = re.compile(filter)
    if(recurse):
        for root, dirs, files in os.walk(directory):
            allFiles.extend([os.path.join(root, file) for file in files if regex.match(os.path.join(root, file))])
    else:
        allFiles.extend([os.path.join(directory, file) for file in os.listdir(directory) if regex.match(os.path.join(directory, file))])
    return allFiles

def stringToHostFilter(filterString):
    hostFilter = []
    rawHostFilterString = filterString
    # Remove any excess white space (start/end/between commas)
    curHostFilterString = re.sub(r'[^\d\./,]', '', rawHostFilterString)
    # Split filter on comma, ignore empty entries and assign to filter
    tmpHostFilter = [ip for ip in curHostFilterString.split(',') if len(ip) > 0]
    for filter in tmpHostFilter:
        validFilter = False
        isIp = False
        try:
            ipaddress.ip_address(filter)
            validFilter = True
            isIp = True
        except ValueError:
            pass

        try:
            ipaddress.ip_network(filter)
            validFilter = True
        except ValueError:
            pass
        if(validFilter):
            hostFilter.append(nmap.NmapHostFilter(filter, isIp))
        else:
            eprint("Invalid host filter option ignored: " + filter)
    return hostFilter