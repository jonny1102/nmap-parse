import random, textwrap, os, argparse, re
import cmd2, tabulate

from typing import List

from modules import helpers
from modules import constants
from modules import settings
from modules import common
from modules import nmap

class TerminalBase(cmd2.Cmd):
    def printTextOutput(self, textOutput):
        for line in textOutput.entries:
            if(line.output == constants.TEXT_NORMAL):
                self.poutput(line.getText())
            elif(line.output == constants.TEXT_ERROR):
                self.perror(line.getText())
            #elif (not self.quiet) and (not self.redirecting) and settings.printHumanFriendlyText:
            elif (not self.quiet) and settings.printHumanFriendlyText:
                if(line.output == constants.TEXT_FRIENDLY):
                    self.pfeedback(line.getText())
                elif(line.output == constants.TEXT_SUCCESS):
                    self.pfeedback(line.getText())
                else:
                    self.poutput(line.getText())

class NmapTerminal(TerminalBase):
    #region Setup defaults
    CMD_CAT_NMAP = "Nmap Commands"
    CMD_CAT_FILTER = "Configure Filters"

    service_filter = ''
    port_filter = ''
    host_filter = ''
    include_ports = True
    include_hostname = True
    have_ports = True
    only_up = True
    verbose = True
    raw = False

    settable = [constants.OPT_INCLUDE_PORTS, constants.OPT_INCLUDE_HOSTNAME, constants.OPT_SERVICE_FILTER, constants.OPT_PORT_FILTER, constants.OPT_HOST_FILTER, constants.OPT_UP, constants.OPT_HAVE_PORTS, constants.OPT_VERBOSE, constants.OPT_RAW]

    prompt = '\n\033[4m\033[1;30mnmap-parse\033[1;30m\033[0m\033[1;30m >\033[0;m '
    intro = """\nWelcome to nmap parse! Type ? to list commands
  \033[1;30mTip: You can send output to clipboard using the redirect '>' operator without a filename\033[1;m
  \033[1;30mTip: Set quiet to true to only get raw command output (no headings)\033[1;m"""
    
    #endregion

    def __init__(self, nmapOutput, *args, **kwargs):
        super().__init__(*args, **kwargs, allow_cli_args = False)
        self.printRandomBanner()
        self.nmapOutput = nmapOutput
        
        cmd2.utils.categorize(self.do_set, self.CMD_CAT_FILTER)

        self.add_settable(cmd2.Settable(constants.OPT_INCLUDE_PORTS, bool, "Toggles whether ports are included in 'list/services' output  [ True / False ]", self))
        self.add_settable(cmd2.Settable(constants.OPT_INCLUDE_HOSTNAME, bool, "Toggles whether hostnames are included in 'list' output  [ True / False ]", self))
        self.add_settable(cmd2.Settable(constants.OPT_SERVICE_FILTER, str, "Comma seperated list of services to show, e.g. \"http,ntp\"", self))
        self.add_settable(cmd2.Settable(constants.OPT_PORT_FILTER, str, "Comma seperated list of ports to show, e.g. \"80,123\"", self))
        self.add_settable(cmd2.Settable(constants.OPT_HOST_FILTER, str, "Comma seperated list of hosts to show, e.g. \"127.0.0.1,127.0.0.2\"", self))
        self.add_settable(cmd2.Settable(constants.OPT_UP, bool, "When enabled, any hosts which were down will be excluded from output  [ True / False ]", self))
        self.add_settable(cmd2.Settable(constants.OPT_HAVE_PORTS, bool, "When enabled, hosts with no open ports are excluded from output  [ True / False ]", self))
        self.add_settable(cmd2.Settable(constants.OPT_VERBOSE, bool, "Shows verbose service information  [ True / False ]", self))
        self.add_settable(cmd2.Settable(constants.OPT_RAW, bool, "Shows raw output (no headings)  [ True / False ]", self))

    #region Completion Methods
    def complete_unset(self, text, line, begidx, endidx):
        # remove 'unset' from first array slot
        splitText = line.split()[1:]
        if(line.strip() == 'unset'):
            return [option for option in self.settable]
        if(len(splitText) == 1):            
            return [option for option in self.settable if option.startswith(splitText[0].lower()) and not (option == splitText[0].lower())]

    def complete_set(self, text, line, begidx, endidx):
        # remove 'set' from first array slot
        tmpSplit = line.split()[1:]
        # Remove any additional flags (e.g. -v)
        splitText = [i for i in tmpSplit if not i.startswith("-")]
        if(line.strip() == 'set'):
            return [option for option in self.settable]
        if(len(splitText) == 1):            
            return [option for option in self.settable if option.startswith(splitText[0].lower()) and not (option == splitText[0].lower())]
        if(len(splitText) == 2):
            if splitText[0] == constants.OPT_SERVICE_FILTER:
                # need to split this value on comma incase user specified more than one service
                # then use last split. Also remove quotes
                tmpText = splitText[1].replace("\"","")
                tmpServices = tmpText.split(',')
                curService = tmpServices[-1:][0]
                prefix = ''
                if len(tmpServices) > 1:
                    prefix = ','.join(tmpServices[:-1]) + ','
                return self.tryMatchService(curService, prefix)
            elif splitText[0] == constants.OPT_HOST_FILTER:
                # need to split this value on comma incase user specified more than one IP
                # then use last split. Also remove quotes
                tmpText = splitText[1].replace("\"","")
                tmpHosts = tmpText.split(',')
                curHost = tmpHosts[-1:][0]
                prefix = ''
                if len(tmpHosts) > 1:
                    prefix = ','.join(tmpHosts[:-1]) + ','
                return [(prefix + ip) for ip in self.nmapOutput.Hosts if curHost in ip]
        return [text]

    def tryMatchService(self, text, prefix):
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
        except:
            raise
        return [(prefix + match) for match in matches]

    # text - Current text typed for current parameter user is typing
    # line - Full command entered so far
    # begidx and endidx are indices of start and end of current parameter
    # arg_tokens = dictionary of tokens
    def ip_completer(self, text, line, begidx, endidx, arg_tokens):
        sText = text.strip()
        ips = [x for x in self.nmapOutput.Hosts.keys() if x.startswith(sText)]
        return ips

    host_parser = cmd2.Cmd2ArgumentParser()
    host_parser.add_argument('ip', help="Show details of specified host", type=str, completer=ip_completer)

    def complete_file(self, text, line, begidx, endidx):
        return [file for file in self.nmapOutput.FilesImported if file.startswith(text)]

    def complete_ports(self, text, line, begidx, endidx):
        return self.basic_complete(text, line, begidx, endidx, constants.PORT_OPTIONS)

    complete_import = cmd2.Cmd.path_complete
    #endregion

    #region Terminal Commands
    def do_exit(self, inp):
        '''Exit the interactive prompt'''
        print("Bye")
        return True

    @cmd2.with_category(CMD_CAT_FILTER)
    def do_unset_all(self, inp):
        '''"unset_all" will reset all user options to default values'''
        consoleOutput = common.TextOutput()
        for option in self.settable:
            if(self.unsetOption(option)):
                consoleOutput.addHumn("Unset [" + option + "]")
            else:
                consoleOutput.addErrr("Failed to unset [%s]" % option)
        self.printTextOutput(consoleOutput)

    @cmd2.with_category(CMD_CAT_FILTER)
    def do_unset(self, inp):
        '''"unset [option]" will unset the specified user option'''
        splitText = inp.split()
        if(len(splitText) != 1):
            print ("Invalid use of unset command")
        else:
            success = self.unsetOption(splitText[0].lower())  
            if(success):
                print("Unset [" + splitText[0].lower() + "] ==> ''")

    @cmd2.with_category(CMD_CAT_NMAP)
    @cmd2.with_argparser(host_parser)
    def do_host(self, args):
        '''Print details for specified host
        Useage: "host [ip address]'''
        ip = args.ip.strip()
        if(ip not in self.nmapOutput.Hosts):
            self.perror("Host not found: " + ip)
            return
        curHost = self.nmapOutput.Hosts[ip]
        self.printTextOutput(helpers.getHostDetails(curHost))

    @cmd2.with_category(CMD_CAT_NMAP)
    def do_list(self, inp):
        '''List all IP's matching filter'''
        consoleOutput = helpers.getHostListOutput(self.nmapOutput, includePorts=self.include_ports, filters=self.getFilters(), includeHostname=self.include_hostname, isTable=False)
        self.printTextOutput(consoleOutput)

    @cmd2.with_category(CMD_CAT_NMAP)
    def do_tlist(self, inp):
        '''List all IP's matching filter as table'''
        consoleOutput = helpers.getHostListOutput(self.nmapOutput, includePorts=self.include_ports, filters=self.getFilters(), includeHostname=self.include_hostname, isTable=True)
        self.printTextOutput(consoleOutput)

    @cmd2.with_category(CMD_CAT_NMAP)
    def do_file(self, inp):
        '''Print details for specified file'''
        file = inp.strip().replace("\"","")
        if(file not in self.nmapOutput.FilesImported):
            self.perror("File not found: " + file)
            return

        filters = self.getFilters()
        self.pfeedback(helpers.getNmapFiltersString(filters))
        hosts = self.nmapOutput.getHostsWithinFile(file, filters=filters)

        self.pfeedback(helpers.getHeader("Hosts within file"))
        if self.verbose:
            headers = ['IP', 'Hostname', 'State', 'TCP Ports (count)', 'UDP Ports (count)' ]
            verboseOutput = []
            for host in hosts:
                verboseOutput.append([host.ip, host.getHostname(), host.getState(),
                                        len(host.getUniquePortIds(constants.PORT_OPT_TCP)),
                                        len(host.getUniquePortIds(constants.PORT_OPT_UDP))])
            self.poutput(tabulate.tabulate(verboseOutput, headers=headers, tablefmt="github"))
        else:
            for host in hosts:
                self.poutput(host.ip)

    @cmd2.with_category(CMD_CAT_NMAP)
    def do_services(self, inp):
        '''Lists all services (supports verbose output)'''
        consoleOutput = helpers.getServiceListOutput(self.nmapOutput, filters=self.getFilters(), verbose=self.verbose, includePorts = self.include_ports)
        self.printTextOutput(consoleOutput)

    @cmd2.with_category(CMD_CAT_NMAP)
    def do_ports(self, inp):
        '''Lists unique ports. Usage "ports [default/tcp/udp/combined]"'''
        option = constants.PORT_OPT_DEFAULT
        userOp = inp.strip().lower()
        if(userOp in constants.PORT_OPTIONS):
            option = userOp
        filters = self.getFilters()
        consoleOutput = helpers.getUniquePortsOutput(self.nmapOutput.getHostDictionary(filters), option, filters=filters)
        self.printTextOutput(consoleOutput)
    
    @cmd2.with_category(CMD_CAT_NMAP)
    @cmd2.with_argument_list
    def do_import(self, args: List[str]):
        '''Import additional nmap files or directories

        Usage: import [filename/directory]
        '''
        if not args:
            self.perror('import requires a path to a file/directory as an argument')
            return
        allFiles = []
        for file in args:
            allFiles.extend(helpers.getNmapFiles(file, recurse=True))
        self.nmapOutput.parseNmapXmlFiles(allFiles)

    @cmd2.with_category(CMD_CAT_NMAP)
    def do_import_summary(self, inp):
        '''Displays list of imported files'''

        self.pfeedback(helpers.getHeader("Successfully Imported Files"))
        if(len(self.nmapOutput.FilesImported) > 0):
            if self.verbose:
                headers = ['Filename', 'Hosts Scanned', 'Alive Hosts']
                verboseOutput = []
                filesWithNoHosts = []
                filters = nmap.NmapFilters(defaultBool=False)
                hostsByFile = self.nmapOutput.getHostsByFile(filters)
                for file in self.nmapOutput.FilesImported:
                    if file in hostsByFile:
                        scannedHosts = hostsByFile[file]
                        aliveHostCount = len([host for host in scannedHosts if host.alive])
                        verboseOutput.append([file, len(scannedHosts), aliveHostCount])
                    else:
                        verboseOutput.append([file, 0, 0])
                        filesWithNoHosts.append(file)
                self.poutput(tabulate.tabulate(verboseOutput, headers=headers))
                if(len(filesWithNoHosts) > 0):
                    self.perror("\nThe following file(s) had no hosts:")
                    for file in filesWithNoHosts:
                        self.perror("  - " + file)
            else:
                for file in self.nmapOutput.FilesImported:
                    self.poutput(file)
        else:
            self.perror("No files were imported successfully")
        print()

        if(len(self.nmapOutput.FilesFailedToImport) > 0):
            self.pfeedback( helpers.getHeader("Failed Imports"))
            for file in self.nmapOutput.FilesFailedToImport:
                self.perror(file)

    @cmd2.with_category(CMD_CAT_NMAP)
    def do_scanned_hosts(self, inp):
        '''List all hosts scanned'''
        self.pfeedback(helpers.getHeader('Scanned hosts'))

        filters = self.getFilters()
        filters.onlyAlive = False

        for line in [host.ip for host in self.nmapOutput.getHosts(filters=filters)]:
            self.poutput(line)

    @cmd2.with_category(CMD_CAT_NMAP)
    def do_alive_hosts(self, inp):
        '''List alive hosts'''
        self.pfeedback(helpers.getHeader('Alive hosts'))
        for ip in self.nmapOutput.getAliveHosts(self.getFilters()):
            self.poutput(ip)
    #endregion

    #region Helper Methods
    def unsetOption(self, option):
        if(option == constants.OPT_HAVE_PORTS):
            self.have_ports = True
        elif(option == constants.OPT_HOST_FILTER):
            self.host_filter = ''
        elif(option == constants.OPT_PORT_FILTER):
            self.port_filter = ''
        elif(option == constants.OPT_RAW):
            self.raw = False
        elif(option == constants.OPT_SERVICE_FILTER):
            self.service_filter = ''
        elif(option == constants.OPT_VERBOSE):
            self.verbose = True
        elif(option == constants.OPT_INCLUDE_PORTS):
            self.include_ports = True
        elif(option == constants.OPT_UP):
            self.only_up = True
        elif(option == constants.OPT_INCLUDE_HOSTNAME):
            self.include_hostname = True
        else:
            return False
        return True

    def getPortFilter(self):
        portFilter = []
        rawPortFilterString = self.port_filter
        # Check only contains valid chars
        if(re.match(r'^([\d\s,]+)$', rawPortFilterString)):
            # Remove any excess white space (start/end/between commas)
            curPortFilterString = re.sub(r'[^\d,]', '', rawPortFilterString)
            # Split filter on comma, ignore empty entries and assign to filter
            portFilter = [int(port) for port in curPortFilterString.split(',') if len(port) > 0]
        return portFilter
    
    def getHostFilter(self):
        return helpers.stringToHostFilter(self.host_filter)
    
    def getServiceFilter(self):
        return [option for option in self.service_filter.split(',') if len(option.strip()) > 0]

    def getFilters(self):
        filters = nmap.NmapFilters()
        filters.services = self.getServiceFilter()
        filters.ports = self.getPortFilter()
        filters.hosts = self.getHostFilter()
        filters.onlyAlive = self.only_up
        filters.mustHavePorts = self.have_ports
        return filters
    
    def printRandomBanner(self):
        banners = [  """
                                                       .         .
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
        curBanner = textwrap.dedent(random.choice(banners)).replace(os.linesep, os.linesep + "  ")
        maxLen = 0
        for line in curBanner.split('\n'):
            if len(line) > maxLen:
                maxLen = len(line)
        curBanner = ("-" * maxLen) + "\n\033[1;34m" + curBanner + "\033[0;m \n" + ("-" * maxLen)
        self.poutput(curBanner)
    
    #endregion