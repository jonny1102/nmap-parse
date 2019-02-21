import cmd2
from cmd2 import Cmd, with_category, argparse_completer, with_argparser
from cmd2.argparse_completer import ACArgumentParser, ACTION_ARG_CHOICES, AutoCompleter
from tabulate import tabulate
import os, random, re, textwrap
import argparse
import ipaddress

from modules import helpers
from modules import constants
from modules import settings
from modules import common
from modules import nmap

from modules.helpers import hprint, sprint, eprint, header

class InteractivePrompt(Cmd):  
    CMD_CAT_NMAP = "Nmap Commands"

    prompt = '\n\033[1;30mnp> \033[1;m'
    intro = """\nWelcome to nmap parse! Type ? to list commands
  \033[1;30mTip: You can send output to clipboard using the redirect '>' operator without a filename\033[1;m
  \033[1;30mTip: Set quiet to true to only get raw command output (no headings)\033[1;m"""
    allow_cli_args = False
    
    service_filter = ''
    port_filter = ''
    host_filter = ''
    include_ports = True
    have_ports = True
    verbose = False
    raw = False

    userOptions = [
        [constants.OPT_SERVICE_FILTER, "string", "", "Comma seperated list of services to show, e.g. \"http,ntp\""],
        [constants.OPT_PORT_FILTER, "string", "", "Comma seperated list of ports to show, e.g. \"80,123\""],
        [constants.OPT_HOST_FILTER, "string","", "Comma seperated list of hosts to show, e.g. \"127.0.0.1,127.0.0.2\""],
        [constants.OPT_HAVE_PORTS, "bool","True", "When enabled, hosts with no open ports are excluded from output  [ True / False ]"],
        [constants.OPT_INCLUDE_PORTS, "bool","True", "Toggles whether ports are included in 'list/services' output  [ True / False ]"],
        [constants.OPT_VERBOSE, "bool", "False", "Shows verbose service information  [ True / False ]"],
        [constants.OPT_RAW, "bool", "False", "Shows raw output (no headings)  [ True / False ]"]
    ]

    def __init__(self, nmapOutput, *args, **kwargs):
        self.setupUserOptions()
        super().__init__(*args, **kwargs)
        self.nmapOutput = nmapOutput
        self.printRandomBanner()
        self.register_postcmd_hook(self.postCmdHook)

    # Use this to check if the set command was used and do our own internal logic 
    # in addition to cmd2's logic
    def postCmdHook(self, data: cmd2.plugin.PostcommandData) -> cmd2.plugin.PostcommandData:
        if data.statement.command == 'set' and len(data.statement.args.split()) == 2:
            tmpOption = data.statement.args.split()[0] 
            tmpValue = data.statement.args.split()[1]
            for option in self.userOptions:
                if(tmpOption.lower() == option[0]):
                    self.setOption(option[0], tmpValue)
                    break
        return data

    def setupUserOptions(self):
        for userOption in self.userOptions:
            self.settable[userOption[0]] = userOption[3]
        
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
        curBanner = ("-" * maxLen) + "\n\033[1;30m" + curBanner + "\033[0;m \n" + ("-" * maxLen)
        print(curBanner)
    
    def do_exit(self, inp):
        '''Exit the interactive prompt'''
        print("Bye")
        return True
 
    @with_category(CMD_CAT_NMAP)
    def do_list(self, inp):
        '''List all IP's matching filter'''
        consoleOutput = helpers.getHostListOutput(self.nmapOutput, includePorts=self.include_ports, filters=self.getFilters())
        self.printTextOutput(consoleOutput)


    def complete_show(self, text, line, begidx, endidx):
        return ['options']

    @with_category(CMD_CAT_NMAP)
    def do_show(self, inp):
        '''"show options" will list current user options'''
        self.syncOptions()
        if(inp.lower() == 'options'):
            self.poutput('')
            self.poutput(tabulate(self.userOptions, headers=['Setting', "Type", 'Value', 'Description'], tablefmt="github"))
            self.poutput('')
        else:
            self.poutput('"show options" will list current user options')
 
    
    def complete_set(self, text, line, begidx, endidx):
        # remove 'set' from first array slot
        splitText = line.split()[1:]
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

    def complete_ports(self, text, line, begidx, endidx):
        return self.basic_complete(text, line, begidx, endidx, constants.PORT_OPTIONS)

    @with_category(CMD_CAT_NMAP)
    def do_services(self, inp):
        '''Lists all services (supports verbose output)'''
        consoleOutput = helpers.getServiceListOutput(self.nmapOutput, filters=self.getFilters(), verbose=self.verbose, includePorts = self.include_ports)
        self.printTextOutput(consoleOutput)

    @with_category(CMD_CAT_NMAP)
    def do_ports(self, inp):
        '''Lists unique ports. Usage "ports [default/tcp/udp/combined]"'''
        option = constants.PORT_OPT_DEFAULT
        userOp = inp.strip().lower() 
        if(userOp in constants.PORT_OPTIONS):
            option = userOp
        consoleOutput = helpers.getUniquePortsOutput(self.nmapOutput.getHostDictionary(self.getFilters()), option)
        self.printTextOutput(consoleOutput)


    @with_category(CMD_CAT_NMAP)
    def do_import_summary(self, inp):
        '''Displays list of imported files'''
        
        self.pfeedback(helpers.getHeader("Successfully Imported Files"))
        if(len(self.nmapOutput.FilesImported) > 0):
            for file in self.nmapOutput.FilesImported:
                self.poutput(file)
        else:
            self.perror("No files were imported successfully")
        print()

        if(len(self.nmapOutput.FilesFailedToImport) > 0):
            self.pfeedback( helpers.getHeader("Failed Imports"))
            for file in self.nmapOutput.FilesFailedToImport:
                self.perror(file)


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
        helpers.printList(self.nmapOutput.Hosts,filename=inp)

    @with_category(CMD_CAT_NMAP)
    def do_alive_hosts(self, inp):
        '''List alive hosts\nUseage: alive_hosts [filename_output]'''
        header('Alive hosts')
        helpers.printList(self.nmapOutput.getAliveHosts(),filename=inp)

    @with_category(CMD_CAT_NMAP)
    def do_unset_all(self, inp):
        '''"unset_all" will reset all user options to default values'''
        consoleOutput = common.TextOutput()
        for option in [option[0] for option in self.userOptions]:
            if(self.unsetOption(option)):
                consoleOutput.addHumn("Unset [" + option + "] ==> " + str(self.getOption(option)))
            else:
                consoleOutput.addErrr("Failed to unset [%s]" % option)
        self.printTextOutput(consoleOutput)

    @with_category(CMD_CAT_NMAP)
    def do_unset(self, inp):
        '''"unset [option]" will unset the specified user option'''
        splitText = inp.split()
        if(len(splitText) != 1):
            print ("Invalid use of unset command")
        else:
            success = self.unsetOption(splitText[0].lower())  
            if(success):
                print("Unset [" + splitText[0].lower() + "] ==> ''")

    def unsetOption(self, option):
        if(option == constants.OPT_HAVE_PORTS):
            self.have_ports = False
        elif(option == constants.OPT_HOST_FILTER):
            self.host_filter = ''
        elif(option == constants.OPT_PORT_FILTER):
            self.port_filter = ''
        elif(option == constants.OPT_RAW):
            self.raw = False
        elif(option == constants.OPT_SERVICE_FILTER):
            self.service_filter = ''
        elif(option == constants.OPT_VERBOSE):
            self.verbose = False
        elif(option == constants.OPT_INCLUDE_PORTS):
            self.include_ports = True
        else:
            return False
        return True

    def setOption(self, specifiedOption, value):
        for option in self.userOptions:
            if option[0] == specifiedOption.lower():
                if (option[1] == "bool"):
                    self.setBoolOption(option, specifiedOption, value)
                elif(option[0] == constants.OPT_HOST_FILTER):
                    self.setHostFilter(option, value.replace('"', ''))
                else:
                    option[2] = value.replace('"', '')

    def setHostFilter(self, option, userFilter):
        tmpHostFilter = helpers.stringToHostFilter(userFilter.replace('"', ''))
        filterString = ','.join([filter.filter for filter in tmpHostFilter])
        option[2] = filterString
        self.host_filter = filterString

    def setBoolOption(self, cmdOption, userOption, value):
        tmpValue = value.lower().strip()
        result = (tmpValue in constants.TRUE_STRINGS)
        cmdOption[2] = str(result)
        if(cmdOption[0] == constants.OPT_RAW):
            settings.printHumanFriendlyText = not result

    def getOptionBool(self, specifiedOption):
        return "True" == self.getOption(specifiedOption)

    def syncOptions(self):
        for option in self.userOptions:
            if(option[0] == constants.OPT_HAVE_PORTS):
                option[2] = self.have_ports
            elif(option[0] == constants.OPT_HOST_FILTER):
                option[2] = self.host_filter
            elif(option[0] == constants.OPT_PORT_FILTER):
                option[2] = self.port_filter
            elif(option[0] == constants.OPT_RAW):
                option[2] = self.raw
            elif(option[0] == constants.OPT_SERVICE_FILTER):
                option[2] = self.service_filter
            elif(option[0] == constants.OPT_VERBOSE):
                option[2] = self.verbose
            elif(option[0] == constants.OPT_INCLUDE_PORTS):
                option[2] = self.include_ports

    def getOption(self, specifiedOption):
        for option in self.userOptions:
            if(option[0] == specifiedOption.lower()):
                return option[2]
    
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
        filters.mustHavePorts = self.have_ports
        return filters

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

    def printTextOutput(self, textOutput):
        for line in textOutput.entries:
            if(line.output == constants.TEXT_NORMAL):
                self.poutput(line.getText())
            elif(line.output == constants.TEXT_ERROR):
                self.perror(line.getText(), False, err_color=constants.COLOUR_ERROR)
            elif (not self.quiet) and (not self.redirecting) and settings.printHumanFriendlyText:
                if(line.output == constants.TEXT_FRIENDLY):
                    self.pfeedback(line.getText())
                elif(line.output == constants.TEXT_SUCCESS):
                    self.pfeedback(line.getText())
                else:
                    self.poutput(line.getText())