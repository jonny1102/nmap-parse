from colorama import Fore, Style

from modules import constants
from modules import settings
from modules import helpers

class TextOutput():
    def __init__(self):
        self.entries = []
    
    def addMain(self, text):
        self.entries.append(TextOutputEntry(text, constants.TEXT_NORMAL, Fore.RESET))
    
    def addHumn(self, text):
        self.entries.append(TextOutputEntry(text, constants.TEXT_FRIENDLY, Style.DIM))
    
    def addErrr(self, text):
        self.entries.append(TextOutputEntry(text, constants.TEXT_ERROR, Fore.RED))
    
    def addGood(self, text):
        self.entries.append(TextOutputEntry(text, constants.TEXT_SUCCESS, Fore.GREEN))

    def printToConsole(self):
        for line in self.entries:
            shouldPrint = False
            if(line.output == constants.TEXT_NORMAL or line.output == constants.TEXT_ERROR):
                shouldPrint = True
            elif(settings.printHumanFriendlyText):
                shouldPrint = True
            
            if shouldPrint:
                print(line.getText())

class TextOutputEntry():
    # Output specified the type of output for the text
    #   0 - Main output
    #   1 - Unnecessary but friendly output (e.g. headings)
    #   2 - Error output
    #   3 - Success/Good output
    def __init__(self, text, output, colour):
        self.text = text
        self.output = output
        self.colour = colour

    def getText(self):
        if settings.colourSupported:
            return "%s%s%s" % (self.colour, self.text, Style.RESET_ALL)
        else:
            return self.text
            