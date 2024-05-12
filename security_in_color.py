from colorama import init, Fore, Back, Style
from termcolor import cprint

init()

#print(Fore.CYAN + 'This text is red in color')

cprint("\nThis text is red in color\n", "red", attrs=["dark"])

#print(Back.YELLOW + 'The text with Green background')
#print(Style.BRIGHT + 'The text is DIM now')


#print(Fore.MAGENTA + 'This text is red in color')

cprint("This text is red in color\n", "light_cyan")