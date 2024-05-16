from colorama import init, Fore, Back, Style
from termcolor import cprint

init()

#print(Fore.CYAN + 'This text is red in color')

cprint("\t****WELCOME TO SECURITY SUITE 1.0****\t\n", "cyan", attrs=["dark"])
cprint("\n  ____      _____      ____", "light_cyan")
cprint("\n  \   \    /     \    /   /", "light_cyan")
cprint("\n   \   \__/   _   \__/   /", "light_cyan")
cprint("\n    \        / \        /" , "light_cyan")
cprint("\n     \______/   \______/" , "light_cyan")
#print(Back.YELLOW + 'The text with Green background')
#print(Style.BRIGHT + 'The text is DIM now')


#print(Fore.MAGENTA + 'This text is red in color')

cprint("\nThis text is red in color\n", "red")