from colorama import init, Fore, Back, Style
from termcolor import cprint


def welcome():
    init()

    #print(Fore.CYAN + 'This text is red in color')

    cprint("\t****WELCOME TO SECURITY SUITE 1.0****\t\n", "cyan", attrs=["dark"])
    cprint("___      __      ___  _______   __        _______   ________   ____      ____   _______", "light_cyan")
    cprint("\  \    /  \    /  / |   ____| |  |      |  _____| |   __   | |    \    /    | |   ____|", "light_cyan")
    cprint(" \  \  /    \  /  /  |  |____  |  |      |  |      |  |  |  | |     \  /     | |  |____ ", "light_cyan")
    cprint("  \  \/  /\  \/  /   |   ____| |  |      |  |      |  |  |  | |  |\  \/  /|  | |   ____|", "light_cyan")
    cprint("   \    /  \    /    |  |____  |  |____  |  |____  |  |__|  | |  | \    / |  | |  |____ " , "light_cyan")
    cprint("    \__/    \__/     |_______| |_______| |_______| |________| |__|  \__/  |__| |_______|\n" , "light_cyan")
    #print(Back.YELLOW + 'The text with Green background')
    #print(Style.BRIGHT + 'The text is DIM now')


    #print(Fore.MAGENTA + 'This text is red in color')

    #cprint("\nThis text is red in color\n", "red")



#welcome()