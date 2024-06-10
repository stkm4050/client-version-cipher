from argparse import ArgumentParser

def get_option():
    argparser = ArgumentParser()
    argparser.add_argument('-f','--file',type=str,default='/home/kamada/searchVersion/regular-202406090000.dump',help='Set search file')
    return argparser.parse_args()