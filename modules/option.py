from argparse import ArgumentParser

def get_option():
    argparser = ArgumentParser()
    argparser.add_argument('-f','--file',type=str,default='/home/kamada/capture_libssh/libssh-0.10.0-1.0.1u-install/sshd9.0-1.0.1u.dump',help='Set search file')
    argparser.add_argument('-i','--address',type=str,default='10.1.152.2',help='Set server IP')
    return argparser.parse_args()