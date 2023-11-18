#!/usr/bin/python
from socket import *
import optparse
from threading import *

def portScan(tgtHost,tgtPort):
    try:
        tgtIP=gethostbyname(tgtHost)
    except:
        print('unknown host %s' %tgtHost)


def main():
    parser=optparse.OptionParser('Usage of program: '+'-H <Target Host> p <Target Port>')
    parser.add_option('-H',dest='tgtHost',type='string',help='Specify the host')
    parser.add_option('-p',dest='tgtPort',type='string',help='specify the port or ports seperated by coma port,port')
    (options,args)=parser.parse_args()
    tgtHost=options.tgtHost
    tgtPort=str(options.tgtPort).split(',')
    if(tgtHost==None) | (tgtPort[0]==None):
        print(parser.usage)
        exit(0)

if __name__ == '__main__':
        main()
