#!/usr/bin/python
import os
import argparse
import ConfigParser

#Parse from command line
parser = argparse.ArgumentParser(description='GSM CAPTURING...')
parser.add_argument('ARFCN', metavar='a', type=int, help='Arfcn.')
parser.add_argument('DEV', metavar='d', type=int, help='Device index.')
args = parser.parse_args()
dev = str(args.DEV)

#Parse from config file
config = ConfigParser.ConfigParser()
config.read("config")
PPM = config.getint("settings" + dev,"PPM")
GAIN = config.getfloat("settings" + dev,"GAIN")
SAMP_RATE = config.get("settings" + dev,"SAMP_RATE")

print PPM, GAIN, SAMP_RATE

command = "grgsm_capture --args=rtl=" + dev + " --ppm=" + str(PPM) + " --gain=" + str(GAIN) + " -a " + str(args.ARFCN) + " -s " + SAMP_RATE + " -c " + str(args.ARFCN) + ".cfile"
print os.system(command)
print "DONE"
