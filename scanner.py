#!/usr/bin/python
import os
import argparse
import ConfigParser

#Parse from command line
parser = argparse.ArgumentParser(description='GSM SCANNING...')
parser.add_argument('DEV', metavar='d', type=int, help='Device index.')
args = parser.parse_args()

#Parse from config file
dev = str(args.DEV)
config = ConfigParser.ConfigParser()
config.read("config")
PPM = config.getint("settings" + dev,"PPM")
GAIN = config.getfloat("settings" + dev,"GAIN")

print PPM, GAIN

command = "grgsm_scanner --args=rtl=" + dev + " --ppm=" + str(PPM) + " --gain=" + str(GAIN) + " -b GSM900 --speed=4"
print os.system(command)
