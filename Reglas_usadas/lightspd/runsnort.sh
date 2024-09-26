#!/bin/bash

if [ $# -ne 7 ]
then
   echo "PLEASE NOTE: This script is intended only for testing and getting snort 3 up and running."
   echo "As written, it only reads pcaps from the specified directory and alerts to the terminal,"
   echo "but it's useful for learning how to assemble the command line for running Snort 3."
   echo
   echo
   echo "USAGE: $0 <SNORTINSTALLDIR> <DAQDIR> <SNORTPOLICYVER> <SNORTMODULESVER> <ARCHITECTURE> <POLICY> <PCAPDIR>"
   echo "Ex: $0 /usr/local/bin/snort/snort3/install /usr/local/lib/daq 3.1.0.0-0 3.1.51.0-0 arch-x64 security-over-connectivity /tmp/pcaps"
   echo
   echo "SNORTINSTALLDIR is the --prefix parameter of configure_cmake.sh when you built snort3"
   echo "DAQDIR is where the DAQ plugins are installed.  This is needed for things like daq pcap reading"
   echo

   echo "Valid snort policy versions are:"
   find policies/ -maxdepth 1 -type d | sed 's/policies\///' | grep -v common | sort -r
   echo -n "Valid snort modules versions are:"
   find modules/ -maxdepth 1 -type d | sed 's/modules\///' | grep -v stubs
   echo
   echo "Valid architectures are:"
   for X in `ls -d modules/*/* | grep -v stubs | sed 's/^.*\///' | sort -u`; do echo -e "\t$X"; done
   echo
   echo "Valid policies are (usually):"
   echo "	connectivity-over-security"
   echo "	balanced-security-and-connectivity"
   echo "	security-over-connectivity"
   echo "	maximum-detection"
   echo "	no-rules-active"
   echo 
   echo
   exit
fi;


SNORTINSTALLDIR=$1
DAQDIR=$2
SNORTPOLICYVER=$3
SNORTMODULESVER=$4
ARCH=$5
POLICY=$6
PCAPDIR=$7

${SNORTINSTALLDIR}/bin/snort -c policies/${SNORTPOLICYVER}/${POLICY}.lua --daq-dir $DAQDIR --plugin-path modules/${SNORTMODULESVER}/${ARCH}/ --daq dump --daq-var load-mode=read-file --pcap-dir $PCAPDIR -A cmg


