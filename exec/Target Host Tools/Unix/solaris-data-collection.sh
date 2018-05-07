#!/bin/ksh
# Script to collect the major security configuration files on a Solaris system
# RUN AS ROOT!
# tested on Solaris 10

# Jeff A. Odegard, CISSP
# AFSPC SMC/GPEA
# 20 Aug 13
# Updated 4 Sep 14

# Add to this list as necessary (get copies of these files)
FILELIST="/.cshrc
/.profile
/etc/access.conf
/etc/apache
/etc/apache2
/etc/cron.allow
/etc/cron.d
/etc/cron.deny
/etc/default
/etc/dfs
/etc/ftpd
/etc/ftpusers
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/hosts.equiv
/etc/httpd
/etc/inet/inetd.conf
/etc/inet/ntp.conf
/etc/inetd.conf
/etc/issue
/etc/issue.net
/etc/motd
/etc/nsswitch.conf
/etc/ntp.conf
/etc/pam.conf
/etc/passwd
/etc/passwd
/etc/profile
/etc/resolv.conf
/etc/securetty
/etc/security
/etc/shells
/etc/snmp/conf/snmpd.conf
/etc/snmpd.conf
/etc/syslog.conf
/etc/system
/noshell"

#HOSTNAME=`uname -a | cut -d" " -f2`
HOSTNAME=`hostname`
DIR="$HOSTNAME-baseline"
echo ""
echo "Results will be in ./$DIR"
mkdir -p $DIR
cd $DIR
FILEDIR="system-files"
echo "System files will be in ./$DIR/system-files"
mkdir -p system-files
rm -f $HOSTNAME-errors

echo ""
echo "Collecting some system information..."
echo "	uname -a"
uname -a > uname.txt
echo "	ifconfig -a"
ifconfig -a > ifconfig.txt
echo "	netstat -nr"
netstat -nr > netstat-nr.txt
echo "	netstat -nap"
netstat -nap > netstat-nap.txt
echo "	ps -eaf"
ps -eaf > ps-eaf.txt
echo "	last -a"
last -a > last-a.txt
echo "	who -a"
who -a > who-a.txt
echo "	df -ak"
df -ak > df-ak.txt
echo "	mount -p"
mount -p > mount-p.txt
echo "	rpcinfo -p"
rpcinfo -p >rpcinfo-p.txt
if [ `grep "nfs" rpcinfo-p.txt` ] ; then
	echo "	showmount"
	showmount 2>&1 > showmount.txt
	echo "	showmount -e"
	showmount -e 2>&1 > showmount-e.txt
else
	echo "	Skipping showmount. NFS does not appear in rpcinfo."
	echo "	NFS does not appear in rpcinfo.  Skipping showmount." >> $HOSTNAME-errors.log
fi
echo "	pkginfo -l"
pkginfo -l > pkginfo-l.txt
echo "	crontab -l"
crontab -l > crontab-l.txt
echo "	showrev -a"
showrev -a > showrev-a.txt
echo "	xhost"
xhost 2>&1 1>xhost.txt
echo "	eeprom security-mode"
eeprom security-mode 2>&1 1>eeprom-security-mode.txt
echo "	prtconf -D"
prtconf -D 2>&1 1>prtconf-D.txt

echo ""
echo "Gathering file listing/permissions for STIG checks"
echo "   NOTE: find errors are normal"
rm -f file-permissions.txt
# Get FStype for /
#FSTYPE=`mount -p | egrep " \/ [a-z]+" | awk '{print $4}'`
find / -local -ls > file-permissions.txt
ls -sh file-permissions.txt

echo ""
echo "Collecting some security configuration files and folders."
echo "   NOTE: Inability to find some files is normal":
# use cp -R - cron.d has a named pipe
for FILE in $FILELIST ; do
   if [ -f  $FILE -o -d $FILE ] ; then
	  DEST=`echo $FILE | sed "s/\//\-/g" | sed "s/^\-//"`
      echo "cp -R $FILE ./$FILEDIR/$DEST"
      cp -R $FILE ./$FILEDIR/$DEST
   else
     echo "   Could not find $FILE" >> $HOSTNAME-errors.log
     echo "   Could not find $FILE"
   fi
done

# We don't want to collect password hashes, but need to know if the accounts are locked.
# Note: this "for LINE in" hack only works because there are no spaces in /etc/shadow... :o}

rm -f shadow-trimmed
echo ""
echo "Trimming /etc/shadow for safety..."
for LINE in `cat /etc/shadow` ; do
   HASH=`echo $LINE | cut -d":" -f2`
   # Typical password hash is 34 characters
   if [ ${#HASH} -lt 13 ] ; then
	echo $LINE >> shadow-trimmed.txt
   elif [ ${#HASH} -lt 34 ] ; then
        echo $LINE | awk -F':' 'BEGIN{ OFS=":"; } { print $1,"SHORT/WEAK HASH",$3,$4,$5,$6,$7,$8,$9 }' >> shadow-trimmed.txt
   else
        echo $LINE | awk -F':' 'BEGIN{ OFS=":"; } { print $1,"FILTERED",$3,$4,$5,$6,$7,$8,$9 }' >> shadow-trimmed.txt
   fi
done

echo ""
echo "Please review to ensure hashes are filtered"
echo ""
cat shadow-trimmed.txt
echo ""

cd ..
echo "Tarring and Gzipping the results"
tar -cvf $DIR.tar ./$DIR
gzip $DIR.tar

echo ""
echo "All packaged up and ready to go in $DIR.tar.gz"
ls -sh $DIR.tar.gz
echo "Have a nice day!"
echo ""

