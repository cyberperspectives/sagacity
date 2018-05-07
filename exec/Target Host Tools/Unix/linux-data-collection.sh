#!/bin/bash
# Script to collect the major security configuration files on a Linux system
# RUN AS ROOT!
# tested on RHEL 5.2, SUSE 11

# Jeff A. Odegard, CISSP, CPT, CEH
# AFSPC SMC/GPEVA
# 20 Aug 13
# Rewritten 16 Sep 14
# Update 31 Mar 15:  Use find -xdev to limit the ffile-permissions.txt to local filesystems only.
	# Erik Wohlgemuth (Raytheon) and Jeff Odegard

# Add to this list as necessary (get copies of these files)
FILELIST="/.cshrc
/.profile
/etc/aide.conf
/etc/apache
/etc/apache2
/etc/audit/audit.rules
/etc/audit/auditd.conf
/etc/cron.allow
/etc/cron.d
/etc/cron.deny
/etc/crontab
/etc/default
/etc/ftpusers
/etc/gshadow
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/hosts.equiv
/etc/httpd
/etc/inetd.conf
/etc/inittab
/etc/motd
/etc/newsyslog.conf
/etc/nsswitch.conf
/etc/ntp.conf
/etc/ntp.conf
/etc/pam.conf
/etc/pam.d
/etc/passwd
/etc/profile
/etc/redhat-release
/etc/resolv.conf
/etc/securetty
/etc/security
/etc/shells
/etc/ssh_config
/etc/sshd_config
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/SuSE-brand
/etc/SuSE-release
/etc/syslog-ng
/etc/sysconfig/apache2
/etc/sysconfig/selinux
/etc/sysctl.conf
/etc/syslog.conf
/etc/syslog-ng
/etc/xinetd.conf
/etc/xinetd.d
/proc/cmdline
/root/.cshrc
/root/.profile"


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
rm -f $HOSTNAME-errors.txt
echo "Linux Data collection started on `date`" >> $HOSTNAME-errors.txt
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
echo "	ps aux"
ps aux > ps-aux.txt
echo "	last -a"
last -a -i > last-a-i.txt
echo "	who -a"
who -a > who-a.txt
echo "	df -ak"
df -ak > df-ak.txt
echo "	mount"
mount > mount.txt
echo "	rpcinfo -p"
rpcinfo -p > rpcinfo-p.txt
if [ `grep "nfs" rpcinfo-p.txt` ] ; then
	echo "	showmount"
	showmount 2>showmount.txt > showmount.txt
	echo "	showmount -e"
	showmount -e 2>showmount.txt > showmount-e.txt
else
	echo "	Skipping showmount. NFS does not appear in rpcinfo."
	echo "	NFS does not appear in rpcinfo.  Skipping showmount." >> $HOSTNAME-errors.txt
fi

echo "	rpm -qa -last"
rpm -qa -last > rpm-qa-last.txt
echo "	crontab -l"
crontab -l 2>crontab-l.txt > crontab-l.txt
echo "	pwck -r"
pwck -r > pwck-r.txt

echo ""
echo "Gathering file listing/permissions for STIG checks"
echo "   NOTE: find errors are normal"
rm -f file-permissions.txt
FSTYPE=`mount | egrep "on \/ type" | awk '{print $5}'`
for MOUNTPT in `mount | grep $FSTYPE | awk '{print $3}'`; do
	find $MOUNTPT -xdev -fstype $FSTYPE -ls >> file-permissions.txt
done
FILESIZE=`ls -sh file-permissions.txt | cut -d" " -f1`
if [ $FILESIZE -eq "0" ]; then # SuSE Linux 
	echo "  Hmmm, might be a SuSE Linux system"
	find / -fstype rootfs -ls > file-permissions.txt
fi
ls -sh file-permissions.txt

echo ""
echo "Collecting some security configuration files and folders."
echo "   NOTE: Inability to find some files is normal":
for FILE in $FILELIST ; do
   if [ -f  $FILE -o -d $FILE ] ; then
	DEST=`echo $FILE | sed "s/\//\-/g" | sed "s/^\-//"`
      echo " cp -af $FILE ./$FILEDIR/$DEST"
      cp -af $FILE ./$FILEDIR/$DEST
   else
	#egrep "\/passwd$" ehud-baseline/file-permissions.txt | awk '{print $11}'
     echo "	  Could not find $FILE" >> $HOSTNAME-errors.txt
     echo "	  Could not find $FILE"
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
echo "Linux Data collection ended on `date`" >> $HOSTNAME-errors.txt
cd ..
echo "Tarring and Gzipping the results"
tar -zcvf $DIR.tgz ./$DIR

echo ""
echo "All packaged up and ready to go in $DIR.tgz"
ls -sh $DIR.tgz
echo "Have a nice day!"
echo ""

