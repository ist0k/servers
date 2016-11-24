#!/bin/bash
# chkconfig: 2345 08 92
# syntax: ./firewall-eth0.sh start|stop|restart
#
### BEGIN INIT INFO
# Provides:          firewall
# Required-Start:    $network 
# Required-Stop:     $network 
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: iptables start/stop/restart script
### END INIT INFO
#
# $Id: firewall,v 1.5 24-12-2014 02:05:34 cvs Exp $
#
### Set these ports to match your setup. ###
# You NEED to set this!							|
# Configuration follows:						|
#									|
# You probably don't want all the ports I have under here open.         |
# Portscan yourself to find what you want open or use:                  | 			
#                                                                       |
# netstat -pant | grep LISTEN                                           |
#
#

IPTABLES="/sbin/iptables"	# set to your iptables location, must be set
TCP_ALLOW="25 80 110 113 143 443" #TCP ports to ALLOW - 25 is SMTP, 80 web, 110 is POP3, 143 is IMAP, 22 is SSH
UDP_ALLOW=""		# UDP ports to ALLOW (53 not needed, covered by DNS below)
INET_IFACE="eth0"			# the interface
DENY_ALL=""				# Internet hosts to explicitly deny from accessing your system at all - a perment blacklist
DROP="REJECT"				# What to do with packets we don't want: DROP, REJECT, LDROP (log and drop), or LREJECT (log and reject)
DNS=1					# Set to 1 if you have DNS running and want INCOMING DNS. Outgoing DNS is already taken care of
FTP=1					# set to 1 if you run an FTP
SSHPORT="22"				# Come on, we all run SSH, may as well hard code it in. Put the port you run it on so we can throttle connects?

# ----------------------------------------------------------------------|
# Do not modify configuration below here				|
# ----------------------------------------------------------------------|
DROP="REJECT" #Apparently some ISPs (@home comes to mind) have problems with denying them, so send back ICMP messages to fool them

FILTER_CHAINS="INETIN INETOUT LDROP LREJECT TCPACCEPT UDPACCEPT"
# ----------------------------------------------------------------------|
# You shouldn't need to modify anything below here			|
# ----------------------------------------------------------------------|

# Let's load it!
#---------------------------------------------------------------
function start() {
echo "Loading iptables firewall:"

#---------------------------------------------------------------
# Configuration Sanity Checks
#---------------------------------------------------------------
echo -n "Checking configuration..."
if ! [ -x $IPTABLES ] ; then
	echo
	echo "ERROR IN CONFIGURATION: IPTABLES doesn't exist or isn't executable!"
	exit 1
fi
echo "passed"

#---------------------------------------------------------------
# Turn on IP forwarding (your kernel still needs it)
#---------------------------------------------------------------
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "IP Forwarding enabled..."

#---------------------------------------------------------------
# Enable TCP Syncookies (always a 'good thing') (thanks steff)
#---------------------------------------------------------------
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo "IP SynCookies enabled..."

#---------------------------------------------------------------
# Flush everything
# If you need compatability, you can comment some or all of these out,
# but remember, if you re-run it, it'll just add the new rules in, it
# won't remove the old ones for you then, this is how it removes them.
#
# You'll notice I give status now :)
#---------------------------------------------------------------
echo -n "Flush: "
${IPTABLES} -t filter -F INPUT
echo -n "INPUT "
${IPTABLES} -t filter -F OUTPUT
echo -n "OUTPUT1 "
${IPTABLES} -t filter -F FORWARD
echo -n "FORWARD "
${IPTABLES} -t nat -F PREROUTING
echo -n "PREROUTING1 "
${IPTABLES} -t nat -F OUTPUT
echo -n "OUTPUT2 "
${IPTABLES} -t nat -F POSTROUTING
echo -n "POSTROUTING "
${IPTABLES} -t mangle -F PREROUTING
echo -n "PREROUTING2 "
${IPTABLES} -t mangle -F OUTPUT
echo -n "OUTPUT3"
echo

#---------------------------------------------------------------
# The loopback interface should accept all traffic
# Necessary for X-Windows and other socket based services
#---------------------------------------------------------------
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Create new chains
# Output to /dev/null in case they don't exist from a previous invocation
echo -n "Creating chains: "
for chain in ${FILTER_CHAINS} ; do
	${IPTABLES} -t filter -F ${chain} > /dev/null 2>&1
	${IPTABLES} -t filter -X ${chain} > /dev/null 2>&1
	${IPTABLES} -t filter -N ${chain}
	echo -n "${chain} "
done
echo

#---------------------------------------------------------------
# Default Policies
# INPUT is still ACCEPT, the INETIN chain (defined above and jumped to later)
# is given a policy of DROP at the end
# Policy can't be reject becuase of kernel limitations
#---------------------------------------------------------------
echo -n "Default Policies: "
${IPTABLES} -t filter -P INPUT ACCEPT
echo -n "INPUT:ACCEPT "
${IPTABLES} -t filter -P OUTPUT ACCEPT
echo -n "OUTPUT:ACCEPT "
${IPTABLES} -t filter -P FORWARD DROP
echo -n "FORWARD:DROP "
echo


# Set up INET chains
echo -n "Setting up INET chains: "
${IPTABLES} -t filter -A INPUT -i ${INET_IFACE} -j INETIN
echo -n "INETIN "
${IPTABLES} -t filter -A OUTPUT -o ${INET_IFACE} -j INETOUT
echo -n "INETOUT "
echo

#---------------------------------------------------------------
#These logging chains are valid to specify in DROP= above
#Set up LDROP
#---------------------------------------------------------------
echo -n "Setting up logging chains: "
${IPTABLES} -t filter -A LDROP -p tcp -j LOG --log-level info --log-prefix "TCP Dropped "
${IPTABLES} -t filter -A LDROP -p udp -j LOG --log-level info --log-prefix "UDP Dropped "
${IPTABLES} -t filter -A LDROP -p icmp -j LOG --log-level info --log-prefix "ICMP Dropped "
${IPTABLES} -t filter -A LDROP -f -j LOG --log-level warning --log-prefix "FRAGMENT Dropped "
${IPTABLES} -t filter -A LDROP -j DROP
echo -n "LDROP "

#And LREJECT too
${IPTABLES} -t filter -A LREJECT -p tcp -j LOG --log-level info --log-prefix "TCP Rejected "
${IPTABLES} -t filter -A LREJECT -p udp -j LOG --log-level info --log-prefix "UDP Rejected "
${IPTABLES} -t filter -A LREJECT -p icmp -j LOG --log-level info --log-prefix "ICMP Dropped "
${IPTABLES} -t filter -A LREJECT -f -j LOG --log-level warning --log-prefix "FRAGMENT Rejected "
${IPTABLES} -t filter -A LREJECT -j REJECT
echo -n "LREJECT "

#newline
echo


#---------------------------------------------------------------
# Set up the per-proto ACCEPT chains
#---------------------------------------------------------------
echo -n "Setting up per-proto ACCEPT: "

# TCPACCEPT
# SYN Flood Protection
${IPTABLES} -t filter -A TCPACCEPT -p tcp --syn -m limit --limit 12/s  --limit-burst 24 -j ACCEPT
${IPTABLES} -t filter -A TCPACCEPT -p tcp ! --syn -j ACCEPT
# Log anything that hasn't matched yet and ${DROP} it since we don't know what it is
${IPTABLES} -t filter -A TCPACCEPT -j LOG --log-prefix "Mismatch in TCPACCEPT "
${IPTABLES} -t filter -A TCPACCEPT -j ${DROP}
echo -n "TCPACCEPT "

#---------------------------------------------------------------
#UDPACCEPT
#---------------------------------------------------------------
${IPTABLES} -t filter -A UDPACCEPT -p udp -j ACCEPT

#---------------------------------------------------------------
# Log anything not on UDP (it shouldn't be here), and ${DROP} it since it's not supposed to be here
#---------------------------------------------------------------
${IPTABLES} -t filter -A UDPACCEPT -j LOG --log-prefix "Mismatch on UDPACCEPT "
${IPTABLES} -t filter -A UDPACCEPT -j ${DROP}

echo -n "UDPACCEPT "

#Done
echo

#---------------------------------------------------------------
# need to cat the file into DENY_ALL and give specific ports
#Explicit denies
#---------------------------------------------------------------


if [ "$DENY_ALL" != "" ] ; then
	echo -n "Denying hosts: "
	for host in ${DENY_ALL} ; do
		${IPTABLES} -t filter -A INETIN -s ${host} -j ${DROP}
		echo -n "${host}:${DROP}"
	done
	echo
fi

#---------------------------------------------------------------
#Invalid packets are always annoying
#---------------------------------------------------------------
echo -n "${DROP}ing invalid packets..."
${IPTABLES} -t filter -A INETIN -m state --state INVALID -j ${DROP}
echo "done"



# ================================================================
# ------------Allow stuff we have chosen to allow in--------------
# ================================================================

#---------------------------------------------------------------
#Start allowing stuff

# Flood "security"
# You'll still respond to these if they comply with the limits
# Default limits are 1/sec for ICMP pings
# SYN Flood is on a per-port basis because it's a security hole to put it here!
# This is just a packet limit, you still get the packets on the interface and
#    still may experience lag if the flood is heavy enough
#---------------------------------------------------------------
echo -n "Flood limiting: "
# Ping Floods (ICMP echo-request)
${IPTABLES} -t filter -A INETIN -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
echo -n "ICMP-PING "
echo

echo -n "Allowing the rest of the ICMP messages in..."
${IPTABLES} -t filter -A INETIN -p icmp --icmp-type ! echo-request -j ACCEPT
echo "done"

if [ "$TCP_ALLOW" != "" ] ; then
	#echo -n "TCP Input Allow: "
	for port in ${TCP_ALLOW} ; do
 		${IPTABLES} -t filter -A INETIN -p tcp --dport ${port} -j TCPACCEPT
		echo -n "${port} "
	done
	echo
fi

if [ "$UDP_ALLOW" != "" ] ; then
	echo -n "UDP Input Allow: "
	for port in ${UDP_ALLOW} ; do
		${IPTABLES} -t filter -A INETIN -p udp --dport ${port} -j UDPACCEPT
		echo -n "${port} "
	done
	echo
fi

#---------------------------------------------------------------
#ftp
#---------------------------------------------------------------

## This is what i used to block all other countries into my FTP except NZ ppl
#/usr/bin/wget ftp://ftp.apnic.net/pub/apnic/dbase/data/country-ipv4.lst -O /tmp/country-ipv4.lst

#for NZIP in `cat /tmp/country-ipv4.lst |grep nz | awk '{print $5}'` ; do
#	echo Allowing ${NZIP}
#	${IPTABLES} -t filter -A INETIN -p tcp --sport 20 --dport 1024:65535 -s $NZIP -d 219.88.241.110 -j TCPACCEPT
#	${IPTABLES} -t filter -A INETIN -p tcp --sport 20 --dport 1024:65535 -s $NZIP -d 219.88.241.107 -j TCPACCEPT
#	${IPTABLES} -t filter -A INETIN -p tcp --sport 873 --dport 1024:65535 -s $NZIP -d 219.88.241.110 -j TCPACCEPT
#	${IPTABLES} -t filter -A INETIN -p tcp --sport 873 --dport 1024:65535 -s $NZIP -d 219.88.241.107 -j TCPACCEPT

#done

if [ $FTP == "1" ];then
	${IPTABLES} -t filter -A INETIN -p tcp --sport 20 --dport 1024:65535  ! --syn -j TCPACCEPT
	${IPTABLES} -t filter -A INETIN -p tcp --dport 21  -j TCPACCEPT
fi	   
		   

#---------------------------------------------------------------
#needs to accept all udp dns
#---------------------------------------------------------------
if [ $DNS == "1" ];then
	echo -n "DNS Transfers: "
	${IPTABLES} -t filter -A INETIN -p udp --dport 53 -j UDPACCEPT
fi

# Limiting the SSH attempts
# The following two rules will limit incoming connections to port 22 to no more than 3 attemps in a minute - an more than that will be dropped
#${IPTABLES} -t filter -A INETIN -p tcp --dport ${SSHPORT} -j TCPACCEPT
${IPTABLES} -t filter -A INETIN -p tcp --dport $SSHPORT -i $INET_IFACE -m state --state NEW -m recent --set -j TCPACCEPT
  
${IPTABLES} -t filter -A INETIN -p tcp --dport $SSHPORT -i $INET_IFACE -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j LREJECT
    

echo -n "Allowing established outbound connections back in..."
${IPTABLES} -t filter -A INETIN -m state --state ESTABLISHED,RELATED -j ACCEPT
echo "done"

#---------------------------------------------------------------
#What to do on those INET chains when we hit the end
#---------------------------------------------------------------
echo -n "Setting up INET policies: "

#---------------------------------------------------------------
#Drop if we cant find a valid inbound rule.
#---------------------------------------------------------------
${IPTABLES} -t filter -A INETIN -j ${DROP}
echo -n "INETIN:${DROP} "

#---------------------------------------------------------------
#We can send what we want to the internet
#---------------------------------------------------------------
# This is the default. Some people may wish to block what is going out from their server,
# however this can break many things. Package management, website plugins, etc
#
# ${IPTABLES} -t filter -A INETOUT -m state --state ESTABLISHED,RELATED  -j ACCEPT
${IPTABLES} -t filter -A INETOUT -j ACCEPT


echo -n "INETOUT:ACCEPT "
echo

set_policy DROP
#${IPTABLES} --policy INPUT   DROP
#${IPTABLES} --policy OUTPUT  DROP
#${IPTABLES} --policy FORWARD DROP

#All done!
echo "Done loading the firewall!"
}
function stop() {
	echo "* Stopping firewall ... "
	flush
	set_policy ACCEPT
	echo "* Firewall stopped."
}

function flush() {
	echo -n "  Flushing tables ... "
	${IPTABLES} -X
	${IPTABLES} -F
	${IPTABLES} -Z
	echo "Done"
}

function set_policy() {
	local policy="$1"
	echo -n "  Setting default policy to $1 ... "
 	${IPTABLES} -P INPUT $policy
	${IPTABLES} -P FORWARD $policy
	${IPTABLES} -P OUTPUT $policy
	echo "Done"
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
		;;
    restart)
		stop
		start
		;;
    *)
		echo "Usage: $0 {start|stop|restart}"
		exit 1
		;;
esac
