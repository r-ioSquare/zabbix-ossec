#!/bin/sh

##############################################################
# ioSquare: This file is managed by Puppet.                  #
# WARNING: Any local modification to this file will be lost. #
##############################################################

# This ossec active response will send the level a crafted message
# To ZBX_SERVER using ZBX_HOSTNAME as the hostname in Zabbix

ACTION=$1
ALERTID=$4
RULEID=$5

#Our constant

ZBX_SERVER="zabbix.classmatic.net"
ZBX_HOSTNAME=$(cat /etc/zabbix/zabbix_agentd.conf |grep -E "^Hostname=.+" |cut -d= -f2)


# Logging the call
echo "`date` $0 $1 $2 $3 $4 $5 $6 $7 $8" >> /var/ossec/logs/active-responses.log


# Getting alert time
ALERTTIME=`echo "$ALERTID" | cut -d  "." -f 1`

# Getting end of alert
ALERTLAST=`echo "$ALERTID" | cut -d  "." -f 2`

# Getting alert level
alert_level=$(grep -A 4 "$ALERTID" /var/ossec/logs/alerts/alerts.log | grep -v ".$ALERTLAST: " -A 4 | grep -Eo "(level [0-9]+)"| grep -Eo "[0-9]+")

alert_message=$(grep -A 4 "$ALERTID" /var/ossec/logs/alerts/alerts.log | grep -v ".$ALERTLAST: " -A 4 | grep -Eo "\(level [0-9]+\).+" )

# Testing : send the log line too
line_number=$(( $( cat /var/ossec/logs/alerts/alerts.log | grep -A 15 "$ALERTID" | grep -nE "^$" | head -n1 | cut -d: -f1)-2 ))

alert_log=$( cat /var/ossec/logs/alerts/alerts.log | grep -A $line_number "$ALERTID" | tail -n1 )

if [ -z "$alert_log" ]; then
	alert_log="no log"
fi


# If there is more than one alert for a alerttime, then we loop to send all the alerts.

set -e 

	echo "$ZBX_HOSTNAME ossec.last_alert_message $alert_message" | zabbix_sender -z $ZBX_SERVER -i -
	echo "$ZBX_HOSTNAME ossec.last_alert_level $alert_level" | zabbix_sender -z $ZBX_SERVER -i -
	echo "$ZBX_HOSTNAME ossec.last_alert_log $alert_log" | zabbix_sender -z $ZBX_SERVER -i -


