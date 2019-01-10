# coding:utf-8
# https://github.com/fourninecloud/SSL_Certs_expiry-Check

import socket
import ssl
import boto3
import json
import logging
import re, sys, os, datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

domainlist = []

def ssl_expiry_date(domainname):
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=domainname,
    )
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)
    conn.connect((domainname, 443))
    ssl_info = conn.getpeercert()
    return datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt).date()

def ssl_valid_time_remaining(domainname):
    """Number of days left."""
    expires = ssl_expiry_date(domainname)
    days_left = expires - datetime.datetime.utcnow().date()
    logger.info('%s SSL certificate will be expired in %s days.', domainname, days_left)
    return days_left

def sns_Alert(dName, eDays, sslStatus):
    TargetSNSArn = os.environ['SNSTopic']
    sslStat = dName + ' SSL certificate will be expired in ' + eDays +' days!! '
    snsSub = dName + ' SSL Certificate Expiry ' + sslStatus + ' alert'
    #logger.info(sslStat)
    logger.info(snsSub)
    response = client.publish(
        TargetArn = TargetSNSArn,
        Message= sslStat,
        Subject= snsSub
    )

def notify_slack(dName, eDays, color):
    slack_url = os.environ['SlackUrl']
    sslStat = dName + ' の証明書有効期限があと ' + eDays +' 日です！\n更新手続きをお願いします！'
    snsSub = dName + ' の証明書有効期限が近づいています！'
    attachments_json = [
        {
            "fallback": "Update the certification.",
            "color": color,
            "title": snsSub,
            "text": sslStat
        }
    ]
    slack_message = {
        'attachments': attachments_json
    }

    req = Request(slack_url, json.dumps(slack_message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted")
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)


# Main Section
client = boto3.client('sns')
def lambda_handler(event, context):
    domainlist.append(os.environ['Domain'])
    for dName in domainlist:
        logger.info(dName)
        expDate = ssl_valid_time_remaining(dName.strip())
        (a, b) = str(expDate).split(',')
        (c, d) = a.split(' ')
    # Critical alerts 
        if int(c) < 14:
            sns_Alert(dName, str(c), 'Critical')
            notify_slack(dName, str(c), 'danger')
    # Second critical alert on 20 th day      
        elif int(c) == 20:
            sns_Alert(dName, str(c), 'Critical')
            notify_slack(dName, str(c), 'danger')
    # First critical alert on 30th day
        elif int(c) == 30:
            sns_Alert(dName, str(c), 'Critical')
            notify_slack(dName, str(c), 'danger')
    # Second warning alert on 45th day      
        elif int(c) == 45:
            sns_Alert(dName, str(c), 'Warning')
            notify_slack(dName, str(c), 'warning')
    # First warning alert on 60th day      
        elif int(c) == 60:
            sns_Alert(dName, str(c), 'Warning')
            notify_slack(dName, str(c), 'warning')
        else:
            logger.info('Everything Fine..')