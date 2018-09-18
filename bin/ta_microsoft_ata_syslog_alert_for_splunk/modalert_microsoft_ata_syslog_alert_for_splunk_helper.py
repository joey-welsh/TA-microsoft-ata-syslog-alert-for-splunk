
# encoding = utf-8
import json
import syslog_client
from collections import OrderedDict
import datetime
import time
from time import gmtime, strftime

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example gets the alert action parameters and prints them to the log
    ata_server_ip = helper.get_param("ata_server_ip")
    helper.log_info("ata_server_ip={}".format(ata_server_ip))

    ata_server_port = helper.get_param("ata_server_port")
    helper.log_info("ata_server_port={}".format(ata_server_port))

    hostname = helper.get_param("hostname")
    helper.log_info("hostname={}".format(hostname))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    helper.log_info("Alert action microsoft_ata_syslog_alert_for_splunk started.")
    # The following example gets and sets the log level
    helper.set_log_level(helper.log_level)
    
    # The following example gets the alert action parameters and prints them to the log

    ata_server_ip = helper.get_param("ata_server_ip")
    #helper.log_info("ata_server_ip={}".format(ata_server_ip))

    ata_server_port = helper.get_param("ata_server_port")
    #helper.log_info("ata_server_port={}".format(ata_server_port))

    hostname = helper.get_param("hostname")
    # helper.log_info("hostname={}".format(hostname))
    
    syslogClient = syslog_client.Syslog(host=str(ata_server_ip),port=int(ata_server_port))
    
    syslogFields = OrderedDict()

    #get Search results
    searchResults = helper.get_events()
    for entry in searchResults:
        if hostname:
            header_host = str(hostname)
        else: 
            header_host = entry.get('host') 

        #time_zone = time.strftime('%z',gmtime(float(entry.get('_time'))))
        time_zone = "-000"
        base_time = datetime.datetime.fromtimestamp(float(entry.get('_time'))).strftime('%Y%m%d%H%M%S.%f')
        event_time = base_time + time_zone

        header = header_host + " " + event_time + "\r\n"
        syslogFields['Logfile'] = entry.get('LogName', "-")
        syslogFields['SourceName'] = entry.get('SourceName', "-")
        syslogFields['EventCode'] = entry.get('EventCode', "-") 
        syslogFields['TimeGenerated'] = event_time
        syslogFields['Type'] = entry.get('Type', "-") 
        syslogFields['ComputerName'] = entry.get('ComputerName', "-") 
        syslogFields['TaskCategory'] = entry.get('TaskCategory', "-") 
        syslogFields['OpCode'] = entry.get('OpCode', "-")
        syslogFields['RecordNumber'] = entry.get('RecordNumber', "-")
        syslogFields['Keywords'] = entry.get('Keywords', "-")
        syslogFields['Message'] = entry.get('Message', "-")
        
        toSend = header
        for k,v in syslogFields.items():
            toSend = toSend + k + "=" +  v + "\r\n"

        logs = syslogClient.send(str(toSend), syslog_client.Level.WARNING)
        helper.log_info(logs)
    return 0
    
    
