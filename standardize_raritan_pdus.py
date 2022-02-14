#!/usr/bin/python3

import sys, time
sys.path.append("pdu-python-api")
from raritan.rpc import Agent, pdumodel, firmware, cfg, devsettings, event, datetime, usermgmt

# Configuration Examples
# set pass: https://github.com/ChinaClever/ScalePoint/blob/7afc833dffbf4ed6504c607594f285ebfba482f1/pys/pdu-python-api/py_fvt_node_test.py
# set snmp: https://github.com/andycranston/raritan-setsnmpv3/blob/515ab39ea17cc32d376bf533849b3736c7e474c4/setsnmpv3.py
# rules & actions: https://github.com/tijuca/raritan-pdu-json-rpc-sdk/blob/d516e8e8c4fcabb52c7ec87c1dd0dc8e78cde700/python-idl-example.py
# https://help.raritan.com/json-rpc/pdu/v3.6.1/devsettings.html


# CONTROLS
fetch_pdu_assets = False
update_snmp_settings = True
update_event_actions = True
update_event_rules = True

# CREDENTIALS & SETTINGS (old)
user = "admin"
pw = "oldpassword"

# CREDENTIALS & SETTINGS (new)
new_user = "admin"
new_pw = "newpassword"
new_snmp_ro_community = "newstring"
new_snmp_sysContact = "newcontact"
new_syslog_target = "192.168.255.40"
new_syslog_port = "1514"




def fetch_outlet_sensors(outlet):
    outlet_sensors = outlet.getSensors()
    outlet_metadata = outlet.getMetaData()
    outlet_settings = outlet.getSettings()
    print ("Outlet %s:" % (format(outlet_metadata.label)))
    print ("Name: %s" % (outlet_settings.name if outlet_settings.name != "" else "(none)"))
    print ("Switchable: %s" % ("yes" if outlet_metadata.isSwitchable else "no"))
    if outlet_sensors.voltage:
        sensor_reading = outlet_sensors.voltage.getReading()
        print ("  Voltage: %s" % (("%d V" % (sensor_reading.value)) if sensor_reading.valid else "n/a"))
    if outlet_sensors.current:
        sensor_reading = outlet_sensors.current.getReading()
        print ("  Current: %s" % (("%d A" % (sensor_reading.value)) if sensor_reading.valid else "n/a"))
    if outlet_metadata.isSwitchable:
        outlet_state_sensor = outlet_sensors.outletState
        outlet_state = outlet_state_sensor.getState()
        if outlet_state.available:
            print ("  Status :%s" % ("on" if outlet_state.value == outlet_state_sensor.OnOffState.ON.val else "off"))


def changeDefaultPassword(agent):
    print('\n\nUpdating Default Password...')
    try:
      # Update Default password
        user_proxy = usermgmt.User("/auth/user/admin", agent)
        idlRet = user_proxy.setAccountPassword(new_pw)
        print(idlRet)
        time.sleep(1)
    except:
        print('ERROR UPDATING PASSWORD')
        exit()




def apply_pdu_standards(pdu_list):

    could_not_login_list = []
    success_list = []

  # ITERATE HOSTS
    for ip in pdu_list:
        print('\n\nFetching PDU settings for %s...' % (ip))
        agent = Agent("https", ip, user, pw, disable_certificate_verification=True)

      # ATTEMPT LOGIN & FETCH EXISTING SETTINGS
        try:
            pdu = pdumodel.Pdu('/model/pdu/0', agent)
            settings = pdu.getSettings()
            print('Successfully retrieved current PDU settings.')
            print("settings: %s" % (settings))

          # FETCH PDU FIRMWARE
            firmware_proxy = firmware.Firmware("/firmware", agent)
            print ("Firmware version: %s" % (firmware_proxy.getVersion()))

          # FETCH PDU ASSETS
            if fetch_pdu_assets == True:
                print('\n\nFetching PDU Assets...')
                inlets = pdu.getInlets()
                print("Inlets: %s" % (len(inlets)))
                ocps = pdu.getOverCurrentProtectors()
                print("ocps: %s" % (len(ocps)))
                outlets = pdu.getOutlets()
                print("Outlets: %s" % (len(outlets)))
                for outlet in outlets:
                    fetch_outlet_sensors(outlet)

       ## FETCH PDU NTP ##
            print('\n\nFetching PDU NTP config...')
            ntp_proxy = datetime.DateTime("/datetime", agent)
            print("Current NTP settings: %s" % (ntp_proxy.getCfg()))

       ## APPLY STANDARD EVENT ACTIONS ##
            event_proxy = event.Engine("/event_engine", agent)
            print('\n\nFetching PDU event Actions...')
            existing_syslog_settings_name = None
            for existing_action in event_proxy.listActions():
                if existing_action.name == 'send_syslog':
                    existing_syslog_settings_name = existing_action.name
                    print(existing_action.id)
                    print(existing_action.name)
                    print(existing_action.isSystem)
                    print(existing_action.type)
                    for argument in existing_action.arguments:
                        print(argument)
            standard_syslog_settings = event.Engine.Action(
                id = 'Action_001',
                name = 'send_syslog',
                isSystem = False,
                type = 'Syslogmessage',
                arguments = [
                    event.KeyValue('SyslogServerName', new_syslog_target),
                    event.KeyValue('SyslogServerUseTcp', '0'),
                    event.KeyValue('SyslogServerUseTls', '0'),
                    event.KeyValue('SyslogServerNoBsdCompat', '0'),
                    event.KeyValue('SyslogServerCaCertChain', ''),
                    event.KeyValue('SyslogServerAllowOffTimeRangeCerts', '0'),
                    event.KeyValue('SyslogServerPort', new_syslog_port)
                ]
            )
            if standard_syslog_settings.name == existing_syslog_settings_name:
                print("standard_syslog_settings == existing_syslog_settings")
            else:
                if update_event_actions == True:
                    print('Creating new syslog event action ...')
                    ret, action_id = event_proxy.addAction(standard_syslog_settings)
                    if ret == 0:
                        print('Action successfully created; id = ', action_id)
                    else:
                        print('event.Engine.addAction() failed: ret = ', ret)
                        sys.exit(1)


       ## APPLY STANDARD EVENT RULES ##
            print('\n\nFetching PDU event Rules...')
            existing_syslog_rule_name = None
            for existing_rule in event_proxy.listRules():
                if existing_rule.name == 'send_syslog_rule':
                    existing_syslog_rule_name = existing_rule.name
                    print(existing_rule.id)
                    print(existing_rule.name)
                    print(existing_rule.isSystem)
                    print(existing_rule.isEnabled)
                    print(existing_rule.isAutoRearm)
                    print(existing_rule.hasMatched)
                    print(existing_rule.condition)
                    print(existing_rule.actionIds)
                    print(existing_rule.arguments)
            standard_syslog_rule = event.Engine.Rule(
                id = 'Rule_001',
                name = 'send_syslog_rule',
                isSystem = False,
                isEnabled = True,
                isAutoRearm = True,
                hasMatched = False,
                condition = event.Engine.Condition(
                    negate = False,
                    operation = event.Engine.Condition.Op.AND,
                    matchType = event.Engine.Condition.MatchType.BOTH,
                    eventId = [ '**' ],
                    conditions = []
                ),
                actionIds = [ 'Action_001' ],
                arguments = []
            )
            if standard_syslog_rule.name == existing_syslog_rule_name:
                print("standard_syslog_rule == existing_syslog_rule")
            else:
                print(standard_syslog_rule.name, existing_syslog_rule_name)
                if update_event_rules == True:
                    print('Creating new syslog event rule ...')
                    ret, rule_id = event_proxy.addRule(standard_syslog_rule)
                    if ret == 0:
                        print('Rule successfully created; id = ', rule_id)
                    elif ret == 1:
                        print('event.Engine.addRule() failed: rule already exisits.')
                    else:
                        print('event.Engine.addRule() failed: ret = ', ret)
                        sys.exit(1)


         ## APPLY STANDARD SNMP SETTINGS ##
            print('\n\nFetching SNMP Settings')
            snmp_proxy = devsettings.Snmp('/snmp', agent)
            current_snmp_settings = snmp_proxy.getConfiguration()
            print("EXISTING snmp config: %s" % (current_snmp_settings))
            standard_snmp_settings = devsettings.Snmp.Configuration(
                v2enable = True,
                v3enable = False,
                readComm = new_snmp_ro_community,
                writeComm = '',
                sysContact = new_snmp_sysContact,
                sysName = '',
                sysLocation = ''
            )
            print("STANDARD snmp config: %s" % (standard_snmp_settings))
            if standard_snmp_settings != current_snmp_settings:
                if update_snmp_settings == True:
                    print('Updating SNMP agent settings ...')
                    snmp_proxy = devsettings.Snmp('/snmp', agent)
                    ret = snmp_proxy.setConfiguration(standard_snmp_settings)
                    if ret == 0:
                        print('SNMP agent settings successfully updated.')
                    else:
                        print('Snmp.setConfiguration() failed: ret = ', ret)
                        sys.exit(1)
            else:
                print("current_snmp_settings = standard_snmp_settings, Skipping action")
            print("DONE \n\n")


         ## APPLY STANDARD PASSWORD ##
            changeDefaultPassword(agent)

         ## ADD IP TO SUCCESSFULLY UPDATED HOST LIST
            success_list.append(ip)

        except:
            print("COULD NOT LOGIN TO %s USING DEFAULT CREDENTIALS" % (ip))
            could_not_login_list.append(ip)

    result_dict = {'success_list' : success_list, 'could_not_login_list' : could_not_login_list}
    return(result_dict)



if __name__ == "__main__":
    pdu_list = ["1.1.1.1", "2.2.2.2"]
    result_dict = apply_pdu_standards(pdu_list)
    print(result_dict)
