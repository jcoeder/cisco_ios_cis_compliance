from napalm import get_network_driver
from getpass import getpass
from ciscoconfparse import CiscoConfParse
from pprint import pprint

#hostname = input('IP or Hostname: ')
#username = input('Username: ')
#password = getpass()

ios_driver = get_network_driver('ios')
device = ios_driver(hostname, username, password)

# Open connection to the device
#device.open()

# Gather information from device
#facts = device.get_facts()
#config = device.get_config()

# Save config to a file for CiscoConfParse
#with open('config.conf', 'w') as f:
#    f.write(config['running'])

# Close connection to the device
#device.close()

# Initialized the parsed configuration
parse = CiscoConfParse('config.conf', syntax='ios')


def conf_parse_object_to_list(parse_object):
    conf_parse_list = []
    for item in parse_object:
        conf_parse_list.append(item.text)
    return conf_parse_list


#def check_aaa_new_model():
#    print('check aaa new-model')
#    aaa_new_model = parse.find_objects('^aaa new-model')
#    aaa_new_model_list = conf_parse_object_to_list(aaa_new_model)
#    if 'aaa new-model' in aaa_new_model_list:
#        print('aaa new-model is in compliance\n\n')
#    elif 'no aaa new-model' in aaa_new_model_list:
#        print('aaa new-model is NOT in compliance\n\n')
#    elif aaa_new_model_list == []:
#        print('aaa new-model is NOT in compliance\n\n')
#    else:
#        print('aaa new-model complaince could not be determined\n\n')

def check_aaa_new_model():
    '''
    Description:
    This command enables the AAA access control system.
    
    Rationale:
    Authentication, authorization and accounting (AAA) services provide an authoritative
    source for managing and monitoring access for devices. Centralizing control improves
    consistency of access control, the services that may be accessed once authenticated and
    accountability by tracking services accessed. Additionally, centralizing access control
    simplifies and reduces administrative costs of account provisioning and de-provisioning,
    especially when managing a large number of devices.
    
    Audit:
    Perform the following to determine if AAA services are enabled:
    hostname#show running-config | inc aaa new-model
    '''
    print('check aaa new-model')
    aaa_new_model = parse.find_objects('^aaa new-model')
    no_aaa_new_model = parse.find_objects('^no aaa new-model')
    print(aaa_new_model)
    if aaa_new_model != [] and no_aaa_new_model == []:
        print('aaa new-model is in compliance\n\n')
    elif aaa_new_model == [] and no_aaa_new_model != []:
        print('aaa new-model is NOT in compliance\n\n')


def check_aaa_authentication_login():
    '''
    Description:
    Sets authentication, authorization and accounting (AAA) authentication at login.

    Rationale:
    Using AAA authentication for interactive management access to the device provides
    consistent, centralized control of your network. The default under AAA (local or network)
    is to require users to log in using a valid user name and password. This rule applies for
    both local and network AAA. Fallback mode should also be enabled to allow emergency
    access to the router or switch in the event that the AAA server was unreachable, by
    utilizing the LOCAL keyword after the AAA server-tag.

    Audit:
    Perform the following to determine if AAA authentication for login is enabled:
    hostname#show running-config | incl aaa authentication login
    '''
    print('check aaa authentication login')
    aaa_authentication_login = parse.find_objects('^aaa authentication login')
    print(aaa_authentication_login)
    if aaa_authentication_login != []:
        print('aaa authentication login is in compliance\n\n')
    elif aaa_authentication_login == []:
        print('aaa authentication login is NOT in compliance\n\n')


def check_aaa_authentication_enable_default():
    '''
    Description:
    Authenticates users who access privileged EXEC mode when they use the enable command.

    Rationale:
    Using AAA authentication for interactive management access to the device provides
    consistent, centralized control of your network. The default under AAA (local or network)
    is to require users to log in using a valid user name and password. This rule applies for
    both local and network AAA.

    Audit:
    Perform the following to determine if AAA authentication enable mode is enabled:
    hostname#show running-config | incl aaa authentication enable
    '''
    print('check aaa authentication enable default')
    aaa_authentication_enable = parse.find_objects('^aaa authentication enable')
    if aaa_authentication_enable != []:
        print('aaa authentication enable is in compliance\n\n')
    elif aaa_authentication_enable == []:
        print('aaa authentication enable is NOT in compliance\n\n')


def check_line_con_0_authentication():
    print('check line con 0 authentication')
    line_con_auth = parse.find_objects_w_parents(parentspec='^line con', childspec='^ login auth')
    if line_con_auth != []:
        print(line_con_auth)
        print('line con 0 authenctication is in compliance\n\n')
    else:
        print('line con 0 authenctication is NOT in compliance\n\n')


def check_line_vty_authentication():
    print('check line vty authentication')
    line_vty_auth = parse.find_objects_w_parents(parentspec='^line vty 0', childspec='^ login auth')
    if line_vty_auth != []:
        print(line_vty_auth)
        print('line vty authenctication is in compliance\n\n')
    else:
        print('line vty authenctication is NOT in compliance\n\n')


def check_line_vty_5_authentication():
    print('check line vty 5+ authentication')
    line_vty_auth = parse.find_objects_w_parents(parentspec='^line vty 5', childspec='^ login auth')
    if line_vty_auth != []:
        print(line_vty_auth)
        print('line vty 5+ authenctication is in compliance\n\n')
    else:
        print('line vty 5+ authenctication is NOT in compliance\n\n')


def check_http_auth():
    print('check http auth')
    if (parse.find_objects('^ip http server') or parse.find_objects('^ip http secure-server')) != []:
        if 'ip http authentication' in (parse.find_objects('^ip http auth')):
            print('http auth is in compliance\n\n')
        else:
            print('http auth is NOT in compliance\n\n')
    else:
        print('http(s) server not configured\n\n')



check_aaa_new_model()
check_aaa_authentication_login()
check_aaa_authentication_enable_default()
check_line_con_0_authentication()
check_line_vty_authentication()
check_line_vty_5_authentication()
check_http_auth()
