import napalm
from getpass import getpass
from ciscoconfparse import CiscoConfParse
from pprint import pprint
import csv

class Connection:
    def __init__(self, hostname, operating_system, username, password):
        self.hostname = hostname
        self.operating_system = operating_system
        self.username = username
        self.password = password
        self.napalm_driver = napalm.get_network_driver(operating_system)
        self.napalm_connection = self.napalm_driver(hostname, username, password)
        self.facts = self.get_facts() 
        self.config = self.get_config()
    def get_facts(self):
        self.napalm_connection.open()
        facts = self.napalm_connection.get_facts()
        self.napalm_connection.close()
        return facts
    def get_config(self):
        self.napalm_connection.open()
        config = self.napalm_connection.get_config()
        self.napalm_connection.close()
        return config
  

class Configuration:
    def __init__(self, hostname, operating_system, configuration):
        self.hostname = str(hostname)
        self.operating_system = str(operating_system)
        self.configuration = configuration
        self.save_config()
        self.parsed_config = CiscoConfParse(str(self.hostname) + '.conf', syntax=self.operating_system)
    def save_config(self):
        with open(str(self.hostname) + '.conf', 'w') as f:
            f.write(self.configuration['running'])


def check_aaa_new_model(parsed_config):
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
    aaa_new_model = parsed_config.find_objects('^aaa new-model')
    no_aaa_new_model = parsed_config.find_objects('^no aaa new-model')
    print(aaa_new_model)
    if aaa_new_model != [] and no_aaa_new_model == []:
        print('aaa new-model is in compliance\n\n')
    elif aaa_new_model == [] and no_aaa_new_model != []:
        print('aaa new-model is NOT in compliance\n\n')


def check_aaa_authentication_login(parsed_config):
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
    aaa_authentication_login = parsed_config.find_objects('^aaa authentication login')
    print(aaa_authentication_login)
    if aaa_authentication_login != []:
        print('aaa authentication login is in compliance\n\n')
    elif aaa_authentication_login == []:
        print('aaa authentication login is NOT in compliance\n\n')


def check_aaa_authentication_enable_default(parsed_config):
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
    aaa_authentication_enable = parsed_config.find_objects('^aaa authentication enable')
    print(aaa_authentication_enable)
    if aaa_authentication_enable != []:
        print('aaa authentication enable is in compliance\n\n')
    elif aaa_authentication_enable == []:
        print('aaa authentication enable is NOT in compliance\n\n')


def check_line_con_0_authentication(parsed_config):
    '''
    Description:
    Authenticates users who access the router or switch using the serial console port.

    Rationale:
    Using AAA authentication for interactive management access to the device provides
    consistent, centralized control of your network. The default under AAA (local or network)
    is to require users to log in using a valid user name and password. This rule applies for
    both local and network AAA.

    Audit:
    Perform the following to determine if AAA authentication for line login is enabled:
    If the command does not return a result for each management access method, the feature is
    not enabled
    hostname#show running-config | sec line | incl login authentication
    '''
    print('check line con 0 authentication')
    line_con_auth = parsed_config.find_objects_w_parents(parentspec='^line con', childspec='^ login auth')
    print(line_con_auth)
    if line_con_auth != []:
        print('line con 0 authenctication is in compliance\n\n')
    else:
        print('line con 0 authenctication is NOT in compliance\n\n')


def check_line_vty_authentication(parsed_config):
    '''
    Description:
    Authenticates users who access the router or switch using the TTY port.

    Rationale:
    Using AAA authentication for interactive management access to the device provides
    consistent, centralized control of your network. The default under AAA (local or network)
    is to require users to log in using a valid user name and password. This rule applies for
    both local and network AAA.

    Audit:
    Perform the following to determine if AAA authentication for line login is enabled:
    If the command does not return a result for each management access method, the feature is
    not enabled
    hostname#show running-config | sec line | incl login authentication
    '''
    print('check line vty authentication')
    line_vty_auth = parsed_config.find_objects_w_parents(parentspec='^line vty 0', childspec='^ login auth')
    if line_vty_auth != []:
        print(line_vty_auth)
        print('line vty authenctication is in compliance\n\n')
    else:
        print('line vty authenctication is NOT in compliance\n\n')


def check_line_vty_5_authentication(parsed_config):
    '''
    Description:
    Authenticates users who access the router or switch using the TTY port.

    Rationale:
    Using AAA authentication for interactive management access to the device provides
    consistent, centralized control of your network. The default under AAA (local or network)
    is to require users to log in using a valid user name and password. This rule applies for
    both local and network AAA.

    Audit:
    Perform the following to determine if AAA authentication for line login is enabled:
    If the command does not return a result for each management access method, the feature is
    not enabled
    hostname#show running-config | sec line | incl login authentication
    '''
    print('check line vty 5+ authentication')
    line_vty_auth = parsed_config.find_objects_w_parents(parentspec='^line vty 5', childspec='^ login auth')
    if line_vty_auth != []:
        print(line_vty_auth)
        print('line vty 5+ authenctication is in compliance\n\n')
    else:
        print('line vty 5+ authenctication is NOT in compliance\n\n')


def check_http_auth(parsed_config):
    '''
    Description:
    If account management functions are not automatically enforced, an attacker could gain
    privileged access to a vital element of the network security architecture

    Rationale:
    Using AAA authentication for interactive management access to the device provides
    consistent, centralized control of your network. The default under AAA (local or network)
    is to require users to log in using a valid user name and password. This rule applies for
    both local and network AAA.

    Audit:
    Perform the following to determine if AAA authentication for line login is enabled:
    If the command does not return a result for each management access method, the feature is
    not enabled
    hostname#show running-config | inc ip http authentication
    '''
    print('check http auth')
    if (parsed_config.find_objects('^ip http server') or parsed_config.find_objects('^ip http secure-server')) != []:
        if 'ip http authentication' in (parsed_config.find_objects('^ip http auth')):
            print(parsed_config.find_objects('^ip http auth'))
            print('http auth is in compliance\n\n')
        else:
            print('http auth is NOT in compliance\n\n')
    else:
        print('http(s) server not configured\n\n')


def check_aaa_accounting(parsed_config):
    '''
    Description:
    Runs accounting for all commands at the specified privilege level.

    Rationale:
    Authentication, authorization and accounting (AAA) systems provide an authoritative
    source for managing and monitoring access for devices. Centralizing control improves
    consistency of access control, the services that may be accessed once authenticated and
    accountability by tracking services accessed. Additionally, centralizing access control
    simplifies and reduces administrative costs of account provisioning and de-provisioning,
    especially when managing a large number of devices. AAA Accounting provides a
    management and audit trail for user and administrative sessions through RADIUS or
    TACACS+.

    Audit:
    Perform the following to determine if aaa accounting for commands is required:
    Verify a command string result returns
    hostname#show running-config | incl aaa accounting commands
    '''
    print('aaa accounting check')
    aaa_accounting = parsed_config.find_objects('^aaa accounting commands')
    print(aaa_accounting)
    if aaa_accounting != []:
        print('aaa accounting is in compliance\n\n')
    elif aaa_accounting == []:
        print('aaa accounting is NOT in compliance\n\n')


def check_aaa_accounting_connection(parsed_config):
    '''
    Description:
    Provides information about all outbound connections made from the network access
    server.

    Rationale:
    Authentication, authorization and accounting (AAA) systems provide an authoritative
    source for managing and monitoring access for devices. Centralizing control improves
    consistency of access control, the services that may be accessed once authenticated and
    accountability by tracking services accessed. Additionally, centralizing access control
    simplifies and reduces administrative costs of account provisioning and de-provisioning,
    especially when managing a large number of devices. AAA Accounting provides a
    management and audit trail for user and administrative sessions through RADIUS and
    TACACS+.

    Audit:
    Perform the following to determine if aaa accounting for connection is required:
    Verify a command string result returns
    hostname#show running-config | incl aaa accounting connection
    '''
    print('aaa accounting connection check')
    aaa_accounting_connection = parsed_config.find_objects('^aaa accounting connection')
    print(aaa_accounting_connection)
    if aaa_accounting_connection != []:
        print('aaa accounting connection is in compliance\n\n')
    elif aaa_accounting_connection == []:
        print('aaa accounting connection is NOT in compliance\n\n')


def main():
    with open('devices.csv') as csv_file:
        csv_dict = csv.DictReader(csv_file, delimiter=',')
        devices = []
        for row in csv_dict:
            devices.append(row)

    for device in devices:
        device_connection = Connection(device['hostname'], device['operating_system'], device['username'], device['password'])
        device_configuration = Configuration(device_connection.hostname, device_connection.operating_system, device_connection.config)
        check_aaa_new_model(device_configuration.parsed_config)
        check_aaa_authentication_login(device_configuration.parsed_config)
        check_aaa_authentication_enable_default(device_configuration.parsed_config)
        check_line_con_0_authentication(device_configuration.parsed_config)
        check_line_vty_authentication(device_configuration.parsed_config)
        check_line_vty_5_authentication(device_configuration.parsed_config)
        check_http_auth(device_configuration.parsed_config)
        check_aaa_accounting(device_configuration.parsed_config)
        check_aaa_accounting_connection(device_configuration.parsed_config)


if __name__ == "__main__":
    main()
