#!/usr/bin/python3

class ConfigException(Exception):
    pass

class Config():
    '''
        Holds configuration.
        Dict-like access is supported.
        Keys that contain hyphens are also valid ('dns-server' becomes 'dns_server')
    '''

    __slots__ = (
        'dnsmasq_conf',
        'dnsmasq_restart_cmd',
        'dns_server',
        'ip_blacklisted',
        'ip_auto_blocked',
        'blacklist_file',
        'whitelist_file',
        'drop_after',
        'load_log_lines',
        'dateformat',
        'default_command',

        'dnsmasq_logfile' # actually not a user option
    )

    def __getitem__(self, key):
        try:
            return self.__getattribute__(key)
        except:
            return self.__getattribute__(key.replace('-', '_'))

    def __setitem__(self, key, value):
        if '-' in key:
            key = key.replace('-', '_')
        return self.__setattr__(key, value)

    def __contains__(self, key):
        if '-' in key:
            key = key.replace('-', '_')
        return key in self.__slots__
        
