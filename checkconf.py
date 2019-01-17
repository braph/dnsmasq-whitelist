#!/usr/bin/python3

import os
from conf    import *
from common  import *
from dnsmasq import parse_dnsmasq_config

class CheckConf():
    '''
        Class for checking configuration.
    '''

    # Option in dnsmasq.conf
    _opt    = None

    # Messages that are displayed.
    # If not set, a generic message will be used.
    # Overwrite `error()`, `ask()`, `desc()` to display a dynamic message.
    _error  = None
    _ask    = None
    _desc   = None

    def __init__(self, conf, options):
        self.conf    = conf
        self.options = options

    def conf_insert(self, line):
        with open(self.conf.dnsmasq_conf, 'a') as fh:
            fh.write('%-50s # dnsmasq-whitelist\n' % (line))

    def error(self):
        if self._error:
            return self._error
        else:
            return 'Option `%s` not set in dnsmasq.conf' % (self._opt)

    def ask(self):
        if self._ask:
            return self._ask
        else:
            return 'Set `%s`?' % (self._opt)

    def desc(self):
        if self._desc:
            return self._desc
        else:
            return 'No description available'


class CheckLogFacility(CheckConf): 
    _opt  = 'log-facility'
    _desc = 'This option makes dnsmasq write to a log file'

    def check(self):
        return 'log-facility' in self.options

    def fix(self):
        f = read_default('Enter filename for dnsmasq log', '/var/log/dnsmasq.log')
        self.conf_insert('log-facility=' + f)


class CheckLogQueries(CheckConf):
    _opt = 'log-queries'
    _desc = 'This option makes dnsmasq log incoming dns queries'

    def check(self):
        return 'log-queries' in self.options

    def fix(self):
        self.conf_insert('log-queries')


class CheckAddress(CheckConf):
    _opt =  'address'
    _desc = 'This option is used for blocking incoming queries by default'

    def check(self):
        self.hash_addresses = list(filter(lambda o: '/#/' in o.value,
                                    self.options.get('address', ())))
        return self.hash_addresses

    def fix(self):
        self.conf_insert('address=/#/' + self.conf.ip_auto_blocked)


class CheckConfFileExistence(CheckConf):
    _opt = 'conf-file'
    _ask = 'Create file (with subdirectories) ?'

    def __init__(self, conf, options, file, option):
        super().__init__(conf, options)
        self.file = file
        self.option = option

    def check(self):
        return os.path.exists(self.file)

    def error(self):
        return 'Config file `%s` does not exist in filesystem' % (self.file)

    def fix(self):
        os.makedirs(os.path.dirname(self.file), exist_ok=True)
        with open(self.file, 'w') as fh:
            fh.write('# created by dnsmasq-whitelist\n')


class CheckConfFileIncluded(CheckConf):
    _opt = 'conf-file'

    def __init__(self, conf, options, file, option):
        super().__init__(conf, options)
        self.file = file
        self.option = option

    def check(self):
        conf_file_opts = self.options.get('conf-file', ())
        return any(filter(lambda o: o.value == self.file, conf_file_opts))

    def error(self):
        return 'Missing option `conf-file` for --%s (%s)' % (self.option, self.file)

    def fix(self):
        self.conf_insert("conf-file=%s" % (self.file))


def check_dnsmasq_conf(conf):
    '''
        Check dnsmasq.conf.
        Return True if restart is needed.
    '''

    all_fixed = True
    need_restart = False
    check_objs = []
    check_classes = (
        (CheckLogFacility,),
        (CheckLogQueries,),
        (CheckAddress,),
        (CheckConfFileIncluded,  conf.allow_file, 'allow-file'),
        (CheckConfFileIncluded,  conf.block_file, 'block-file'),
        (CheckConfFileExistence, conf.allow_file, 'allow-file'),
        (CheckConfFileExistence, conf.block_file, 'block-file')
    )

    needed_dnsmasq_options = list(map(lambda t: t[0]._opt, check_classes))
    options = parse_dnsmasq_config(conf.dnsmasq_conf, needed_dnsmasq_options)

    for check_class in check_classes:
        check_obj = check_class[0](conf, options, *(check_class[1:]))

        if not check_obj.check():
            check_objs.append(check_obj)

    if check_objs:
        need_restart = True
        print("There have been found some configuration.\n")
        for check_obj in check_objs:
            print('-', check_obj.error())
            print(' (%s)' % (check_obj.desc()))
            print()
            #_desc = check_obj.desc()
            #if _desc:
            #    print('   ', _desc)

        p = ' [a]uto fix all, [m]anually fix, [q]uit'
        r = read_prompt_with_choices(p)
        if r == 'm':
            for check_obj in check_objs:
                print()
                print(check_obj.error())
                print(check_obj.desc())
                if read_yes_no(check_obj.ask()):
                    check_obj.fix()
                else:
                    all_fixed = False

        elif r == 'a':
            for check_obj in check_objs:
                check_obj.fix()
        elif r == 'q':
            raise KeyboardInterrupt()

    if not all_fixed:
        raise ConfigException("Not all configuration problems have been fixed.\n" +
                              "Please fix them manually or start me again.")
    return need_restart


def check_user_conf(conf):
    def die(s):
        raise ConfigException(s + ' (check your config file and command line options)')

    e = "Options --allow-file and --block-file must be different"
    if conf.allow_file == conf.block_file:
        die(e)

    e = 'Options --dnsmasq-conf and --allow-file must be different'
    if conf.dnsmasq_conf == conf.allow_file:
        die(e)

    e = 'Options --dnsmasq-conf and --block-file must be different'
    if conf.dnsmasq_conf == conf.block_file:
        die(e)
