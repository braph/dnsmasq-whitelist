#!/usr/bin/python3

import shlex
import tempfile
import argparse
import readline
import traceback
import configparser
import os, re, sys, datetime, time

from enum           import Enum
from shutil         import copy
from fnmatch        import fnmatch
from itertools      import groupby, chain
from threading      import Thread, Lock
from operator       import itemgetter, attrgetter, methodcaller as mCaller

from conf           import *
from dnsmasq        import *
from common         import *
from checkconf      import check_dnsmasq_conf, check_user_conf

# Global configuration
conf = Config()
conf.dnsmasq_conf        = '/etc/dnsmasq.conf'
conf.dnsmasq_restart_cmd = 'systemctl restart dnsmasq'
conf.dns_server          = '8.8.4.4'
conf.ip_manual_blocked   = '127.0.0.2'
conf.ip_auto_blocked     = '127.0.0.1'
conf.block_file          = '/etc/dnsmasq.d/dnsmasq_block.conf'
conf.allow_file          = '/etc/dnsmasq.d/dnsmasq_allow.conf'
conf.drop_after          = 36000
conf.load_log_lines      = 1000

# We keep our automatically blocked domains here
blocked_domains = dict()
blocked_lock = Lock()

# Available commands/aliases reside in this dicts. (see command())
commands = {}
command_aliases = {}

# read_dnsmasg_log() reads from this handle.
# We use this handle also to signal the program exit to the thread.
logfile_fh = None 

def dnsmasq_restart():
    os.system(conf.dnsmasq_restart_cmd)

def read_dnsmasg_log(fh, conf, lock, blocked_domains):
    months = ( 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
               'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec' )
    year = datetime.datetime.now().year

    # Jan 15 18:00:03 dnsmasq[15814]: config blabla.de is 127.0.0.1
    # Jan 15 18:00:03 dnsmasq[15814]: config blabla.de is ::
    # Jan 14 18:11:03 dnsmasq[5693]: reply proxy.duckduckgo.com is <CNAME>
    # Jan 14 18:11:03 dnsmasq[5693]: reply icons.duckduckgo.com is 54.75.239.212
    # Jan 16 01:24:03 dnsmasq[2377]: config isblocked.net is NODATA-IPv6

    def parse_line(line):
        month, day, clock, _, *parts = line.strip().split(' ')

        if parts[-2] == 'is':
            ip = parts[-1]
            domain = parts[-3]
            #print(ip)

            # Automatically blocked domain
            if ip == conf.ip_auto_blocked:
                state = DomainState.AutoBlocked
                hour, minute, second = clock.split(':')
                date = datetime.datetime(
                    year=year, month=(months.index(month) + 1), day=int(day),
                    hour=int(hour), minute=int(minute), second=int(second)
                )

                with use_lock(lock):
                    blocked_domains[domain] = date
            # Manual blocked domain
            elif ip == conf.ip_manual_blocked:
                with use_lock(lock):
                    blocked_domains.pop(domain, None)
            # Does not contain NODATA -> is valid IP -> Allowed
            elif 'NODATA' not in ip:
                with use_lock(lock):
                    blocked_domains.pop(domain, None)
            # Is NODATA, do nothing
            else:
                return

    if conf.load_log_lines == 0:
        fh.read(-1)
    else:
        lines = fh.readlines()
        if conf.load_log_lines != -1: # limit to latest lines
            lines = lines[(-1 * conf.load_log_lines):]
        
        for line in lines:
            parse_line(line)

        patterns, domains = filter01(lambda d: '*' in d,
            map(lambda d: d.domain, 
                chain(
                        read_dnsmasq_allowed(conf.allow_file),
                        read_dnsmasq_blocked(conf.block_file),
                )
            )
        )

        with use_lock(lock):
            for domain in domains:
                if blocked_domains.pop(domain, None):
                    pass #print('popped by name', domain)

            for domain in list(blocked_domains.keys()):
                for pattern in patterns:
                    if fnmatch(domain, pattern):
                        #print('poped by pattern', domain, pattern)
                        blocked_domains.pop(domain, None)

    while True:
        try:
            line = fh.readline()

            if line:
                parse_line(line)
            else:
                time.sleep(1)
        except:
            print('Log-Reading-Thread exited')
            return 

def read_dnsmasq_allowed(conf_file):
    return map(
        DnsMasqAllowedDomain.fromOption,
        parse_dnsmasq_config_yield(conf_file, ('server',))
    )

def read_dnsmasq_blocked(conf_file):
    return map(
        DnsMasqBlockedDomain.fromOption,
        parse_dnsmasq_config_yield(conf_file, ('address',))
    )

def get_from_mappings(mappings, key):
    return mappings[int(key) - 1]

def get_domains_from_args(mappings, args):
    domains = []
    for index in args:
        try:
            domains.append(get_from_mappings(mappings, index))
        except IndexError:
            raise Exception("Invalid index: " + index)
        except ValueError:
            if valid_domain(index):
                domains.append(index)
            else:
                raise Exception("Not a valid domain: " + index)
    return domains

def command(name, short_desc, long_desc):
    def decorate(f):
        commands[name] = f
        #for alias in aliases: 
        #    command_aliases[alias] = f

        f.name = name
        f.short_desc = short_desc
        f.long_desc = long_desc

        return f
    return decorate

@command('show-blocked', 'show automatically blocked domains', '''
    Shows the domains that have been automatically blacklisted.
''')
def cmd_show_blocked(args):
    with use_lock(blocked_lock):
        now = datetime.datetime.now()

        new_blocked = []

        for domain in list(blocked_domains.keys()):
            delta = now - blocked_domains[domain]
            delta = delta.total_seconds()

            if delta > conf.drop_after:
                blocked_domains.pop(domain)
            else:
                new_blocked.append(
                    (domain, blocked_domains[domain].replace(second=0, microsecond=0))
                )
        
        new_blocked.sort(key=itemgetter(0)) # sort by domain name
        new_blocked.sort(key=itemgetter(1)) # sort by date
        counter = len(new_blocked)
        new_blocked = groupby(new_blocked, key=itemgetter(1))

        mappings = []

        for date, domains in new_blocked:
            print(date, end='  ')
            domain = next(domains)[0]
            mappings.append( domain )
            print('%2d) %s' % (counter, domain))
            counter -= 1

            for domain, _ in domains:
                print('                     %2d) %s' % (counter, domain))

                mappings.append(  domain )
                counter -= 1

        mappings.reverse()
        return mappings

@command('allow', 'whitelist domains', '''
    Allowing means to whitelist the specified domain.

    Example:

        Allow domains by index 3 and 42 and 'wanted.com':

        > allow 3 32 wanted.com
''')
def cmd_allow(mappings, args):
    if not args:
        return print("allow: missing arguments")

    options, args = getopts_short('t', args)
    temp = options['t']
    domains = get_domains_from_args(mappings, args)

    with open(conf.allow_file, 'a') as fh:
        for domain in domains:
            try:
                print('allowing', domain)
                d = DnsMasqAllowedDomain(domain, conf.dns_server, temp=temp)
                fh.write(d.getConfStr() + '\n')

                with use_lock(blocked_lock):
                    if '*' in domain: # TODO: Performance?
                        for d in list(blocked_domains.keys()):
                            if fnmatch(d, domain):
                                blocked_domains.pop(d, None)
                    else:
                        blocked_domains.pop(domain, None)
            except Exception as e:
                print("Error:", e)

    dnsmasq_restart()


@command('temp', 'temporary whitelist domains', '''
    An alias for `allow -t`
''')
def cmd_temp(mappings, args):
    cmd_allow(mappings, ['-t', *args])


@command('unallow', 'remove domain from whitelist', 'todo')
def cmd_unallow(mapping, args):
    remove_domains = get_domains_from_args(mappings, args)

    with tempfile.NamedTemporaryFile('w', prefix='dnsmasqwl') as tempf:
        domains = read_dnsmasq_allowed(conf.allow_file)
        domains = filter(lambda d: d.domain not in remove_domains, domains)
        #print('remove:', remove_domains)
        #print(list(map(attrgetter('domain'), domains)))
        #return
        domains_as_str = map(lambda d: d.getConfStr() + '\n', domains)
        tempf.file.writelines(domains_as_str)
        tempf.file.flush()
        copy(tempf.name, conf.allow_file)

    dnsmasq_restart()


@command('revoke', 'remove all temporary allowed domains from whitelist', 'todo')
def cmd_revoke(args):
    with tempfile.NamedTemporaryFile('w', prefix='dnsmasqwl') as tempf:
        domains = read_dnsmasq_allowed(conf.allow_file)
        domains = filter(lambda d: d.temp, domains)
        domains_as_str = map(lambda d: d.getConfStr() + '\n', domains)
        tempf.file.writelines(domains_as_str)
        tempf.file.flush()
        copy(tempf.name, conf.allow_file)

    dnsmasq_restart()


@command('block', 'explicitly block a domain', '''
    Blocking a domain means that this domain will not show up in the list again

    Example:
        block domains by index 3 and 42 and 'unwanted.com':
            block 3 42 unwanted.com
''')
def cmd_block(mappings, args):
    if not args:
        return print("block: missing arguments")

    with open(conf.block_file, 'a') as fh:
        for index in args:
            try:
                domain = get_from_mappings(mappings, index)
                print('blocking', domain)
                d = DnsMasqBlockedDomain(domain, conf.ip_manual_blocked)
                fh.write(d.getConfStr() + '\n')
                with use_lock(blocked_lock):
                    blocked_domains.pop(domain, None)
            except IndexError:
                print("Invalid index:", index)
            #except Exception as e:   # TODO
            #    print("Error:", e)

    dnsmasq_restart()


@command('show-allowed', 'show domains that are whitelisted', '''
    List all domains that are currently whitelisted in the dnsmaq.conf
''')
def cmd_show_allowed(args):
    domains = list(read_dnsmasq_allowed(conf.allow_file))
    index   = len(domains)

    for domain in domains:
        print(domain.getIsoDate(), '%d)' % index, domain.domain,
            ('[Temp]' if domain.temp else ''))
        index -= 1

    domains = list(map(attrgetter('domain'), domains))
    domains.reverse()
    return domains
command_aliases['sa'] = cmd_show_allowed


@command('show-user-blocked', 'show domains that are explicitly blacklisted', '''
    List all domains that are explicitly blacklisted in the dnsmasq.conf
''')
def cmd_show_user_blocked(args):
    domains = list(read_dnsmasq_blocked(conf.block_file))
    index   = len(domains)

    for domain in domains:
        print(domain.getIsoDate(), '%d)' % index, domain.domain)
        index -= 1

    domains = list(map(attrgetter('domain'), domains))
    domains.reverse()
    return domains
command_aliases['sub'] = cmd_show_user_blocked


@command('help', 'show help', '''
    Type 'help <command>' for more infos.

    Abbreviated commands are supported:
        `b facebook.com` -> `block facebook.com`

    If an integer or a domain name is typed without a command, these
    arguments will be passed to `allow`:
        `gooddomain.com` -> `allow gooddomain.com`
''')
def cmd_help(args):
    if args:
        for name in args:
            func = resolve_cmd(name)
            if func:
                print('   ', func.name, '-', func.short_desc)
                print('    ', func.long_desc)
            #except KeyError:
            #    print('Command not found:', name)
    else:
        names = list(commands.keys())
        names.sort()

        for name in names:
            func = commands[name]
            print('    %-20s %s' % (name, func.short_desc))
        print(cmd_help.long_desc)


@command('restart', 'restart dnsmasq', '')
def cmd_restart(args):
    dnsmasq_restart()

#@command('dump', 'show confg')

@command('quit', 'quit program', '')
def cmd_quit(args):
    raise KeyboardInterrupt()


def resolve_cmd(cmd):
    try:    return commands[cmd]
    except: pass

    try:    return command_aliases[cmd]
    except: pass

    funcs = []
    for name, func in commands.items():
        if name.startswith(cmd):
            funcs.append(func)

    if not funcs:
        print("No such command: ", cmd)
    elif len(funcs) > 1:
        possible_cmds = ', '.join(map(attrgetter('name'), funcs))
        print("Ambiguous command: %s, could be: %s" % (cmd, possible_cmds))
    else:
        return funcs[0]

def no_command(cmd, args):
    try:
        domains = get_domains_from_args(mappings, (cmd,))
    except:
        return

    domains.extend(get_domains_from_args(mappings, args))
    return domains

try:
    parser = argparse.ArgumentParser(description='whitelist domains using dnsmasq')
    parser.add_argument('--dnsmasq-conf',
        help='dnsmasq configuration file')
    parser.add_argument('--config', default="/etc/dnswhite.ini",
        help='configuration file')
    parser.add_argument('--dns-server',
        help='dns server to forward whitelisted domains')
    parser.add_argument('--drop-after', type=int, metavar='SECONDS',
        help='dont list blocked domains after given timeout')
    parser.add_argument('--load-log-lines', type=int, metavar='N',
        help='read N latest lines from dnsmasq log. 0=disable, -1=all')
    parser.add_argument('--ip-auto-blocked',
        help='ip used for auto blocked domains')
    parser.add_argument('--ip-manual-blocked',
        help='ip used for manual blocked domains')
    args = parser.parse_args().__dict__

    # Parse configuration file
    iniparser = configparser.ConfigParser(dict_type=dict)
    iniparser.read(args.pop('config'))

    # Check for [config] section, check for unknown sections
    sections = iniparser.sections()
    try:
        sections.remove('config')
    except:
        raise ConfigException('[config] section missing')

    if sections:
        raise ConfigException('Unknown sections in config: ', ', '.join(sections))
    del sections

    # Import INI values into conf
    for key, value in iniparser.items('config'):
        try:    key_type = type(conf[key])
        except: raise ConfigException('Unknown option in config: ' + key)
        conf[key] = key_type(value)

    # Overwrite conf with command line arguments
    for key, value in args.items():
        if value is not None:
            conf[key] = value

    # Check conf
    check_user_conf(conf)

    # Read variables from dnsmasq.conf
    if check_dnsmasq_conf(conf):
        print('Restarting dnsmasq ...')
        dnsmasq_restart()

    # Read destination of dnsmasq log from dnsmasq.conf
    options = parse_dnsmasq_config_yield(conf.dnsmasq_conf, ('log-facility',))
    conf.dnsmasq_logfile = next(options).value

    # Cleanup
    del parser, args, iniparser, options

    # Open our dnsmasq logfile, start parsing thread
    logfile_fh = open(conf.dnsmasq_logfile, 'r+')
    Thread(target=read_dnsmasg_log, args=(logfile_fh, conf, blocked_lock, blocked_domains)).start()

    mappings = cmd_show_blocked(None)

    while True:
        try:
            if mappings:
                prompt = '(a)llow (b)lock (h)elp > '
            else:
                prompt = ' > '
            line = input(prompt)
            cmd, *args = shlex.split(line)
        except ValueError:
            cmd, args = '', None

        if cmd == '':
            mappings = cmd_show_blocked(args)
        else:
            # check
            domains = no_command(cmd, args)
            if domains:
                func = cmd_allow
                args = domains
            else:
                func = resolve_cmd(cmd)

            try:
                if func in (cmd_show_blocked, cmd_show_allowed, cmd_show_user_blocked):
                    mappings = func(args)
                else:
                    if func in (cmd_allow, cmd_block, cmd_temp, cmd_unallow):
                        if not mappings:
                            print('Must call show-blocked, show-allowed, show-user-blocked before using this function')
                        else:
                            func(mappings, args)
                    elif func:
                        func(args)
                    #mappings = None
            except Exception as e:
                print('Ouch:', e, '\n\n', traceback.format_exc())

except (KeyboardInterrupt, EOFError):
    pass
except ConfigException as e:
    print(e)
    sys.exit(1)
except Exception as e:
    print('Ouch:', e, '\n\n', traceback.format_exc())
    sys.exit(1)
finally:
    try:
        logfile_fh.close()
    except:
        pass
