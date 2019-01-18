def load_conf():
    try:
        with open(conf_file, 'r') as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {'blocked': []}

def save_conf(conf):
    with open(conf_file, 'w') as fh:
        json.dump(conf, conf_file)

    using_nameserver_for_re = re.compile('using nameserver ([\w\.#]+) for domain ([\w\.-]+)')

            try:
                domain = using_nameserver_for_re.findall(msg)[0][1]
                data_domains.put(domain)
                continue
            except:
                pass

            month, day, clocktime, _, msg = line.split(' ', 4)
            date = datetime.datetime.strptime('%s %s %s %s' % (year, month, day, clocktime), '%Y %b %d %H:%M:%S')


    #try:
    #    while True:
    #        domain = data_domains.get_nowait()
    #        allowed_domains.add(domain)
    #except QueueEmpty:
    #    pass


    if 'server' in options:
        plain    = filter(lambda s: '*' not in s, options['server'])
        wildcard = filter(lambda s: '*' in s,     options['server'])
        plain    = list(map(lambda s: s.split('/')[1], plain))
        wildcard = list(map(lambda s: s.split('/')[1], wildcard))
    else:
        plain, wildcard = [], []

    nodata_re = re.compile('config ([\w\.-]+) is NODATA')


                #if domain in allowed_plain:
                #    return

                #for pat in allowed_wildcard:
                #    if fnmatch(domain, pat):
                #        return


def read_logfile(logfile):
    DomainState = namedtuple('Action', ('state', 'domain', 'date'))

    months = ( 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
               'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec' )

    year = datetime.datetime.now().year

    
    AUTO_BLOCKED, MANUAL_BLOCKED, FORWARED = 1, 2, 3
    def parse_line2(line):
        if 'is 127.0.0.' in line:
            pass

    # forwarded
    # Jan 15 18:46:25 dnsmasq[17820]: forwarded heise.de to 8.8.8.8
    # Jan 15 18:00:03 dnsmasq[15814]: config blabla.de is 127.0.0.1
    # Jan 15 18:00:03 dnsmasq[15814]: config blabla.de is ::
    re_blocked = re.compile('([\w\.-]+) is (?:127\.0\.0\.[12]|::)')
    is_block = lambda s: (' is ::' in s) or (' is 127.0.0.1' in s)
    is_man_block = lambda s: (' is 127.0.0.2' in s)

    #re_blocked = re.compile('([\w\.-]+) is ::')
    #is_block = lambda s: ' is ::' in s

    with open(logfile, 'r+') as fh:
        def parse_line(line):
            if not is_block(line):
                return

            # Jan 14 19:03:15 dnsmasq[16243]: forwarded www.heise.de to 8.8.8.8
            month, day, clocktime, _, msg = line.split(' ', 4)
            hour, minute, second = clocktime.split(':')

            date = datetime.datetime(
                year=year, month=(months.index(month) + 1), day=int(day),
                hour=int(hour), minute=int(minute), second=int(second)
            )

            try:
                domain = re_blocked.findall(msg)[0]
                nodata_domains.put((domain, date))
            except:
                pass

        if conf.load_log_lines == 0:
            fh.read(-1)
        else:
            last_lines = list(filter(is_block, fh))
            if conf.load_log_lines != -1:
                last_lines = last_lines[(-1 * conf.load_log_lines):]
            
            for line in last_lines:
                parse_line(line)

        while True:
            line = fh.readline()

            if not line:
                time.sleep(1)
                continue

            parse_line(line)




    HOME = os.environ['HOME']
    XDG_CONFIG_HOME = os.environ.get('XDG_CONFIG_HOME', HOME+'./config')


def check_startup():
    need_restart = False
    exmsg = 'Sorry, you need to fix your dnsmasq.conf in order to run this program'
    options = parse_dnsmasq_config(conf.dnsmasq_conf,
        ('log-facility', 'log-queries', 'address'))

    # Option `log-facility`
    try:
        conf.dnsmasq_logfile = options['log-facility'][0].value
    except:
        print('Option `log-facility` is not set in your dnsmasq.conf.')
        p = 'Do you wish to set the `log-facility` option now?'
        if read_yes_no(p):
            f = read_default('Enter filename for dnsmasq log', '/var/log/dnsmasq.log')
            conf_insert('log-facility=' + f)
            conf.dnsmasq_logfile = f
            need_restart = True
        else:
            raise Exception(exmsg)

    # Option `log-queries`
    if not 'log-queries' in options:
        print('Option `log-queries` is not set in your dnsmasq.conf.')
        print('This option must be set to track the incoming dns queries.')
        s = 'Do you wish to enable `log-queries` option now?'
        if read_yes_no(s):
            conf_insert('log-queries')
            need_restart = True
        else:
            raise Exception(exmsg)

    # Option `address`
    hash_addresses = list(filter( lambda o: '/#/' in o.value,
                                  options.get('address', ())  ))

    if not hash_addresses:
        print('No `address` option set in your dnsmasq.conf.')
        print('This option must be set to block incoming queries by default.')
        s = 'Do you wish to set `address` option now?'
        if read_yes_no(s):
            conf_insert('address=/#/' + conf.ip_auto_blocked)
            need_restart = True
        else:
            raise Exception(exmsg)
    else:
        found = False
        for option in hash_addresses:
            found = (option.value.split('/')[2] == conf.ip_auto_blocked)
            if found:
                break

        if not found:
            print('Found `addres=/#/...` option, but it does not match your --ip-auto-blocked value.')
            print('Please insert `address=/#/%s` to your dnsmaq.conf.' % conf.ip_auto_blocked)
            print('Keep in mind that there should only be ONE `address=/#/...` line in your configuration file.')
            raise Exception(exmsg)

    if need_restart:
        dnsmasq_restart()



    # Set default values
    #for key, value in defaults.items():
    #    if key not in conf:
    #        conf[key] = value




# TODO
def read_dnsmasq_blocked(args):
    options = parse_dnsmasq_config(conf.dnsmasq_conf, ('address',))
    for option in options.get('address', ()):
        _, domain, ip = option.value.split('/')
        if ip == conf.ip_manual_blocked:
            print(domain)

def read_dnsmasq_allowed(conf_file):
    # domains are written into conf_file in this format:
    #   server=/domain.com/1.2.3.4/ # TIMESTAMP [TMP]
    #
    options = parse_dnsmasq_config(conf_file, ('server',))
    for option in options.get('server', ()):
        comment = option.comment.strip()

        try:
            clock, is_tmp = comment.split()
            is_tmp = True if is_tmp == 'TMP' else False
        except:
            clock = commment
            is_tmp = False

        try:
            date = datetime.datetime.fromisoformat(clock)
        except:
            date = datetime.datetime.now()

        domain = option.value.split('/')[1]

        yield DnsMasqAllowedDomain(domain, timestamp, is_tmp)

# XXX XXX XXX XXX
def conf_insert_allow(domain, temporary=False):
    temp = 'TMP' if temporary else ''
    iso = datetime.datetime.now().isoformat(u'T', 'seconds')

    with open(conf.allow_file, 'a') as fh:
        fh.write("server=/%s/%s # %s %s\n" %
            (domain, conf.dns_server, iso, temp))

def conf_insert_block(domain):
    iso = datetime.datetime.now().isoformat(u'T', 'seconds')

    with open(conf.block_file, 'a') as fh:
        fh.write("address=/%s/%s # %s\n" %
            (domain, conf.ip_manual_blocked, iso))

def unallow(domain):
    tempf = tempfile.NamedTemporaryFile(mode='w', prefix='dnsall')

    with open(conf.dnsmasq_conf, 'r') as fh:
        line = fh.readline()

@command('show-allowed', 'show domains that are whitelisted', '''
    List all domains that are currently whitelisted in the dnsmaq.conf
''')
def cmd_show_allowed(args):
    options = parse_dnsmasq_config(conf.dnsmasq_conf, ('server',))
    for option in options.get('server', ()):
        try:
            date = datetime.datetime.fromisoformat( option.comment.strip() )
        except:
            date = datetime.datetime.now()

        print(date, option.value.split('/')[1])
        


# checkconf.py
#    # Option `address`
#    hash_addresses = list(filter( lambda o: '/#/' in o.value,
#                                  options.get('address', ())  ))
#
#    if not hash_addresses:
#        print('No `address` option set in your dnsmasq.conf.')
#        print('This option must be set to block incoming queries by default.')
#        s = 'Do you wish to set `address` option now?'
#        if read_yes_no(s):
#            conf_insert('address=/#/' + conf.ip_auto_blocked)
#            restart()
#        else:
#            die()
#    else:
#        found = False
#        for option in hash_addresses:
#            found = (option.value.split('/')[2] == conf.ip_auto_blocked)
#            if found:
#                break
#
#        if not found:
#            print('Found `addres=/#/...` option, but it does not match your --ip-auto-blocked value.')
#            print('Please insert `address=/#/%s` to your dnsmaq.conf.' % conf.ip_auto_blocked)
#            print('Keep in mind that there should only be ONE `address=/#/...` line in your configuration file.')
#            raise Exception(exmsg)



        patterns, domains = filter01(lambda d: '*' in d,
            map(lambda d: d.domain, 
                chain(
                    read_dnsmasq_allowed(conf.whitelist_file),
                    read_dnsmasq_blocked(conf.blacklist_file),
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


 
        # Version 2
        #new_blocked = groupby(new_blocked, key=itemgetter(1))

        #mappings = []

        #for date, domains in new_blocked:
        #    datestr = date.strftime(conf.dateformat)
        #    domain = next(domains)[0]
        #    mappings.append(domain)
        #    print('%s %2d) %s' % (datestr, index, domain))
        #    index -= 1

        #    print_fmt = '%%%ds %%2d) %%s' % len(datestr)

        #    for domain, _ in domains:
        #        print(print_fmt % ('', index, domain))
        #        mappings.append( domain )
        #        index -= 1

        #mappings.reverse()
        #return mappings



from enum import Enum
class DomainState(Enum):
    AutoBlocked = 1
    UserBlocked = 2
    Allowed = 3

#months = ( 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
#           'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec' )
#
class DomainMessage():
    __slots__ = ('state', 'domain', 'date')

    def __init__(self, state, domain, date):
        self.state = state
        self.domain = domain
        self.date = date
#
#    def fromLine(line):
#        month, day, clocktime, _, *parts = line.strip().split(' ')
#
#        if parts[-2] == 'is':
#            date = None
#
#            # Automatically blocked domain
#            if parts[-1] == conf.ip_auto_blocked:
#                state = DomainState.AutoBlocked
#                hour, minute, second = clocktime.split(':')
#                date = datetime.datetime(
#                    year=year, month=(months.index(month) + 1), day=int(day),
#                    hour=int(hour), minute=int(minute), second=int(second)
#                )
#            # Manual blocked domain
#            elif parts[-1] == conf.ip_manual_blocked:
#                state = DomainState.UserBlocked
#            # Does not contain NODATA -> is valid IP -> Allowed
#            elif 'NODATA' not in parts[-1]:
#                state = DomainState.Allowed
#            # Is NODATA, do nothing
#            else:
#                return
#
#            domain = parts[-3]
#
#            return D
#            message_queue.put(DomainMessage(state, domain, date))
#
#
#def read_dnsmasg_log(fh):
#    year = datetime.datetime.now().year
#
#    # Jan 15 18:00:03 dnsmasq[15814]: config blabla.de is 127.0.0.1
#    # Jan 15 18:00:03 dnsmasq[15814]: config blabla.de is ::
#    # Jan 14 18:11:03 dnsmasq[5693]: reply proxy.duckduckgo.com is <CNAME>
#    # Jan 14 18:11:03 dnsmasq[5693]: reply icons.duckduckgo.com is 54.75.239.212
#    # Jan 16 01:24:03 dnsmasq[2377]: config isblocked.net is NODATA-IPv6
#
#
#
#

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
                    #(domain, blocked_domains[domain].replace(second=0, microsecond=0)) # Version 2
                    (domain, blocked_domains[domain])
                )
        
        index = len(new_blocked)
        new_blocked.sort(key=itemgetter(0)) # sort by domain name
        new_blocked.sort(key=itemgetter(1)) # sort by date

        # Version 1
        mappings = []

        for domain, date in new_blocked:
            index -= 1
            mappings.append(domain)
            print('%s %2d) %s' % (
                date.strftime(conf.dateformat), index, domain))

        mappings.reverse()
        return mappings

        # Version 2
        #new_blocked = groupby(new_blocked, key=itemgetter(1))

        #mappings = []

        #for date, domains in new_blocked:
        #    datestr = date.strftime(conf.dateformat)
        #    domain = next(domains)[0]
        #    mappings.append(domain)
        #    print('%s %2d) %s' % (datestr, index, domain))
        #    index -= 1

        #    print_fmt = '%%%ds %%2d) %%s' % len(datestr)

        #    for domain, _ in domains:
        #        print(print_fmt % ('', index, domain))
        #        mappings.append( domain )
        #        index -= 1

        #mappings.reverse()
        #return mappings
