#!/usr/bin/python3

''' Stuff for parsing dnsmasq confs '''

import datetime

class DnsMasqOption():
    __slots__ = ('name', 'value', 'comment')

    def __init__(self, name, value=None, comment=None):
        self.name = name
        self.value = value
        self.comment = comment

    def tryFromLine(line):
        try:    return DnsMasqOption.fromLine(line)
        except: return None

    def fromLine(line):
        option = line.strip()
        if not option:
            raise Exception('empty line')
        
        if option[0] == '#':
            raise Exception('comment')

        try:
            option, comment = option.split(' #', 1)
            option = option.strip()
            comment = comment.strip()
        except:
            comment = None

        try:    option, value = option.split('=', 1)
        except: value = None

        return DnsMasqOption(option, value, comment)

def parse_dnsmasq_config(conf_file, wanted_options=None):
    ''' Parse dnsmasq configuration file.  '''
    options = {}

    for opt in parse_dnsmasq_config_yield(conf_file, wanted_options):
        options[opt.name] = options.get(opt.name, [])
        options[opt.name].append(opt)

    return options

def parse_dnsmasq_config_yield(conf_file, wanted_options=None):
    ''' Parse dnsmasq configuration file. (yield version) '''

    with open(conf_file, 'r') as fh:
        for opt in map(DnsMasqOption.tryFromLine, fh.readlines()):
            if opt and (not wanted_options or opt.name in wanted_options):
                yield opt

class DnsMasqAllowedDomain():
    ''' Allowed Domain Class '''

    __slots__ = ('domain', 'ip', 'date', 'temp')

    # domains are written into conf_file in this format:
    #   server=/domain.com/1.2.3.4/ # TIMESTAMP [TMP]

    def __init__(self, domain=None, ip=None, date=None, temp=False):
        self.domain = domain
        self.ip = ip
        self.date = date
        self.temp = temp

    def fromOption(option):
        comment = option.comment.strip()

        try:
            clock, is_tmp = comment.split()
            is_tmp = True if is_tmp == 'TMP' else False
        except:
            clock = comment
            is_tmp = False

        try:
            date = datetime.datetime.fromisoformat(clock)
        except:
            date = datetime.datetime.now()

        _, domain, ip = option.value.split('/')

        return DnsMasqAllowedDomain(domain, ip, date, is_tmp)

    def getDate(self):
        if not self.date:
            self.date = datetime.datetime.now()
        return self.date

    def getIsoDate(self):
        return self.getDate().isoformat(u'T', 'seconds')

    def getConfStr(self):
        temp = 'TMP' if self.temp else ''
        return "server=/%s/%s # %s %s" % (
            self.domain, self.ip, self.getIsoDate(), temp)

    def __repr__(self):
        return '%s=>%s' % (self.domain, self.ip)


class DnsMasqBlockedDomain():
    __slots__ = ('domain', 'ip', 'date')

    def __init__(self, domain, ip, date=None):
        self.domain = domain
        self.ip = ip
        self.date = date

    def fromOption(option):
        _, domain, ip = option.value.split('/')

        try:
            date = datetime.datetime.fromisoformat(option.comment.strip())
        except:
            date = datetime.datetime.now()

        return DnsMasqBlockedDomain(domain, ip, date)

    def getDate(self):
        if not self.date:
            self.date = datetime.datetime.now()
        return self.date

    def getIsoDate(self):
        return self.getDate().isoformat(u'T', 'seconds')

    def getConfStr(self):
        return "address=/%s/%s # %s\n" % (
            self.domain, self.ip, self.getIsoDate())

    def __repr__(self):
        return '%s=>%s' % (self.domain, self.ip)

