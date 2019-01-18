#!/usr/bin/python3

import re
from contextlib import contextmanager

__DOMAIN_RE = re.compile('^[\*\w\.-]+\.[\*\w\.-]+$')
def valid_domain(domain):
    return __DOMAIN_RE.match(domain)

def filter01(callback, iterable):
    good, bad = [], []
    for i in iterable:
        (bad, good)[not not callback(i)].append(i)
    return (good, bad)

@contextmanager
def use_lock(lock):
    try:
        lock.acquire()
        yield
    finally:
        lock.release()

def reindent(string, pad=0):
    lines = string.split('\n')

    def rofl(lines):
        space_re = re.compile('^ *.')
        for line in lines:
            try:
                yield space_re.match(line).span()[1] - 1
            except:
                pass

    shortest_space = min(rofl(lines))

    pad = ' ' * pad
    return '\n'.join(
        map(lambda s: '%s%s' % (pad, s[shortest_space:]), lines)
    )

def getopts_short(opts, args):
    options = { c: None for c in opts if c != ':' }
    arguments = []
    args = iter(args)

    for arg in args:
        if len(arg) < 2: # too short for opt, is arg
            arguments.append(arg)

        elif arg[0] == '-':
            if arg[1] in opts:
                if len(arg) > 2:
                    raise Exception('chaining of flags not supported: ' + arg)

                try:
                    options[arg[1]] = True
                    if opts[opts.index(arg[1]) + 1] == ':':
                        options[arg[1]] = next(args)
                except StopIteration:
                    raise Exception('missing argument for: ' + arg)
                except IndexError:
                    pass
            else:
                raise Exception('unknown args:', arg)
        else:
            arguments.append(arg)

    return (options, arguments)

def read_prompt_with_choices(prompt):
    choices = re.findall('\[(.)\]', prompt)

    while True:
        s = input(prompt + ': ')
        if s in choices:
            return s

def read_yes_no(prompt):
    prompt += ' [y/n] '

    while True:
        try:
            s = input(prompt).lower()
            if s == 'y':
                return True
            elif s == 'n':
                return False
        except (EOFError, KeyboardInterrupt):
            raise
        except:
            pass

def read_default(prompt, default):
    s = input('%s [%s]: ' % (prompt, default))

    if s:
        return s
    else:
        return default

#def print_domains(domains):
#    new_blocked.sort(key=itemgetter(1))
#    counter = len(new_blocked)
#    new_blocked = groupby(new_blocked, key=itemgetter(1))
#
#    mappings = []
#
#    for date, domains in new_blocked:
#        print(date, end='  ')
#        domain = next(domains)[0]
#        mappings.append( domain )
#        print('%d) %s' % (counter, domain))
#        counter -= 1
#
#        for domain, _ in domains:
#            print('                       %d) %s' % (counter, domain))
#
#            mappings.append(  domain )
#            counter -= 1
#
#    mappings.reverse()
#    return mappings
