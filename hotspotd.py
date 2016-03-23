#!/usr/bin/env python2
# @author: Prahlad Yeri
# @description: Small daemon to create a wifi hotspot on linux
# @license: MIT
# python -m hotspotd $*

import array
import fcntl
import glob
import json
import logging
import os
import socket
import struct
import subprocess
import sys
import click

__license__ = 'MIT'
__version__ = '0.2.0'


class Hotspotd(object):

    def __init__(self, wlan=None, inet=None, ip='192.168.45.1', netmask='255.255.255.0',
                 ssid='hotspod', password='12345678', verbose=False):

        self.wlan = wlan
        self.inet = inet
        self.ip = ip
        self.netmask = netmask
        self.ssid = ssid
        self.password = password
        self.config_file = '/etc/hotspotd.json'
        print('Hotspotd conf file: %s' % self.config_file)

        # Initialize logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%d.%m.%Y %H:%M:%S'))
        self.logger.addHandler(handler)

    def start(self, free=False):
        if free:
            try:
                result = execute_shell('nmcli radio wifi off')
                if "error" in result.lower():
                    execute_shell('nmcli nm wifi off')
                execute_shell('rfkill unblock wlan')
                execute_shell('sleep 1')
                print 'done.'
            except:
                pass

        self.apply()

        s = 'ifconfig ' + self.wlan + ' up ' + self.ip + ' netmask ' + self.netmask
        print('using interface: ' + self.wlan + ' on IP: ' + self.ip)
        r = execute_shell(s)
        print('sleeping for 2 seconds.')

        execute_shell('sleep 2')
        i = self.ip.rindex('.')
        ipparts = self.ip[0:i]

        # stop dnsmasq if already running.
        if is_process_running('dnsmasq') > 0:
            print('stopping dnsmasq')
            execute_shell('killall dnsmasq')

        # stop hostapd if already running.
        if is_process_running('hostapd') > 0:
            print('stopping hostapd')
            execute_shell('killall -9 hostapd')

        # enable forwarding in sysctl.
        print('enabling forward in sysctl.')
        r = set_sysctl('net.ipv4.ip_forward', '1')
        # print r.strip()

        # enable forwarding in iptables.
        print('creating NAT using iptables: %s <--> %s' % (self.wlan , self.inet))
        execute_shell('iptables -P FORWARD ACCEPT')

        # add iptables rules to create the NAT.
        execute_shell('iptables --table nat --delete-chain')
        execute_shell('iptables --table nat -F')
        r = execute_shell('iptables --table nat -X')
        if len(r.strip()) > 0: print r.strip()
        execute_shell('iptables -t nat -A POSTROUTING -o ' + self.inet + ' -j MASQUERADE')
        execute_shell(
            'iptables -A FORWARD -i ' + self.inet + ' -o ' + self.wlan + ' -j ACCEPT -m state --state RELATED,ESTABLISHED')
        execute_shell('iptables -A FORWARD -i ' + self.wlan + ' -o ' + self.inet + ' -j ACCEPT')

        # allow traffic to/from wlan
        execute_shell('iptables -A OUTPUT --out-interface ' + self.inet + ' -j ACCEPT')
        execute_shell('iptables -A INPUT --in-interface ' + self.wlan + ' -j ACCEPT')

        # start dnsmasq
        s = 'dnsmasq --dhcp-authoritative --interface=' + self.wlan + ' --dhcp-range=' + ipparts + '.20,' + ipparts + '.100,' + self.netmask + ',4h'
        print('running dnsmasq: %s' % s)
        r = execute_shell(s)
        s = 'hostapd -B ' + os.getcwd() + '/run.conf'
        print(s)
        execute_shell('sleep 2')
        r = execute_shell(s)
        print('hotspot is running.')

    def stop(self):
        # bring down the interface
        execute_shell('ifconfig ' + self.wlan + ' down')

        # TODO: Find some workaround. killing hostapd brings down the wlan0 interface in ifconfig.
        # ~ #stop hostapd
        if is_process_running('hostapd') > 0:
            print('stopping hostapd')
            execute_shell('killall -9 hostapd')
            # execute_shell('pkill hostapd')

        # stop dnsmasq
        if is_process_running('dnsmasq') > 0:
            print('stopping dnsmasq')
            execute_shell('killall dnsmasq')

        # disable forwarding in iptables.
        print('disabling forward rules in iptables.')
        execute_shell('iptables -P FORWARD DROP')

        # delete iptables rules that were added for wlan traffic.
        execute_shell('iptables -D OUTPUT --out-interface ' + self.wlan + ' -j ACCEPT')
        execute_shell('iptables -D INPUT --in-interface ' + self.wlan + ' -j ACCEPT')
        execute_shell('iptables --table nat --delete-chain')
        execute_shell('iptables --table nat -F')
        execute_shell('iptables --table nat -X')
        # disable forwarding in sysctl.
        print('disabling forward in sysctl.')
        r = set_sysctl('net.ipv4.ip_forward', '0')
        # print r.strip()
        # execute_shell('ifconfig ' + self.wlan + ' down'  + IP + ' netmask ' + Netmask)
        # execute_shell('ip addr flush ' + self.wlan)
        print 'hotspot has stopped.'
        return

    def apply(self, filename=None):
        f = open('run.dat', 'r')
        lout = []
        for line in f.readlines():
            lout.append(line.replace('<SSID>', self.ssid).replace('<PASS>', self.password).replace('<WIFI>', self.wlan))

        f.close()
        f = open('run.conf', 'w')
        f.writelines(lout)
        f.close()

        print('created hostapd configuration: run.conf')

    def save(self, filename=None):
        fname = self.config_file if filename is None else filename
        dc = {'wlan': self.wlan, 'inet': self.inet, 'ip': self.ip, 'netmask': self.netmask, 'ssid': self.ssid, 'password': self.password}
        # print(dc)
        json.dump(dc, open(fname, 'wb'))
        print('Configuration saved. Run "hotspotd start" to start the router.')

    def load(self, filename=None):
        fname = self.config_file if filename is None else filename
        dc = json.load(open(fname, 'rb'))
        self.wlan = dc['wlan']
        self.inet = dc['inet']
        self.ip = dc['ip']
        self.netmask = dc['netmask']
        self.ssid = dc['ssid']
        self.password = dc['password']


def execute(command='', errorstring='', wait=True, shellexec=False, ags=None):
    try:
        if shellexec:
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # self.logger.debug('command: ' + command)
        else:
            p = subprocess.Popen(args=ags)
            # self.logger.debug('command: ' + ags[0])

        if wait:
            p.wait()
            result = get_stdout(p)
            return result
        else:
            # self.logger.debug('not waiting')
            return p
    except subprocess.CalledProcessError as e:
        # self.logger.error('error occured:' + errorstring)
        return errorstring
    except Exception as ea:
        # self.logger.error('Exception occured:' + ea.message)
        return errorstring


def execute_shell(command, error=''):
    return execute(command, wait=True, shellexec=True, errorstring=error)


def get_stdout(pi):
    result = pi.communicate()
    return result[0] if len(result[0]) > 0 else result[1]


def killall(self, process):
    cnt = 0
    pid = is_process_running(process)
    while pid != 0:
        self.execute_shell('kill ' + str(pid))
        pid = is_process_running(process)
        cnt += 1
    return cnt


def is_process_running(name):
    s = execute_shell('ps aux |grep ' + name + ' |grep -v grep')
    return 0 if len(s) == 0 else int(s.split()[1])


def check_sysfile(filename):
    if os.path.exists('/usr/sbin/' + filename):
        return '/usr/sbin/' + filename
    elif os.path.exists('/sbin/' + filename):
        return '/sbin/' + filename
    else:
        return ''


def get_sysctl(setting):
    result = execute_shell('sysctl ' + setting)
    return result.split('=')[1].lstrip() if '=' in result else result


def set_sysctl(setting, value):
    return execute_shell('sysctl -w ' + setting + '=' + value)


def get_interfaces_dict():
    is_64bits = sys.maxsize > 2 ** 32
    struct_size = 40 if is_64bits else 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    max_possible = 8  # initial value
    while True:
        _bytes = max_possible * struct_size
        names = array.array('B')
        for i in range(0, _bytes):
            names.append(0)
        outbytes = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            0x8912,  # SIOCGIFCONF
            struct.pack('iL', _bytes, names.buffer_info()[0])
        ))[0]
        if outbytes == _bytes:
            max_possible *= 2
        else:
            break
    namestr = names.tostring()
    ifaces = {}
    for i in range(0, outbytes, struct_size):
        iface_name = bytes.decode(namestr[i:i + 16]).split('\0', 1)[0]
        iface_addr = socket.inet_ntoa(namestr[i + 20:i + 24])
        ifaces[iface_name] = iface_addr
    return ifaces


def get_auto_wifi_interface():
    wifi_interfaces = get_ifaces_names(True)
    net_interfaces = map(lambda (x,y): x, get_interfaces_dict().items())
    for wifi in wifi_interfaces:
        if wifi not in net_interfaces:
            return wifi

    return None


def get_default_iface():
    route = "/proc/net/route"
    with open(route) as f:
        for line in f.readlines():
            try:
                iface, dest, _, flags, _, _, _, _, _, _, _, =  line.strip().split()
                if dest != '00000000' or not int(flags, 16) & 2:
                    continue
                return iface
            except:
                continue

    return None


def get_iface_list():
    return [x for (x,y) in get_interfaces_dict().items()]


def get_ifaces_names(wireless=False):
    if wireless:
        return [f.split('/')[-2] for f in glob.glob("/sys/class/net/*/phy80211")]
    return os.listdir('/sys/class/net')


@click.group()
@click.option('--debug/--no-debug', help='Enable debug output', default=False)
@click.pass_context
def cli(ctx, debug):
    ctx.obj = {}
    if os.geteuid() != 0:
        print("You need root permissions to do this, sloth!")
        sys.exit(1)

    ctx.obj['DEBUG'] = debug


def validate_ip(ctx, param, value):
    try:
        socket.inet_aton(value)
        return value
    except socket.error:
        raise click.BadParameter('non valid IP address')


def validate_inet(ctx, param, value):
    if value not in get_iface_list():
        raise click.BadParameter('non valid IP address')
    return value


def validate_wifi(ctx, param, value):
    if value not in get_ifaces_names(True):
        raise click.BadParameter('non valid wireless interface')
    return value


def validate_password(ctx, param, value):
    if len(value) < 8:
        raise click.BadParameter('WiFi password must be 8 chars length minimum')
    return value


@cli.command()
@click.option('-W', '--wlan', prompt='WiFi interface to use for AP', callback=validate_wifi, default=get_auto_wifi_interface())
@click.option('-I', '--inet', prompt='Network interface connected to Internet', callback=validate_inet, default=get_default_iface())
@click.option('-i', '--ip', prompt='Access point IP address', callback=validate_ip, default='192.168.45.1')
@click.option('-m', '--netmask', prompt='Netmask for network', callback=validate_ip, default='255.255.255.0')
@click.option('-s', '--ssid', prompt='WiFi access point SSID', default='hostapd')
@click.option('-p', '--password', prompt='WiFi password', hide_input=True, confirmation_prompt=True, callback=validate_password, default='12345678')
@click.pass_context
def configure(ctx, wlan, inet, ip, netmask, ssid, password):
    '''Configure Hotspotd'''
    click.echo('Debug is %s' % (ctx.obj['DEBUG'] and 'on' or 'off'))
    h = Hotspotd(wlan, inet, ip, netmask, ssid, password)
    h.save()


@cli.command()
@click.pass_context
def start(ctx):
    '''Start hotspotd'''
    click.echo('Debug is %s' % (ctx.obj['DEBUG'] and 'on' or 'off'))
    h = Hotspotd()
    click.echo('Loading configuration')
    h.load()
    click.echo('Starting...')
    h.start()


@cli.command()
@click.pass_context
def stop(ctx):
    '''Stop Hotspotd'''
    click.echo('Debug is %s' % (ctx.obj['DEBUG'] and 'on' or 'off'))
    h = Hotspotd()
    h.load()
    h.stop()


@cli.command()
@click.pass_context
def check(ctx):
    '''Check dependencies: hostapd, dsmasq'''
    if len(check_sysfile('hostapd')) == 0:
        click.secho('hostapd executable not found. Make sure you have installed hostapd.', fg='red')

    if len(check_sysfile('dnsmasq')) == 0:
        click.secho('dnsmasq executable not found. Make sure you have installed dnsmasq.', fg='red')

    click.secho('All dependencies found 8).', fg='green')


if __name__ == '__main__':
    cli(obj={})
