#!/usr/bin/env python2
# @authors: Prahlad Yeri, Oleg Kupreev
# @description: Small daemon to create a wifi hotspot on linux
# @license: MIT

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
import time
import re
import click

__license__ = 'MIT'
__version__ = '0.2.0'


class Hotspotd(object):
    def __init__(self, wlan=None, inet=None, ip='192.168.45.1', netmask='255.255.255.0', mac='00:de:ad:be:ef:00',
                 channel=6, ssid='hotspod', password='12345678', verbose=False):

        self.wlan = str(wlan)
        self.inet = str(inet)
        self.ip = ip
        self.netmask = netmask
        self.mac = mac
        self.channel = int(channel)
        self.ssid = ssid
        self.password = password
        self.config_file = '/etc/hotspotd.json'
        print('Hotspotd conf file: %s' % self.config_file)
        self.hostapd_config = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'run.dat')
        print('Hostapd configuration template: %s' % self.hostapd_config)

        # Initialize logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%d.%m.%Y %H:%M:%S'))
        self.logger.addHandler(handler)

    def execute(self, command='', errorstring='', wait=True, shellexec=False, ags=None):
        try:
            if shellexec:
                p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.logger.debug('command: ' + command)
            else:
                p = subprocess.Popen(args=ags)
                self.logger.debug('command: ' + ags[0])

            if wait:
                p.wait()
                result = get_stdout(p)
                return result
            else:
                self.logger.debug('not waiting')
                return p
        except subprocess.CalledProcessError as e:
            self.logger.error('error occured:' + errorstring)
            return errorstring
        except Exception as ea:
            self.logger.error('Exception occured:' + ea.message)
            return errorstring

    def execute_shell(self, command, error=''):
        return self.execute(command, wait=True, shellexec=True, errorstring=error)

    def start(self, free=False):
        # Try to free wireless
        if free:
            # ATTENTION!!! STOP ALL WIRELESS INTERFACES
            try:
                result = self.execute_shell('nmcli radio wifi off')
                if "error" in result.lower():
                    self.execute_shell('nmcli nm wifi off')
                self.execute_shell('rfkill unblock wlan')
                time.sleep(1)
                print('done.')
            except:
                pass

        # Prepare hostapd configuration file
        # config_text = open('run.dat', 'r').read(). \
        config_text = open(self.hostapd_config, 'r').read(). \
            replace('<PASS>', self.password).replace('<WIFI>', self.wlan). \
            replace('<SSID>', self.ssid).replace('<CHANNEL>', str(self.channel))

        with open('/tmp/run.conf', 'w') as f:
            f.write(config_text)
        print('created hostapd configuration: run.conf')

        print('using interface: %s on IP: %s MAC: %s' % (self.wlan, self.ip, self.mac))
        self.execute_shell('ifconfig ' + self.wlan + ' down')
        set_interface_mac(self.wlan, self.mac)
        self.execute_shell('ifconfig ' + self.wlan + ' up ' + self.ip + ' netmask ' + self.netmask)
        # set_channel(self.wlan, self.channel)
        # self.execute_shell('iwconfig %s channel %s' % (self.wlan, self.channel))

        # Split IP to partss
        time.sleep(2)
        i = self.ip.rindex('.')
        ipparts = self.ip[0:i]

        # stop dnsmasq if already running.
        if self.is_process_running('dnsmasq') > 0:
            print('stopping dnsmasq')
            self.execute_shell('killall dnsmasq')

        # stop hostapd if already running.
        if self.is_process_running('hostapd') > 0:
            print('stopping hostapd')
            self.execute_shell('killall -9 hostapd')

        # enable forwarding in sysctl.
        print('enabling forward in sysctl.')
        self.set_sysctl('net.ipv4.ip_forward', '1')

        # enable forwarding in iptables.
        print('creating NAT using iptables: %s <--> %s' % (self.wlan, self.inet))
        self.execute_shell('iptables -P FORWARD ACCEPT')

        # add iptables rules to create the NAT.
        self.execute_shell('iptables --table nat --delete-chain')
        self.execute_shell('iptables --table nat -F')
        self.execute_shell('iptables --table nat -X')
        self.execute_shell('iptables -t nat -A POSTROUTING -o %s -j MASQUERADE' % self.inet)
        self.execute_shell(
            'iptables -A FORWARD -i %s -o %s -j ACCEPT -m state --state RELATED,ESTABLISHED' % (self.inet, self.wlan))
        self.execute_shell('iptables -A FORWARD -i ' + self.wlan + ' -o ' + self.inet + ' -j ACCEPT')

        # allow traffic to/from wlan
        self.execute_shell('iptables -A OUTPUT --out-interface ' + self.inet + ' -j ACCEPT')
        self.execute_shell('iptables -A INPUT --in-interface ' + self.wlan + ' -j ACCEPT')

        # start dnsmasq
        s = 'dnsmasq --dhcp-authoritative --interface=' + self.wlan + ' --dhcp-range=' + ipparts + '.20,' + ipparts + '.100,' + self.netmask + ',4h'
        print('running dnsmasq: %s' % s)
        self.execute_shell(s)
        s = 'hostapd -B ' + os.getcwd() + '/run.conf'
        print(s)
        time.sleep(2)
        self.execute_shell(s)
        print('hotspot is running.')

    def killall(self, process):
        cnt = 0
        pid = self.is_process_running(process)
        while pid != 0:
            self.execute_shell('kill ' + str(pid))
            pid = self.is_process_running(process)
            cnt += 1
        return cnt

    def is_process_running(self, name):
        s = self.execute_shell('ps aux |grep ' + name + ' |grep -v grep')
        return 0 if len(s) == 0 else int(s.split()[1])

    def get_sysctl(self, setting):
        result = self.execute_shell('sysctl ' + setting)
        return result.split('=')[1].lstrip() if '=' in result else result

    def set_sysctl(self, setting, value):
        return self.execute_shell('sysctl -w ' + setting + '=' + value)

    def stop(self):
        # bring down the interface
        self.execute_shell('ifconfig ' + self.wlan + ' down')

        # stop hostapd
        if self.is_process_running('hostapd') > 0:
            print('stopping hostapd')
            self.execute_shell('killall -9 hostapd')

        # stop dnsmasq
        if self.is_process_running('dnsmasq') > 0:
            print('stopping dnsmasq')
            self.execute_shell('killall dnsmasq')

        # disable forwarding in iptables.
        print('disabling forward rules in iptables.')
        self.execute_shell('iptables -P FORWARD DROP')

        # delete iptables rules that were added for wlan traffic.
        self.execute_shell('iptables -D OUTPUT --out-interface ' + self.wlan + ' -j ACCEPT')
        self.execute_shell('iptables -D INPUT --in-interface ' + self.wlan + ' -j ACCEPT')
        self.execute_shell('iptables --table nat --delete-chain')
        self.execute_shell('iptables --table nat -F')
        self.execute_shell('iptables --table nat -X')

        # disable forwarding in sysctl.
        print('disabling forward in sysctl.')
        self.set_sysctl('net.ipv4.ip_forward', '0')
        # self.execute_shell('ifconfig ' + self.wlan + ' down'  + IP + ' netmask ' + Netmask)
        # self.execute_shell('ip addr flush ' + self.wlan)
        print('hotspot has stopped.')

    def save(self, filename=None):
        fname = self.config_file if filename is None else filename
        dc = {'wlan': self.wlan, 'inet': self.inet, 'ip': self.ip, 'netmask': self.netmask, 'mac': self.mac, 'channel': self.channel,
              'ssid': self.ssid, 'password': self.password}
        json.dump(dc, open(fname, 'wb'))
        print('Configuration saved. Run "hotspotd start" to start the router.')

    def load(self, filename=None):
        fname = self.config_file if filename is None else filename
        dc = json.load(open(fname, 'rb'))
        self.wlan = dc['wlan']
        self.inet = dc['inet']
        self.ip = dc['ip']
        self.netmask = dc['netmask']
        self.mac = dc['mac']
        self.channel = dc['channel']
        self.ssid = dc['ssid']
        self.password = dc['password']


def get_stdout(pi):
    result = pi.communicate()
    return result[0] if len(result[0]) > 0 else result[1]


def check_sysfile(filename):
    if os.path.exists('/usr/sbin/' + filename):
        return '/usr/sbin/' + filename
    elif os.path.exists('/sbin/' + filename):
        return '/sbin/' + filename
    else:
        return ''


# From linux/sockios.h
SIOCGIFCONF = 0x8912
SIOCGIFINDEX = 0x8933
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SIOCGIFHWADDR = 0x8927
SIOCSIFHWADDR = 0x8924
SIOCGIFADDR = 0x8915
SIOCSIFADDR = 0x8916
SIOCGIFNETMASK = 0x891B
SIOCSIFNETMASK = 0x891C
SIOCETHTOOL = 0x8946
# ioctl calls for the Linux/i386 kernel
SIOCSIWCOMMIT = 0x8B00  # Commit pending changes to driver
SIOCGIWNAME = 0x8B01  # get name == wireless protocol
SIOCSIWNWID = 0x8B02  # set network id (pre-802.11)
SIOCGIWNWID = 0x8B03  # get network id (the cell)
SIOCSIWFREQ = 0x8B04  # set channel/frequency
SIOCGIWFREQ = 0x8B05  # get channel/frequency
SIOCSIWMODE = 0x8B06  # set the operation mode
SIOCGIWMODE = 0x8B07  # get operation mode
SIOCSIWSENS = 0x8B08  # set sensitivity (dBm)
SIOCGIWSENS = 0x8B09  # get sensitivity
SIOCSIWRANGE = 0x8B0A  # Unused
SIOCGIWRANGE = 0x8B0B  # Get range of parameters
SIOCSIWPRIV = 0x8B0C  # Unused
SIOCGIWPRIV = 0x8B0D  # get private ioctl interface info
SIOCSIWSTATS = 0x8B0E  # Unused
SIOCGIWSTATS = 0x8B0F  # Get /proc/net/wireless stats
SIOCSIWSPY = 0x8B10  # set spy addresses
SIOCGIWSPY = 0x8B11  # get spy info (quality of link)
SIOCSIWTHRSPY = 0x8B12  # set spy threshold (spy event)
SIOCGIWTHRSPY = 0x8B13  # get spy threshold
SIOCSIWAP = 0x8B14  # set AP MAC address
SIOCGIWAP = 0x8B15  # get AP MAC addresss
SIOCGIWAPLIST = 0x8B17  # Deprecated in favor of scanning
SIOCSIWSCAN = 0x8B18  # set scanning off
SIOCGIWSCAN = 0x8B19  # get scanning results
SIOCSIWESSID = 0x8B1A  # set essid
SIOCGIWESSID = 0x8B1B  # get essid
SIOCSIWNICKN = 0x8B1C  # set node name/nickname
SIOCGIWNICKN = 0x8B1D  # get node name/nickname
SIOCSIWRATE = 0x8B20  # set default bit rate (bps)
SIOCGIWRATE = 0x8B21  # get default bit rate (bps)
SIOCSIWRTS = 0x8B22  # set RTS/CTS threshold (bytes)
SIOCGIWRTS = 0x8B23  # get RTS/CTS threshold (bytes)
SIOCSIWFRAG = 0x8B24  # set fragmentation thr (bytes)
SIOCGIWFRAG = 0x8B25  # get fragmentation thr (bytes)
SIOCSIWTXPOW = 0x8B26  # set transmit power (dBm)
SIOCGIWTXPOW = 0x8B27  # get transmit power (dBm)
SIOCSIWRETRY = 0x8B28  # set retry limits and lifetime
SIOCGIWRETRY = 0x8B29  # get retry limits and lifetime
SIOCSIWENCODE = 0x8B2A  # set encryption information
SIOCGIWENCODE = 0x8B2B  # get encryption information
SIOCSIWPOWER = 0x8B2C  # set Power Management settings
SIOCGIWPOWER = 0x8B2D  # get power managment settings
SIOCSIWMODUL = 0x8B2E  # set Modulations settings
SIOCGIWMODUL = 0x8B2F  # get Modulations settings
SIOCSIWGENIE = 0x8B30  # set generic IE
SIOCGIWGENIE = 0x8B31  # get generic IE
# WPA
SIOCSIWMLME = 0x8B16  # request MLME operation; uses struct iw_mlme
SIOCSIWAUTH = 0x8B32  # set authentication mode params
SIOCGIWAUTH = 0x8B33  # get authentication mode params
SIOCSIWENCODEEXT = 0x8B34  # set encoding token & mode
SIOCGIWENCODEEXT = 0x8B35  # get encoding token & mode
SIOCSIWPMKSA = 0x8B36  # PMKSA cache operation

SIOCIWFIRST = 0x8B00  # FIRST ioctl identifier
SIOCIWLAST = 0x8BFF  # LAST ioctl identifier


def get_interfaces_dict():
    is_64bits = sys.maxsize > 2 ** 32
    struct_size = 40 if is_64bits else 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    max_possible = 8  # initial value
    names = ''
    outbytes = 0
    while True:
        _bytes = max_possible * struct_size
        names = array.array('B')
        for i in range(0, _bytes):
            names.append(0)
        outbytes = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            SIOCGIFCONF,
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


def get_iface_list():
    return [x for (x, y) in get_interfaces_dict().items()]


def get_auto_wifi_interface():
    wifi_interfaces = get_ifaces_names(True)
    net_interfaces = map(lambda (x, y): x, get_interfaces_dict().items())
    for wifi in wifi_interfaces:
        if wifi not in net_interfaces:
            return str(wifi)

    return None


def get_default_iface():
    route = "/proc/net/route"
    with open(route) as f:
        for line in f.readlines():
            try:
                iface, dest, _, flags, _, _, _, _, _, _, _, = line.strip().split()
                if dest != '00000000' or not int(flags, 16) & 2:
                    continue
                return iface
            except:
                continue

    return None


def get_ifaces_names(wireless=False):
    return [f.split('/')[-2] for f in glob.glob("/sys/class/net/*/phy80211")] if wireless \
        else os.listdir('/sys/class/net')


def get_interface_mac(ifname):
    if ifname is None:
        return None
        # return '00:de:ad:be:ef:00'
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, struct.pack('256s', ifname[:15]))
    s.close()
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]


def set_interface_mac(interface, newmac):
    ''' Set the device's mac address. Device must be down for this to
        succeed. '''
    if interface is None or newmac is None:
        return

    print('Setting interface %s MAC address to %s' % (interface, newmac))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        macbytes = [int(i, 16) for i in newmac.split(':')]
        ifreq = struct.pack('16sH6B8x', str(interface), socket.AF_UNIX, *macbytes)
        fcntl.ioctl(s.fileno(), SIOCSIFHWADDR, ifreq)
        s.close()
    except:
        pass


def set_channel(interface, channel):
    if interface is None or channel is None:
        return

    if channel < 1 or channel > 13:
        return

    print('Set %s channel %i' % (interface, channel))
    try:
        st = struct.pack('16sihbb', str(interface), channel, 0, 0, 0)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        fcntl.ioctl(s.fileno(), SIOCSIWFREQ, st)
        s.close()
    except:
        pass


@click.group()
@click.option('--debug', help='Enable debug output', is_flag=True)
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
        raise click.BadParameter('Non valid IP address')


def validate_inet(ctx, param, value):
    if value not in get_iface_list():
        raise click.BadParameter('Non valid inet interface')
    return value


def validate_wlan(ctx, param, value):
    if value not in get_ifaces_names(True):
        raise click.BadParameter('Non valid wireless interface')
    return value


def validate_password(ctx, param, value):
    if len(value) < 8:
        raise click.BadParameter('WiFi password must be 8 chars length minimum')
    return value


def validate_mac(ctx, param, value):
    if not re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", value.lower()):
        raise click.BadParameter('Non valid MAC address')
    return value.lower()


def validate_channel(ctx, param, value):
    if not isinstance(value, int):
        raise click.BadParameter('Non valid WiFi channel. Should be integer')

    ival = int(value)
    if 0 < ival < 15:
        return ival

    raise click.BadParameter('Non valid WiFi channel. Should be > 0 and < 15')


@cli.command()
@click.option('-W', '--wlan', prompt='WiFi interface to use for AP', callback=validate_wlan,
              default=get_auto_wifi_interface())
@click.option('-I', '--inet', prompt='Network interface connected to Internet', callback=validate_inet,
              default=get_default_iface())
@click.option('-i', '--ip', prompt='Access point IP address', callback=validate_ip, default='192.168.45.1')
@click.option('-n', '--netmask', prompt='Netmask for network', callback=validate_ip, default='255.255.255.0')
@click.option('-m', '--mac', prompt='WiFi interface MAC address', callback=validate_mac,
              default=get_interface_mac(get_auto_wifi_interface()))
@click.option('-c', '--channel', prompt='WiFi channel to use for AP', default=6, type=int, callback=validate_channel)
@click.option('-s', '--ssid', prompt='WiFi access point SSID', default='hostapd')
@click.option('-p', '--password', prompt='WiFi password', hide_input=True, confirmation_prompt=True,
              callback=validate_password, default='12345678')
@click.pass_context
def configure(ctx, wlan, inet, ip, netmask, mac, channel, ssid, password):
    '''Configure Hotspotd'''
    h = Hotspotd(wlan, inet, ip, netmask, mac, channel, ssid, password)
    h.save()


@cli.command()
@click.pass_context
def start(ctx):
    '''Start hotspotd'''
    h = Hotspotd()
    click.echo('Loading configuration')
    h.load()
    click.echo('Starting...')
    h.start()


@cli.command()
@click.pass_context
def stop(ctx):
    '''Stop Hotspotd'''
    h = Hotspotd()
    click.echo('Loading configuration')
    h.load()
    click.echo('Stopping...')
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
