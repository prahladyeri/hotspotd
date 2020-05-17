#!/usr/bin/env python
# @authors: Prahlad Yeri, Oleg Kupreev
# @description: Small script to create a wifi hotspot on linux
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
__version__ = '0.3.0'

WPA2_CONFIG = """
interface=%s
driver=nl80211
ssid=%s
hw_mode=g
channel=%i
macaddr_acl=0
ignore_broadcast_ssid=%i
auth_algs=1
wpa=2
wpa_passphrase=%s
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
ieee80211d=1
country_code=RU
ieee80211n=1
wmm_enabled=1
"""


OPEN_CONFIG = "interface=%s\nssid=%s\nhw_mode=g\nchannel=%i\nauth_algs=1\nwmm_enabled=1\n"


class Hotspotd(object):
    def __init__(self,
                 wlan=None, inet=None,
                 ip='192.168.45.1', netmask='255.255.255.0', mac='00:de:ad:be:ef:00',
                 channel=6, ssid='hotspod', password='12345678', hidden=False,
                 start_exec=None, stop_exec=None,
                 verbose=False):

        # Network params
        self.wlan = str(wlan)
        self.inet = str(inet)
        self.ip = ip
        self.netmask = netmask

        # AP params
        self.mac = mac
        self.channel = int(channel)
        self.ssid = ssid
        self.password = password
        self.hidden = hidden

        # Exec params
        self.start_exec = start_exec
        self.stop_exec = stop_exec

        # Config files
        self.config_files = {'hotspotd': '/etc/hotspotd.json',
                             # TODO: move config to separate folder?
                             'hostapd': os.path.join(os.path.dirname(os.path.abspath(__file__)), 'run.conf')}

        # Initialize logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%d.%m.%Y %H:%M:%S'))
        self.logger.addHandler(handler)

        # Show current configuration files path
        self.logger.info('Config files:')
        for k in self.config_files.keys():
            self.logger.info('\t%s\t%s' % (k, self.config_files[k]))

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
        except subprocess.CalledProcessError:
            self.logger.error('Subprocess error occured:' + errorstring)
            return errorstring
        except Exception as ex:
            self.logger.error('Exception occured: %s' % ex)
            return errorstring

    def execute_shell(self, command, error=''):
        return self.execute(command, wait=True, shellexec=True, errorstring=error)

    def is_process_running(self, name):
        s = self.execute_shell('ps aux |grep ' + name + ' |grep -v grep')
        return 0 if len(s) == 0 else int(s.split()[1])

    def get_sysctl(self, setting):
        result = self.execute_shell('sysctl ' + setting)
        return result.split('=')[1].lstrip() if '=' in result else result

    def set_sysctl(self, setting, value):
        return self.execute_shell('sysctl -w ' + setting + '=' + value)

    def set_mac(self):
        """ Set the device's mac address. Device must be down for this to succeed. """
        if self.mac is None:
            self.logger.info('No MAC address to set')
            return

        self.logger.info('Setting interface %s MAC address to %s' % (self.wlan, self.mac))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            macbytes = [int(i, 16) for i in self.mac.split(':')]
            ifreq = struct.pack('16sH6B8x', str(self.wlan), socket.AF_UNIX, *macbytes)
            fcntl.ioctl(s.fileno(), SIOCSIFHWADDR, ifreq)
            s.close()
        except Exception as ex:
            self.logger.error('MAC address setup error %s' % ex)

    def set_channel(self):
        self.logger.info('Set %s channel %i' % (self.wlan, self.channel))
        try:
            st = struct.pack('16sihbb', str(self.wlan), self.channel, 0, 0, 0)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            fcntl.ioctl(s.fileno(), SIOCSIWFREQ, st)
            s.close()
        except Exception as ex:
            self.logger.error('Channel setup error %s' % ex)

    def generate_hostapd_config(self):
        # Generate text
        if self.password == '':
            # OPN
            text = OPEN_CONFIG % \
                   (self.wlan, self.ssid, self.channel)
        else:
            # WPA2/PSK
            text = WPA2_CONFIG % \
                   (self.wlan, self.ssid, self.channel, 1 if self.hidden else 0, self.password)

        # Save hostapd conf file
        with open(self.config_files['hostapd'], 'w') as f:
            f.write(text)
            self.logger.info('created hostapd configuration: %s' % self.config_files['hostapd'])

    def start(self, free=False):
        # Check WiFi interfaces existence
        if self.wlan not in get_ifaces_names(True):
            click.secho("Wireless interface %s NOT found" % self.wlan, fg='red')
            return

        # Check Internet interface existence
        if self.inet not in get_ifaces_names():
            click.secho("Internet interface %s NOT found" % self.inet, fg='red')
            return

        # Try to free wireless
        if free:
            # ATTENTION!!! STOP ALL WIRELESS INTERFACES
            try:
                result = self.execute_shell('nmcli radio wifi off')
                if "error" in result.lower():
                    self.execute_shell('nmcli nm wifi off')
                self.execute_shell('rfkill unblock wlan')
                time.sleep(1)
                self.logger.info('done.')
            except Exception as ex:
                self.logger.error('Error caught while freeing wireless %s' % ex)

        # Prepare hostapd configuration file if required
        # if os.path.exists(self.config_files['hostapd']):
        # TODO: ask if config overwrite is needed
        self.generate_hostapd_config()

        # Prepare interface
        self.logger.info('using interface: %s on IP: %s MAC: %s' % (self.wlan, self.ip, self.mac))
        self.execute_shell('ifconfig ' + self.wlan + ' down')
        self.set_mac()
        self.execute_shell('ifconfig %s up %s netmask %s' % (self.wlan, self.ip, self.netmask))

        # Split IP to partss
        time.sleep(2)
        i = self.ip.rindex('.')
        ipparts = self.ip[0:i]

        # stop dnsmasq if already running.
        if self.is_process_running('dnsmasq') > 0:
            self.logger.info('stopping dnsmasq')
            self.execute_shell('killall dnsmasq')

        # stop hostapd if already running.
        if self.is_process_running('hostapd') > 0:
            self.logger.info('stopping hostapd')
            self.execute_shell('killall -9 hostapd')

        # enable forwarding in sysctl.
        self.logger.info('enabling forward in sysctl.')
        self.set_sysctl('net.ipv4.ip_forward', '1')

        # enable forwarding in iptables.
        self.logger.info('creating NAT using iptables: %s <--> %s' % (self.wlan, self.inet))
        self.execute_shell('iptables -P FORWARD ACCEPT')

        # add iptables rules to create the NAT.
        self.execute_shell('iptables --table nat --delete-chain')
        self.execute_shell('iptables --table nat -F')
        self.execute_shell('iptables --table nat -X')
        self.execute_shell('iptables -t nat -A POSTROUTING -o %s -j MASQUERADE' % self.inet)
        self.execute_shell(
            'iptables -A FORWARD -i %s -o %s -j ACCEPT -m state --state RELATED,ESTABLISHED' % (self.inet, self.wlan))
        self.execute_shell('iptables -A FORWARD -i %s -o %s -j ACCEPT' % (self.wlan, self.inet))

        # allow traffic to/from wlan
        self.execute_shell('iptables -A OUTPUT --out-interface %s -j ACCEPT' % self.inet)
        self.execute_shell('iptables -A INPUT --in-interface %s -j ACCEPT' % self.wlan)

        # start dnsmasq
        s = 'dnsmasq --dhcp-authoritative --interface=%s --dhcp-range=%s.20,%s.100,%s,4h' % \
            (self.wlan, ipparts, ipparts, self.netmask)
        self.logger.info('running dnsmasq: %s' % s)
        self.execute_shell(s)

        # start hostapd daemon
        s = 'hostapd -B %s' % self.config_files['hostapd']
        self.logger.info(s)
        time.sleep(2)
        self.execute_shell(s)

        # Execute
        if self.start_exec != '':
            self.logger.info('Executing: %s' % self.start_exec)
            subprocess.Popen(self.start_exec, shell=True, stdout=subprocess.PIPE)

        self.logger.info('hotspot is running.')

    def stop(self):
        # bring down the interface
        self.execute_shell('ifconfig ' + self.wlan + ' down')

        # stop hostapd
        if self.is_process_running('hostapd') > 0:
            self.logger.info('stopping hostapd')
            self.execute_shell('killall -9 hostapd')

        # stop dnsmasq
        if self.is_process_running('dnsmasq') > 0:
            self.logger.info('stopping dnsmasq')
            self.execute_shell('killall dnsmasq')

        # disable forwarding in iptables.
        self.logger.info('disabling forward rules in iptables.')
        self.execute_shell('iptables -P FORWARD DROP')

        # delete iptables rules that were added for wlan traffic.
        self.execute_shell('iptables -D OUTPUT --out-interface ' + self.wlan + ' -j ACCEPT')
        self.execute_shell('iptables -D INPUT --in-interface ' + self.wlan + ' -j ACCEPT')
        self.execute_shell('iptables --table nat --delete-chain')
        self.execute_shell('iptables --table nat -F')
        self.execute_shell('iptables --table nat -X')

        # disable forwarding in sysctl.
        self.logger.info('disabling forward in sysctl.')
        self.set_sysctl('net.ipv4.ip_forward', '0')

        # Execute
        if self.stop_exec != '':
            self.logger.info('Executing: %s' % self.stop_exec)
            subprocess.Popen(self.stop_exec, shell=True, stdout=subprocess.PIPE)

        self.logger.info('hotspot has stopped.')

    def save(self, filename=None):
        fname = self.config_files['hotspotd'] if filename is None else filename

        dc = {'wlan': self.wlan, 'inet': self.inet, 'ip': self.ip, 'netmask': self.netmask, 'mac': self.mac,
              'channel': self.channel,
              'ssid': self.ssid, 'password': self.password, 'hidden': self.hidden,
              'start_exec': self.start_exec, 'stop_exec': self.stop_exec}
        json.dump(dc, open(fname, 'wb'))

        self.logger.info('Configuration saved to %s. Run "hotspotd start" to start the router.' % fname)

    def load(self, filename=None):
        # Read configuration file
        fname = self.config_files['hotspotd'] if filename is None else filename
        self.logger.info('Loading configuration from %s' % fname)
        dc = json.load(open(fname, 'rb'))

        # Load variables
        self.wlan = dc['wlan']
        self.inet = dc['inet']
        self.ip = dc['ip'] if 'ip' in dc else '192.168.45.1'
        self.netmask = dc['netmask'] if 'netmask' in dc else '255.255.255.0'
        self.mac = dc['mac'] if 'mac' in dc else None
        self.channel = dc['channel'] if 'channel' in dc else 6
        self.ssid = dc['ssid'] if 'ssid' in dc else 'hotspotd'
        self.password = dc['password'] if 'password' in dc else ''
        self.hidden = dc['hidden'] if 'hidden' in dc else False
        self.start_exec = dc['start_exec'] if 'start_exec' in dc else None
        self.stop_exec = dc['stop_exec'] if 'stop_exec' in dc else None


def get_stdout(pi):
    result = pi.communicate()
    return result[0] if len(result[0]) > 0 else result[1]


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
    # names = ''
    # outbytes = 0
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
            except Exception as ex:
                # TODO: add error handling
                continue

    return None


def get_ifaces_names(wireless=False):
    return [f.split('/')[-2] for f in glob.glob("/sys/class/net/*/phy80211")] if wireless \
        else os.listdir('/sys/class/net')


def get_interface_mac(ifname):
    if ifname is None:
        return None

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, struct.pack('256s', ifname[:15]))
    s.close()
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]


@click.group()
@click.option('-C', '--config', help='Config file location', type=click.Path(), default='/etc/hotspotd.json')
@click.option('--debug', help='Enable debug output', is_flag=True)
@click.pass_context
def cli(ctx, config, debug):
    ctx.obj = {}
    if os.geteuid() != 0:
        click.secho("You need root permissions to do this, sloth!", fg='red')
        sys.exit(1)

    ctx.obj['DEBUG'] = debug
    ctx.obj['CONFIG'] = config


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
    if 0 > len(value) < 8:
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


# def validate_exec(ctx, param, value):
#     TODO: add validation
#     return value


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
@click.option('-s', '--ssid', prompt='WiFi access point SSID', default='MosMetro_Free')
@click.option('-p', '--password', prompt='WiFi password', hide_input=True, confirmation_prompt=True,
              callback=validate_password, default='')
@click.option('-H', '--hidden', is_flag=True, prompt='Hidden SSID')
@click.option('--start-exec', prompt='execute something on start', default='')
@click.option('--stop-exec', prompt='execute something on stop', default='')
@click.pass_context
def configure(ctx, wlan, inet, ip, netmask, mac, channel, ssid, password, hidden, start_exec, stop_exec):
    """Configure Hotspotd"""
    h = Hotspotd(wlan, inet, ip, netmask, mac, channel, ssid, password, hidden, start_exec, stop_exec)
    h.save(ctx.obj['CONFIG'])


@cli.command()
@click.pass_context
def start(ctx):
    """Start hotspotd"""
    # TODO: add running not in background
    h = Hotspotd()
    h.load(ctx.obj['CONFIG'])
    h.start()


@cli.command()
@click.pass_context
def stop(ctx):
    """Stop Hotspotd"""
    h = Hotspotd()
    h.load(ctx.obj['CONFIG'])
    h.stop()


def check_sysfile(filename):
    if os.path.exists('/usr/sbin/' + filename):
        return '/usr/sbin/' + filename
    elif os.path.exists('/sbin/' + filename):
        return '/sbin/' + filename
    else:
        return ''


@cli.command()
@click.pass_context
def check(ctx):
    """Check dependencies: hostapd, dsmasq"""
    satisfied = True

    if len(check_sysfile('hostapd')) == 0:
        click.secho('hostapd executable not found. Make sure you have installed hostapd.', fg='red')
        satisfied = False

    if len(check_sysfile('dnsmasq')) == 0:
        click.secho('dnsmasq executable not found. Make sure you have installed dnsmasq.', fg='red')
        satisfied = False

    # TODO: add dependencies installation
    if satisfied:
        click.secho('All dependencies found 8).', fg='green')


if __name__ == '__main__':
    cli(obj={})
