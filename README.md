#Introduction
*Hotspotd* is a small linux daemon to create a wifi hotspot on linux. It depends on *hostapd* for AP provisioning and *dnsmasq* to assign IP addresses to devices.

Hotspotd works by creating a virtual NAT (Network address transation) table between your connected device and the internet using *iptables*.

#Dependencies
Since *dnsmasq* is typically included on most linux distributions, *hostapd* is the only dependency that you typically need to install:

```sudo apt-get install hostapd```

Or on RHEL based distros:

```yum install hostapd```

#How to install
To install hotspotd, follow these steps:
```
wget https://github.com/prahladyeri/hotspotd/raw/master/dist/hotspotd-0.1.tar.gz
tar xvf hotspotd-0.1.tar.gz
cd hotspotd-0.1/
sudo python setup.py install
```

You may append the last statement with a --prefix argument in case you don't wish to install the package to the default python pacakges path.

#How to use

To start hotspot:
```sudo hotspotd start```

To stop hotspot:
```sudo hotspotd stop```

The first time you run hotspotd, it will ask you for configuration values for SSID, password, etc. Alternatively, you may also run:
```sudo hotspotd configure```

#Testing status
This package has been tested on:
* Ubuntu 12.04 LTS
* Ubuntu 14.04 LTS

In theory, it should work on other distros too, but you will have to try those out and tell me!

#Notes
* Replace `sudo` with `su` or `su -c` if you manage superuser access in that manner.
* PyPI home page could be found at https://pypi.python.org/pypi/hotspotd.
* I might add GUI support using maybe QT or GTK+ depending on where this goes.
