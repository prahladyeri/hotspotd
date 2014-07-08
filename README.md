hotspotd
========

#Introduction
_Hotspotd_ is a small linux daemon to create a wifi hotspot on linux. It depends on hostapd for AP provisioning and dnsmasq to assign IP addresses to devices.

#Dependencies
Since dnsmasq is typically included in most linux distributions, hostapd is the only dependency that you typically need to install:

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
```sudo hotspotd start```

The first time you run hotspotd, it will ask you for configuration values for SSID, password, etc. Alternatively, you may also run:
```sudo hotspotd configure```
