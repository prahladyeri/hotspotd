#Introduction
*Hotspotd* is a small daemon to create a wifi hotspot on linux. It depends on *hostapd* for AP provisioning and *dnsmasq* to assign IP addresses to devices.

Hotspotd works by creating a virtual NAT (Network address transation) table between your connected device and the internet using linux *iptables*.

#Dependencies
 * *dnsmasq* (typically pre-installed on most linux distributions)
 * *hostapd* for AP provisioning

To install hostapd on ubuntu:

```sudo apt-get install hostapd```

Or on RHEL based distros:

```yum install hostapd```

#Installation
To install hotspotd, follow these steps:
```
wget https://github.com/prahladyeri/hotspotd/raw/master/dist/hotspotd-0.1.tar.gz
tar xvf hotspotd-0.1.tar.gz
cd hotspotd-0.1/
sudo python setup.py install
```

To uninstall hotspotd, just say:

```sudo python setup.py uninstall```

#Usage

To start hotspot:
```sudo hotspotd start```

To stop hotspot:
```sudo hotspotd stop```

The first time you run hotspotd, it will ask you for configuration values for SSID, password, etc. Alternatively, you may also run:
```sudo hotspotd configure```

#Troubleshooting

* To create a hotspot, your wifi must support AP mode. To find that out, use this process:

	* Find your kernel driver module in use by issuing the below command:

	```lspci -k | grep -A 3 -i network```

	(example output: ath9k)

	* Now, use the below command to find out your wifi capabilities (replace ath9k by your kernel driver):

	```modinfo ath9k | grep depend```

	* If the above output includes “mac80211” then it means your wifi card will support the AP mode.	

#Testing status
This package has been tested on:
* Ubuntu 12.04 LTS
* Ubuntu 14.04 LTS

In theory, it should work on other distros too, but you will have to try those out and tell me!

#Notes
* Replace `sudo` with `su` or `su -c` if you manage superuser access in that manner.
* PyPI home page could be found at https://pypi.python.org/pypi/hotspotd.
* I need someone to test this daemon across various linux distros. If you are interested in testing of open-source apps, please contact me.
