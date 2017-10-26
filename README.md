
**Important**

Beta version for Ubuntu 16.04.


This script allows for keepalived to attach an OpenStack floating IP to an instance during a state transition. This way, a floating IP can be made high-available between instances.



## Requirements

Software required:

- Python 2.7
- Python requests
- dmidecode

On Ubuntu this can be installed with the following command:

	apt-get install python python-requests dmidecode

You need at least two instances on our OpenStack with a floating IP. An internal VIP is not required.

The configuration file required the `tenant id`, the username and the password. And of course the floating IP's.

## Setup instructions

This guide assumes two servers setup in the same network (different availability zones are recommended) already setup. All instructions must be executed on both servers.

Reserve a floating IP you want to use for high-availability. Read our [Getting Started](https://www.cloudvps.nl/openstack/openstack-getting-started) guide for more instructions on floating IP's and network setup.

### Script

Create the folder:

	mkdir -p /etc/cloudvps/

Place the script inside folder:

	wget -O /etc/cloudvps/ha-ip-failover.py https://raw.githubusercontent.com/CloudVPS/openstack-ha-floating-ip-failover/master/ha-ip-failover.py

Make it executable:

	chmod +x /etc/cloudvps/ha-ip-failover.py

Place the config file:

	wget -O /etc/cloudvps/ha-ip-config.json https://raw.githubusercontent.com/CloudVPS/openstack-ha-floating-ip-failover/master/ha-ip-config.json.example

Change the configuration and fill in your own values:

	{
	  "username": "AzureDiamond",
	  "password": "hunter2",
	  "tenant_id": "1234abcd...",
	  "floatingips": {
	    "83.96.236.198": "192.168.0.7",
	    "83.96.236.143": "192.168.0.7",
	    "83.96.236.84": "192.168.0.6"
	  } 
	}


The `floatingips` section defines the floating IP as the key, and the internal IP as the value. The internal IP must be an IP that is attached to the instance. If instance 1 has IP `192.168.0.7` and instance 2 has IP `192.168.0.8`, you will end up with two different configuration files where the internal IP's are different.

Multiple floating IP's are accepted, both on the same interface as on different interfaces.

### Verify

After you've configured the script and installed the required software, you must test it to make sure it works. There is a special `VERIFY` option:

	/etc/cloudvps/ha-ip-failover.py VERIFY

Output:

	OK: Token creation successfull.
	OK: Network API URL found.
	OK: Port data found.
	OK: Port data for this instance found.
	OK: Floating IP's found.
	OK: Floating IP 83.96.236.251 found in this tenant
	OK: Floating IP 83.96.236.250 found in this tenant
	OK: All configured floating IP's found in this tenant
	OK: 192.168.0.4 found on instance port d95e3657-97a8-41ce-8d99-a082cb9a99cd
	OK: 192.168.0.4 found on instance port d95e3657-97a8-41ce-8d99-a082cb9a99cd

If there are errors, they are reported:

	[cloudvps] 2017-10-02 16:08:16,497 [ERROR]  Internal IP 192.168.0.5 not bound to this instance ports.

If your authentication data is not correct:

	[cloudvps] 2017-10-02 16:08:59,011 [ERROR]  Request output: 404 POST https://identity.openstack.cloudvps.com/v3/auth/tokens
	[cloudvps] 2017-10-02 16:08:59,011 [ERROR]  Token creation failed: 404 Client Error: Not Found for url: https://identity.openstack.cloudvps.com/v3/auth/tokens

If the config file is not valid JSON:

	[cloudvps] 2017-10-02 16:10:04,951 [ERROR]  Reading config file failed: Expecting , delimiter: line 7 column 17 (char 215)


### Keepalived 

Keepalived is the software that handles the high availability using the VRRP protocol. Normally you can use it for high availability IP's between nodes in the same network. In our case it is used to attach a floating IP to an instance during a state transition. The `virtual_ipaddress` section therefore is not required.


Install Keepalived:

	apt-get install keepalived

Place the config file on both servers. Make sure prority is different, and fill in a password.

	vim /etc/keepalived/keepalived.conf 

Server 1:

	vrrp_instance VI_1 {
	    state MASTER
	    interface eth0
	    virtual_router_id 51
	    priority 150
	    advert_int 1
	    authentication {
	        auth_type PASS
	        auth_pass 
	    }
	    notify /etc/cloudvps/ha-ip-failover.py
	}

Server 2:

	vrrp_instance VI_1 {
	    state MASTER
	    interface eth0
	    virtual_router_id 51
	    priority 100
	    advert_int 1
	    authentication {
	        auth_type PASS
	        auth_pass 
	    }
	    notify /etc/cloudvps/ha-ip-failover.py
	}


This configuration has the IP on Server 1 and will only failover to server 2 when server 1 is offline.