#!/usr/bin/env python2
# Copyright (C) 2017 CloudVPS.
# Author: Remy van Elst, https://www.cloudvps.com
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

## Script to change the floating IP during a
## keepalived state transision on the CloudVPS
## OpenStack 2 Cloud.

import argparse
import subprocess
import os
import re
import sys
import json
import logging
import logging.handlers

## Set up syslog
LOG = logging.getLogger()
LOG.setLevel(logging.DEBUG)
_logFormatter = logging.Formatter("[cloudvps] %(asctime)s [%(levelname)-5.5s]  %(message)s")
_syslogHandler = logging.handlers.SysLogHandler(address = '/dev/log')
_syslogHandler.setFormatter(_logFormatter)
LOG.addHandler(_syslogHandler)
_consoleHandler = logging.StreamHandler(stream=sys.stdout)
_consoleHandler.setFormatter(_logFormatter)
_consoleHandler.setLevel(logging.WARNING)
LOG.addHandler(_consoleHandler)

try:
  import requests
except ImportError as e:
  LOG.exception("Error, requests not available. Please install it. ({0})".format(e))
  sys.exit(1)

## commandline parameters
## https://github.com/acassen/keepalived/blob/master/doc/man/man5/keepalived.conf.5#L375
## $1 = "GROUP"|"INSTANCE"
## $2 = name of the group or instance
## $3 = target state of transition (stop only applies to instances)
##     ("MASTER"|"BACKUP"|"FAULT"|"STOP")
## $4 = priority value


## OpenStack 2.0 keystone (using OpenStack 1 auth credentials because of k2k)
keystone_url = "https://identity.openstack.cloudvps.com/v3/auth/tokens"
config_file = "/etc/cloudvps/ha-ip-config.json"


def load_config(config_file):
  """Loads json formatted config file from specified location
  Example config:
  {
    "username": "AzureDiamond",
    "password": "hunter2",
    "tenant_id": "1234abcd...",
    "floatingips": {
      "VRRP_GROUP_1": {
        "83.96.236.198": "192.168.0.7",
        "83.96.236.143": "192.168.0.7"
      },
      "VRRP_GROUP_2": {
        "83.96.236.84": "192.168.0.6"
      }
    }
  }
  """
  try:
    config_data = json.loads(open(config_file).read())
    # Log everything except for password.
    LOG.debug("""Username: {0};
      Tenant ID: {1},
      Floating IP's: {2}""".format(
                              config_data["username"],
                              config_data["tenant_id"],
                              config_data["floatingips"]))
    return config_data
  except Exception as e:
    LOG.error("Reading config file failed: {0}".format(e))
    sys.exit(1)


def usage():
  """ Print usage help information, since we're not fancy with argparse"""
  print("Usage: ")
  print("{0} TYPE NAME STATE".format(sys.argv[0]))
  print("\nthis script must be called from keepalived")
  print("on keepalived state change, attaches floating-ip to new instance")
  print("\nTo verify config:")
  print("{0} VERIFY".format(sys.argv[0]))
  sys.exit(1)

def main():
  """ Magic happens here"""
  for arg in sys.argv:
    LOG.debug(arg)
  instance_uuid = get_instance_uuid()

  # load configuration from file
  config_data = load_config(config_file)


  if(len(sys.argv) == 1):
    usage()

  if sys.argv[1] == "VERIFY":
    LOG.debug("Starting auth verify")
    verify_config(config_data, instance_uuid, keystone_url)
    sys.exit()

  # Keepalived gives 3 arguments.
  if(len(sys.argv) < 3):
    usage()

  # get arguments into variables
  keepalived_type = sys.argv[1]
  keepalived_name = sys.argv[2]
  keepalived_state = sys.argv[3]


  # Only do an action if we're transisitoning to master state
  # if anything else, we don't want to disassociate floating IP's
  # since the neutron api doesn't allow to disassociate a floating ip
  # from a specific port. Just fire and forget disassociate.
  if keepalived_state != "MASTER":
    LOG.error("Not transitioning to master, no action.")
    usage()

  # check if the vrrp group or instance name is defined in the config
  # and if it contains IP addresses
  if keepalived_name in config_data["floatingips"]:
    if len(config_data["floatingips"][keepalived_name]) >= 1:
      LOG.debug("VRRP group {0} found in ha-ip-config.".format(keepalived_name))
    else:
      LOG.error("VRRP group {0} empty.".format(keepalived_name))
      usage()
  else:
    LOG.error("VRRP group {0} not found in ha-ip-config.".format(keepalived_name))
    usage()


  ## Get the auth token and service catalog from keystone
  try:
    auth_request = get_auth_request(config_data["username"],
                                    config_data["password"],
                                    config_data["tenant_id"],
                                    keystone_url)
  except Exception as e:
    LOG.error("""ERROR: token creation failed: ({0})""".format(e))
    sys.exit(1)

  auth_token = auth_request.headers["X-Subject-Token"]
  LOG.debug(auth_token)

  ## get the compute and neutron api endpoint URL's from the catalogs
  compute_url = get_endpoint_url_from_auth_request(type="compute",
                                                   interface="public",
                                                   tenant_id=config_data["tenant_id"],
                                                   auth_request=auth_request)
  network_url = get_endpoint_url_from_auth_request(type="network",
                                                  interface="public",
                                                  tenant_id=config_data["tenant_id"],
                                                  auth_request=auth_request)

  # Get all the ports from neutron for this tenant.
  ## Neutron uses the tenant_id from the auth_token.
  ports_data = get_resource(auth_token, network_url,
                            "/v2.0/ports?fields=id&fields=device_id&fields=fixed_ips")
  instance_ports = get_network_ports_for_this_instance(instance_uuid, ports_data)

  ## get all the floating IP's for this tenant.
  floatingip_data = get_resource(auth_token, network_url, "/v2.0/floatingips")

  ## Loop over the floating IP's in the config,
  ## disassociate them, check if they are unassigned and then associate them to
  ## the port for the internal IP.
  for floatingip, internal_ip in config_data["floatingips"][keepalived_name].items():
    floatingip_uuid = get_floatingip_uuid(floatingip,
                                          floatingip_data,
                                          auth_token)["id"]
    internal_port_uuid = instance_ports[internal_ip]
    # openstack maps a floating IP as the outgoing ip for an instance
    # when a floating ip is deassigned, the outgoing ip changes to
    # the router ip. Which results in timeouts during these requests.
    # therefore we retry and are extra vigilant.
    try:
      deassign_floatingip(floatingip_uuid, network_url, auth_token)
    except Exception as e:
      LOG.debug("Deassign floatingip {0} failed: {1}. Retrying".format(floatingip_uuid, e))
      try:
        deassign_floatingip(floatingip_uuid, network_url, auth_token)
      except Exception as e:
        LOG.debug("Deassign floatingip {0} failed again: {1}.".format(floatingip_uuid, e))
    # do the deassign again just to be sure. When we're here in the code it means there is a
    # failover so make sure we try extra hard.
    try:
      deassign_floatingip(floatingip_uuid, network_url, auth_token)
    except Exception as e:
      LOG.debug("Deassign floatingip {0} failed: {1}. Retrying".format(floatingip_uuid, e))
      try:
        deassign_floatingip(floatingip_uuid, network_url, auth_token)
      except Exception as e:
        LOG.debug("Deassign floatingip {0} failed again: {1}.".format(floatingip_uuid, e))

    # same goes here, network and ip assignment changes, therefore retry.
    try:
      assign_floatingip(floatingip_uuid, internal_port_uuid,
                      network_url, auth_token)
    except Exception as e:
      LOG.debug("Assign floatingip {0} to port {1} failed, retrying: {2}.".format(floatingip_uuid, port_uuid, e))
      try:
        assign_floatingip(floatingip_uuid, internal_port_uuid,
                        network_url, auth_token)
      except Exception as e:
        LOG.debug("Assign floatingip {0} to port {1} failed again: {2}.".format(floatingip_uuid, port_uuid, e))



def assign_floatingip(floatingip_uuid, port_uuid, network_url, auth_token):
  """Assigns floating IP to port"""
  if port_uuid:
    assign_type = "Assign"
  else:
    assign_type = "Deassign"
  LOG.debug("{0} floating IP {1} to port {2}".format(assign_type,
                                                        floatingip_uuid,
                                                        port_uuid))
  headers = {'X-Auth-Token': auth_token,
            'Content-Type': "application/json",
            'User-Agent': 'python-neutronclient'}
  floatingip_url = network_url + "v2.0/floatingips/" + floatingip_uuid
  floatingip_request_data = {"floatingip": {"port_id": port_uuid }}
  try:
    floatingip_request = requests.put(floatingip_url,
                                      json=floatingip_request_data,
                                      headers=headers, timeout=5)
    LOG.info("OK: Request {2} floating IP {0} to port {1}".format(floatingip_uuid, port_uuid, assign_type))
  # during testing there were a lot of timeouts. Therefore we do a built in retry
  except Exception as e:
    LOG.error("Request {2} floating IP {0} to port {1}: {2}".format(floatingip_uuid, port_uuid, e, assign_type))
    time.sleep(5)
    try:
      floatingip_request = requests.put(floatingip_url,
                                      json=floatingip_request_data,
                                      headers=headers, timeout=5)
      LOG.info("OK: Request retry assign floating IP {0} to port {1}".format(floatingip_uuid, port_uuid))
    except Exception as e2:
      LOG.error("Request retry assign floating IP {0} to port {1}: {2}".format(floatingip_uuid, port_uuid, e))

  if floatingip_request.ok:
    LOG.debug("Request assign floating IP to port output: {0} {1} {2} {3}".format(
                                            floatingip_request.status_code,
                                            floatingip_request.request.method,
                                            floatingip_request.request.url,
                                            floatingip_request.request.body))
    return(floatingip_request.json())
  else:
    LOG.error("Request assign floating IP to port output: {0} {1} {2} {3}".format(
                              floatingip_request.status_code,
                              floatingip_request.request.method,
                              floatingip_request.request.url,
                              floatingip_request.request.body))
    floatingip_request.raise_for_status()


def deassign_floatingip(floatingip_uuid, network_url, auth_token):
  """Deassigns floating IP. Uses assign with None as the port ID."""
  LOG.debug("Deassign floating IP {0}.".format(floatingip_uuid))
  return(assign_floatingip(floatingip_uuid, None, network_url, auth_token))


def get_floatingip_uuid(floatingip, floatingip_data, auth_token):
  LOG.debug("Get UUID for floating IP {0}.".format(floatingip))
  for floatingips in floatingip_data["floatingips"]:
    if floatingips["floating_ip_address"] == floatingip:
      LOG.debug("Floating IP {0} had UUID {1}.".format(floatingip,
                                                   floatingips["id"]))
      return floatingips

def get_network_ports_for_this_instance(instance_uuid, ports_data):
  LOG.debug("Get network ports for instance {0}.".format(instance_uuid))
  port_ids = {}
  for ports in ports_data["ports"]:
    if ports["device_id"] == instance_uuid:
      port_ids[ports["fixed_ips"][0]["ip_address"]] = ports["id"]
      LOG.debug("Instance {0} has port {1} with IP {2}.".format(
                                          instance_uuid,
                                          ports["id"],
                                          ports["fixed_ips"][0]["ip_address"]))
  return port_ids


def get_resource(auth_token, endpoint_url, resource_url):
  LOG.debug("Resource request for {0}{1}".format(endpoint_url, resource_url))
  headers = {'X-Auth-Token': auth_token,
            'Content-Type': "application/json",
              'User-Agent': 'python-openstackclient'}
  resource_url = endpoint_url + resource_url
  try:
    resource_request = requests.get(resource_url, headers=headers, timeout=5)
  except Exception as e:
    LOG.error("Request get_resource: {0}".format(e))
    sys.exit(1)
  if resource_request.ok:
    LOG.debug("Request get_resource output: {0} {1} {2} {3}".format(
                                            resource_request.status_code,
                                            resource_request.request.method,
                                            resource_request.request.url,
                                            resource_request.request.body))
    return(resource_request.json())
  else:
    LOG.error("Request get_resource output: {0} {1} {2} {3}".format(
                                            resource_request.status_code,
                                            resource_request.request.method,
                                            resource_request.request.url,
                                            resource_request.request.body))
    resource_request.raise_for_status()


def get_endpoint_url_from_auth_request(type, interface,
                                      tenant_id, auth_request):
  LOG.debug("Get endpoint from auth_request for {0} {1} tenant {2}".format(
                                                type, interface, tenant_id))
  for items in auth_request.json()["token"]["catalog"]:
    if items["type"] == type:
      for endpoints in items["endpoints"]:
        if endpoints["interface"] == interface:
          LOG.debug("Interface {0} has url {1}".format(interface,
                                                          endpoints["url"]))
          return endpoints["url"]


def get_auth_request(username, password, tenant_id, auth_url):
  """Auth request against keystonev3 to get auth_token"""
  LOG.debug("auth request for user {0} tenant {1} auth_url {2}".format(
                                                                  username,
                                                                  tenant_id,
                                                                  auth_url))
  auth_post_data = { "auth": {
                      "identity": {
                        "methods": ["password"],
                        "password": {
                          "user": {
                            "name": username,
                            "domain": { "id": "default" },
                            "password": password
                          }
                        }
                      },
                      "scope": {
                        "project": {
                          "id": tenant_id,
                          "domain": { "id": "default" }
                        }
                      }
                    }
                  }
  try:
    auth_request = requests.post(auth_url, json=auth_post_data, timeout=5)
  except Exception as e:
    LOG.error("Request get_auth_request : {0}".format(e))
    sys.exit(1)
  if auth_request.ok:
    return(auth_request)
  else:
    # don't log body, contains password
    LOG.error("Request get_auth_request  output: {0} {1} {2}".format(
                                      auth_request.status_code,
                                      auth_request.request.method,
                                      auth_request.request.url))
    auth_request.raise_for_status()

def get_instance_uuid():
  """Returns instance UUID from sysfs, UUID:"""
  uuid_path = "/sys/devices/virtual/dmi/id/product_uuid"
  try:
    uuid_file = open(uuid_path).read()
    return uuid_file.lower().rstrip()
  except Exception as e:
    LOG.error("Reading UUID file /sys/devices/virtual/dmi/id/product_uuid failed: {0}".format(e))
    sys.exit(1)

def verify_config(config_data, instance_uuid, keystone_url):
  """Verify's configuration, credentials and connectivity to OpenStack API"""
  ### First try to get an auth_token from keystone
  try:
    instance_uuid = get_instance_uuid()
  except Exception as e:
    LOG.error("Unable to retreive instance UUID: {0}".format(e))
  print("OK: Instance UUID found: {0}".format(instance_uuid))

  try:
    auth_request = get_auth_request(config_data["username"], config_data["password"],
                                    config_data["tenant_id"], keystone_url)
  except Exception as e:
    LOG.error("Token creation failed: {0}".format(e))
    sys.exit(1)
  print("OK: Token creation successfull.")
  auth_token = auth_request.headers["X-Subject-Token"]

  ## Try to get the networking API from the catalog
  try:
    network_url = get_endpoint_url_from_auth_request(type="network", interface="public",
                                                     tenant_id=config_data["tenant_id"],
                                                     auth_request=auth_request)
  except Exception as e:
    LOG.error("Network API URL unavailable: {0}".format(e))
    sys.exit(1)
  print("OK: Network API URL found.")

  ## Try to get all the ports and their fixed IP for this tenant
  try:
    ports_data = get_resource(auth_token, network_url,
                              "/v2.0/ports?fields=id&fields=device_id&fields=fixed_ips")
  except Exception as e:
    LOG.error("Retreiving port data failed: {0}".format(e))
    sys.exit(1)
  print("OK: Port data found.")

  ## Try to get all ports for this instance
  try:
    instance_ports = get_network_ports_for_this_instance(instance_uuid, ports_data)
  except Exception as e:
    LOG.error("Retreiving this instance ports failed: {0}".format(e))
    sys.exit(1)
  print("OK: Port data for this instance found.")

  ## Try to get floating IP's for this tenant.
  try:
    floatingip_data = get_resource(auth_token, network_url, "/v2.0/floatingips")
  except Exception as e:
    LOG.error("Retreiving floatingips failed: {0}".format(e))
    LOG.exception
    sys.exit(1)
  print("OK: Floating IP's found.")

  floatingcounter = {}
  for vrrp_group in config_data["floatingips"]:
    floatingcounter[vrrp_group] = 0
    for floatingip, internal_ip in config_data["floatingips"][vrrp_group].items():
      for floatingips in floatingip_data["floatingips"]:
        if floatingips["floating_ip_address"] == floatingip:
          floatingcounter[vrrp_group] += 1
          print("OK: Floating IP {0}, VRRP group {1} found in this tenant".format(
                                                                floatingip, vrrp_group))

  for vrrp_group in config_data["floatingips"]:
    if len(config_data["floatingips"][vrrp_group]) == floatingcounter[vrrp_group]:
      print("OK: All configured floating IP's for VRRP group {0} found in this tenant".format(
                                                                              vrrp_group))
    else:
      LOG.error("Floating IP's for VRRP group {0} from configfile not found in this tenant.".format(
                                                                                vrrp_group))
      sys.exit(1)

  for vrrp_group in config_data["floatingips"]:
    for floatingip, internal_ip in config_data["floatingips"][vrrp_group].items():
      if not internal_ip in instance_ports:
        LOG.error("Internal IP {0} for VRRP group {1} not bound to this instance ports.".format(
                                                                            internal_ip, vrrp_group))
        sys.exit(1)
      print("OK: {0} found on instance port {1}".format(internal_ip,
                                                    instance_ports[internal_ip]))

  sys.exit(0)

## main
if __name__ == '__main__':
  main()
