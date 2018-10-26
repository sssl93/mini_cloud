from .drivers import ObjMock
from libcloud.compute.drivers.azure_arm import AzureNetworkSecurityGroup, AzureImage, RESOURCE_API_VERSION, \
    AzureSubnet, AzureVhdImage, NodeAuthSSHKey, NodeAuthPassword, AzureNic
from public_cloud.utils import utc2local, thread_run
from libcloud.common.exceptions import BaseHTTPError
from libcloud.compute.types import NodeState
from libcloud.compute.drivers import azure_arm
from libcloud.compute.providers import DRIVERS
from public_cloud.extend.common import format_security_rule
from libcloud.common.types import LibcloudError
import gevent, base64, logging
import binascii
import os, time

LOG = logging.getLogger(__name__)


class AzureNodeDriver(azure_arm.AzureNodeDriver):
    @staticmethod
    def _get_image_os_type(image):
        if 'windows' in image.offer.lower():
            return 'windows'
        if image.offer.lower() in ['centos', 'redhat', 'debian', 'ubuntu', 'linux mint',
                                   'opensuse', 'fedora', 'pc-bsd', 'rhel', 'gentoo',
                                   'lfs', 'freebsd', 'openbsd', 'solaris', 'opensolaris',
                                   'mindriva', 'gentoo', 'arch', 'slackware']:
            return 'linux'
        return 'windows' if image.publisher.startswith('Microsoft') else 'linux'

    @staticmethod
    def _get_resource_group(source_id):
        """
        Get the resource group from resource id
        :param source_id: the resource id
        :return: str or None
        """
        left = '/resourceGroups/'
        right = '/providers/'
        left_index = source_id.find(left)
        right_index = source_id.find(right)
        if right_index > left_index > -1:
            return source_id[left_index + len(left):right_index]

    @staticmethod
    def _to_security_rule(rule, group_id):
        direction_map = {'Inbound': 'ingress', 'Outbound': 'egress'}
        protocol_map = {'tcp': 'TCP', 'UDP': 'UDP', '*': 'ALL'}
        policy_map = {'Allow': 'accept', 'Deny': 'drop'}

        properties = rule['properties']

        dest_port_range = ','.join(properties['destinationPortRanges'])
        if not dest_port_range:
            dest_port_range = properties['destinationPortRange']

        source_port_range = ','.join(properties['sourcePortRanges'])
        if not source_port_range:
            source_port_range = properties['sourcePortRange']

        dest_cidr = ','.join(properties['destinationAddressPrefixes'])
        if not dest_cidr:
            dest_cidr = properties['destinationAddressPrefix']

        source_cidr = ','.join(properties['sourceAddressPrefixes'])
        if not source_cidr:
            source_cidr = properties['sourceAddressPrefix']

        cidr, port_range = dest_cidr, dest_port_range
        if properties['direction'] == 'Inbound':
            cidr, port_range = source_cidr, source_port_range

        data = {'id': rule['id'], 'base64_id': base64.b64encode(rule['id']), 'name': rule['name'],
                'direction': direction_map.get(properties['direction']), 'priority': properties['priority'],
                'protocol': protocol_map.get(properties['protocol'], properties['protocol']),
                'port_range': port_range, 'source_port_range': source_port_range, 'dest_port_range': dest_port_range,
                'policy': policy_map.get(properties['access']),
                'cidr': cidr, 'source_cidr': source_cidr, 'dest_cidr': dest_cidr, 'group_id': group_id}
        format_security_rule(data)
        return data

    def _to_volume(self, volume_obj, name=None, ex_resource_group=None):
        """
        Format the volume value, you can add other fields to the volume object
        :param volume_obj: source volume object
        :param name: An optional name for the volume.
        :param ex_resource_group: An optional resource group for the volume.
        :return:
        """
        volume = super(AzureNodeDriver, self)._to_volume(volume_obj, name, ex_resource_group)
        volume.extra['resource_group'] = self._get_resource_group(volume.id)
        volume.owner_id = volume.extra['properties'].get('ownerId') or ''
        volume.owner = volume.owner_id.split('/')[-1]
        volume.created_at = utc2local(volume.extra['properties'].get('timeCreated'))
        volume.location = volume.extra.get('location')
        return volume

    def _to_snapshot(self, snapshot_obj, name=None, ex_resource_group=None):
        """
        Format the snapshot value, you can add other fields to the node object
        :param snapshot_obj: source snapshot object
        :param name: An optional name for the snapshot.
        :param ex_resource_group: An optional resource group for the snapshot.
        :return: snapshot
        """
        snapshot = super(AzureNodeDriver, self)._to_snapshot(snapshot_obj, name, ex_resource_group)
        if snapshot.created:
            snapshot.created_at = snapshot.created.strftime('%Y-%m-%d %H:%M')
        snapshot.owner_id = snapshot.extra.get('volume_id') or ''
        snapshot.owner = snapshot.owner_id.split('/')[-1]
        snapshot.location = snapshot.extra.get('location')
        snapshot.extra['resource_group'] = self._get_resource_group(snapshot.extra.get('source_id'))
        return snapshot

    def _to_node(self, data, fetch_nic=False, fetch_power_state=False):
        """
        Format the node value, you can add other fields to the node object
        :param data: source data of node
        :param fetch_nic: if true, get the nic data of the node
        :param fetch_power_state: if true, get the power state of the node
        :return node
        """
        node = super(AzureNodeDriver, self)._to_node(data, fetch_nic, fetch_power_state)
        node.location = node.extra['location']
        node.extra['resource_group'] = self._get_resource_group(node.id)
        img = node.extra['properties']['storageProfile']['imageReference']
        image = '{}:{}:{}:{}'.format(img['offer'], img['publisher'], img['sku'], img['version'])
        node.image = image
        node.size = node.extra['properties']['hardwareProfile']['vmSize']
        node.ips = node.public_ips or node.private_ips
        node.volume_attach_enabled = len(node.extra['properties']['storageProfile']['dataDisks']) < 1
        return node

    def list_nodes(self, ex_resource_group=None, ex_fetch_nic=True, ex_fetch_power_state=True, locations=None):
        """
        Get the list of nodes.
        :param ex_resource_group: filter by resource group
        :param ex_fetch_nic: the param had deserted
        :param ex_fetch_power_state: the param had deserted
        :param locations: the locations of nodes
        :return:
        """
        if ex_resource_group:
            action = "/subscriptions/%s/resourceGroups/%s/" \
                     "providers/Microsoft.Compute/virtualMachines" \
                     % (self.subscription_id, ex_resource_group)
        else:
            action = "/subscriptions/%s/providers/Microsoft.Compute/" \
                     "virtualMachines" \
                     % (self.subscription_id,)
        source_nodes = self.fetch_all_data(action, params={"api-version": "2017-12-01"})
        events = gevent.joinall([gevent.spawn(self._to_node, *(n, False, False)) for n in source_nodes])
        location_ids = [location.id for location in locations] if locations else None

        nodes = []
        for item in events:
            node = item.value
            if location_ids and node.location not in location_ids:
                continue
            nodes.append(node)

        return nodes

    def create_node(self, name, size, image, auth, ex_resource_group, ex_storage_account, ex_blob_container="vhds",
                    location=None, ex_user_name="azureuser", ex_network=None, ex_subnet=None, ex_nic=None,
                    ex_tags=None, ex_customdata="", ex_use_managed_disks=False, ex_storage_account_type="Standard_LRS",
                    ex_security_group=None):
        if location is None:
            location = self.default_location

        public_ip = self.ex_create_public_ip(name + '_public_ip', ex_resource_group, location)
        if ex_network is None:
            raise ValueError("Must provide either ex_network or ex_nic")
        if ex_subnet is None:
            ex_subnet = "default"
        subnet_id = "/subscriptions/%s/resourceGroups/%s/providers" \
                    "/Microsoft.Network/virtualnetworks/%s/subnets/%s" % \
                    (self.subscription_id, ex_resource_group, ex_network, ex_subnet)
        subnet = AzureSubnet(subnet_id, ex_subnet, {})
        ex_nic = self.ex_create_network_interface(name + "-nic", subnet, ex_resource_group, location, public_ip,
                                                  security_group=ex_security_group)

        auth = self._get_and_check_auth(auth)

        target = "/subscriptions/%s/resourceGroups/%s/providers" \
                 "/Microsoft.Compute/virtualMachines/%s" % \
                 (self.subscription_id, ex_resource_group, name)

        os_type = self._get_image_os_type(image)
        if isinstance(image, AzureVhdImage):
            instance_vhd = self._get_instance_vhd(
                name=name,
                ex_resource_group=ex_resource_group,
                ex_storage_account=ex_storage_account,
                ex_blob_container=ex_blob_container)
            storage_profile = {
                "osDisk": {
                    "name": name,
                    "osType": os_type,
                    "caching": "ReadWrite",
                    "createOption": "FromImage",
                    "image": {
                        "uri": image.id
                    },
                    "vhd": {
                        "uri": instance_vhd,
                    }
                }
            }
            if ex_use_managed_disks:
                raise LibcloudError(
                    "Creating managed OS disk from %s image "
                    "type is not supported." % type(image))
        elif isinstance(image, AzureImage):
            storage_profile = {
                "imageReference": {
                    "publisher": image.publisher,
                    "offer": image.offer,
                    "sku": image.sku,
                    "version": image.version
                },
                "osDisk": {
                    "name": name,
                    "osType": os_type,
                    "caching": "ReadWrite",
                    "createOption": "FromImage"
                }
            }
            if ex_use_managed_disks:
                storage_profile["osDisk"]["managedDisk"] = {
                    "storageAccountType": ex_storage_account_type
                }
            else:
                instance_vhd = self._get_instance_vhd(
                    name=name,
                    ex_resource_group=ex_resource_group,
                    ex_storage_account=ex_storage_account,
                    ex_blob_container=ex_blob_container)
                storage_profile["osDisk"]["vhd"] = {
                    "uri": instance_vhd
                }
        else:
            raise LibcloudError(
                "Unknown image type %s, expected one of AzureImage, "
                "AzureVhdImage." % type(image))

        data = {
            "id": target,
            "name": name,
            "type": "Microsoft.Compute/virtualMachines",
            "location": location.id,
            "tags": ex_tags,
            "properties": {
                "hardwareProfile": {
                    "vmSize": size.id
                },
                "storageProfile": storage_profile,
                "osProfile": {
                    "computerName": name
                },
                "networkProfile": {
                    "networkInterfaces": [
                        {
                            "id": ex_nic.id
                        }
                    ]
                }
            }
        }

        if ex_customdata:
            data["properties"]["osProfile"]["customData"] = \
                base64.b64encode(ex_customdata)

        data["properties"]["osProfile"]["adminUsername"] = ex_user_name

        if isinstance(auth, NodeAuthSSHKey):
            data["properties"]["osProfile"]["adminPassword"] = \
                binascii.hexlify(os.urandom(20)).decode("utf-8")
            data["properties"]["osProfile"]["linuxConfiguration"] = {
                "disablePasswordAuthentication": "true",
                "ssh": {
                    "publicKeys": [
                        {
                            "path": '/home/%s/.ssh/authorized_keys' % (
                                ex_user_name),
                            "keyData": auth.pubkey
                        }
                    ]
                }
            }
        elif isinstance(auth, NodeAuthPassword):
            if os_type == 'linux':
                data["properties"]["osProfile"]["linuxConfiguration"] = {
                    "disablePasswordAuthentication": "false"
                }
            data["properties"]["osProfile"]["adminPassword"] = auth.password
        else:
            raise ValueError(
                "Must provide NodeAuthSSHKey or NodeAuthPassword in auth")

        r = self.connection.request(
            target,
            params={"api-version": RESOURCE_API_VERSION},
            data=data,
            method="PUT")

        node = self._to_node(r.object)
        node.size = size
        node.image = image
        return node

    def ex_list_security_groups(self, location=None, resource_group=None):
        """
        List network security groups.
        """

        action = "/subscriptions/%s/providers/" \
                 "Microsoft.Network/networkSecurityGroups" \
                 % (self.subscription_id,)
        r = self.connection.request(action, params={"api-version": "2018-04-01"})
        groups = []
        for net in r.object['value']:
            group = AzureNetworkSecurityGroup(net["id"], net["name"], net["location"], net["properties"])
            group.resource_group = self._get_resource_group(group.id)

            # filter by location or resource_group
            if location and net["location"] != location.id \
                    or resource_group and group.resource_group != resource_group:
                continue

            groups.append(group)
        return groups

    def ex_create_security_group(self, name, resource_group, location=None):
        """
        Create a new security group, the method finally call `ex_create_network_security_group`
        :param str name: the name of security group
        :param str resource_group:
        :param str location:
        :return:
        """
        if location:
            location = ObjMock(location)
        return self.ex_create_network_security_group(name, resource_group, location)

    def ex_update_security_group_by_id(self, group_id, name=None, location=None):
        """
        Update security group by id.
        :param group_id: the id of security group
        :param name: new name of security group
        :param location: new location of security group
        :return:
        """
        if location:
            location = ObjMock(location)
        data = {
            "location": location.id,
            "name": name,
        }
        self.connection.request(group_id, params={"api-version": "2016-09-01"}, data=data, method='PUT')

    def ex_delete_security_group_by_id(self, group_id):
        """
        Delete security group by id.
        :param group_id: the group id which you want to delete
        :return: True
        """
        self.connection.request(
            group_id, params={"api-version": "2016-09-01"},
            data={}, method='DELETE')
        return True

    def list_images(self, location=None, ex_publisher=None, ex_offer=None, ex_sku=None, ex_version=None):
        """
        Get the list of images.
        :param location: filter by the location of images
        :param ex_publisher: filter by the publisher of images
        :param ex_offer: filter by the offer of images
        :param ex_sku: filter by the sku of images
        :param ex_version: filter by the version of images
        :return: list of images
        """

        def get_image(pub, images):
            if not ex_offer:
                offers = self.ex_list_offers(pub[0])
            else:
                offers = [("%s/artifacttypes/vmimage/offers/%s" % (pub[0], ex_offer), ex_offer)]

            for off in offers:
                if not ex_sku:
                    skus = self.ex_list_skus(off[0])
                else:
                    skus = [("%s/skus/%s" % (off[0], ex_sku), ex_sku)]

                for sku in skus:
                    if not ex_version:
                        versions = self.ex_list_image_versions(sku[0])
                    else:
                        versions = [("%s/versions/%s" % (sku[0], ex_version), ex_version)]

                    for v in versions:
                        images.append(AzureImage(v[1], sku[1], off[1], pub[1], loc.id, self.connection.driver))

        images = []

        if location is None:
            locations = [self.default_location]
        else:
            locations = [location]

        for loc in locations:
            if not ex_publisher:
                publishers = self.ex_list_publishers(loc)
            else:
                publishers = [(
                    "/subscriptions/%s/providers/Microsoft"
                    ".Compute/locations/%s/publishers/%s" %
                    (self.subscription_id, loc.id, ex_publisher),
                    ex_publisher)]
            gevent.joinall([gevent.spawn(get_image, *(pub, images,)) for pub in publishers])

        return images

    def ex_node_extend(self, node):
        """
        Get the extend information of node.
        :param node: node object
        :return: node
        """
        private_ips = []
        public_ips = []
        for nic in node.extra["properties"]["networkProfile"]["networkInterfaces"]:
            try:
                n = self.ex_get_nic(nic["id"])
                private_ip = n.extra["ipConfigurations"][0]["properties"].get("privateIPAddress")
                if private_ip:
                    private_ips.append(private_ip)
                public_ip = n.extra["ipConfigurations"][0]["properties"].get("publicIPAddress")
                if public_ip:
                    node.extra['public_ip_id'] = public_ip["id"]
                    pub_address = self.ex_get_public_ip(public_ip["id"])
                    address = pub_address.extra.get("ipAddress")
                    if address:
                        public_ips.append(address)
            except BaseHTTPError:
                pass

        node.public_ips = public_ips
        node.private_ips = private_ips
        node.ips = public_ips or private_ips
        node.state = self.ex_list_node_state(node.id)

        return node

    def list_volumes(self, ex_resource_group=None, locations=None):
        """
        Get list of volumes.
        :param ex_resource_group: resource group of volumes
        :param locations: filter by list of locations
        :return: list of volumes
        """
        if ex_resource_group:
            action = u'/subscriptions/{subscription_id}/resourceGroups' \
                     u'/{resource_group}/providers/Microsoft.Compute/disks'
        else:
            action = u'/subscriptions/{subscription_id}' \
                     u'/providers/Microsoft.Compute/disks'

        action = action.format(subscription_id=self.subscription_id, resource_group=ex_resource_group)

        location_ids = [location.id for location in locations] if locations else None

        volumes = []
        for volume in self.fetch_all_data(action, 'GET', {'api-version': RESOURCE_API_VERSION}):
            if location_ids and volume.get('location') not in location_ids:
                continue
            volumes.append(self._to_volume(volume))
        return volumes

    def fetch_all_data(self, action, method='GET', params=None):
        """
        Fetch data of all pages.
        :param action: the url of action
        :param method: the method of http request
        :param params: the params of request
        :return: list of data
        """
        result = []
        response = self.connection.request(action, method=method, params=params)
        result.extend(response.object['value'])
        next_link = response.object.get('nextLink')
        while next_link:
            url_index = response.object['nextLink'].find(self.connection.host) + len(self.connection.host)
            response = self.connection.request(next_link[url_index:], method=method, params=params)
            result.extend(response.object['value'])
            next_link = response.object.get('nextLink')
        return result

    def ex_list_security_rules(self, group_id):
        """
        Get the security rules from group id.
        :param str group_id: security group id
        :return:
        """
        action = "%s/securityRules" % (group_id,)
        r = self.connection.request(action, params={"api-version": "2018-04-01"})
        rules = []
        for rule in r.object['value']:
            rules.append(self._to_security_rule(rule, group_id))
        return rules

    def ex_create_security_rule(self, group_id, name, direction, policy, cidr, priority,
                                protocol='tcp', from_port=None, to_port=None, ):
        """
        Create security rule.
        :param str group_id: security group id
        :param str name: the name of new rule
        :param str direction: 'ingress' and 'egress'
        :param str policy: 'accept' and 'drop'
        :param str from_port: The beginning of the port range to open
        :param str to_port: The end of the port range to open
        :param str cidr: IP ranges to allow traffic for, such as '10.20.0.0/24'
        :param int priority: the priority of rule
        :param str protocol: 'Tcp', 'Udp' and 'all'
        :return:
        """
        action = '%s/securityRules/%s' % (group_id, name)
        port_range = from_port if from_port == to_port else '%s-%s' % (from_port, to_port)
        if protocol == 'all':
            port_range = protocol = '*'

        if direction == 'ingress':
            source_cidr, dest_cidr = cidr, '*'
            source_port_range, dest_port_range = port_range, '*'
        elif direction == 'egress':
            source_cidr, dest_cidr = '*', cidr
            source_port_range, dest_port_range = '*', port_range
        else:
            raise Exception("Invalid direction: `%s`, 'ingress' and 'degress' were supported.")

        data = {'properties': {
            'access': {'accept': 'Allow', 'drop': 'Deny'}.get(policy, 'Inbound'),
            'direction': {'ingress': 'Inbound', 'egress': 'Outbound'}.get(direction, 'Inbound'),
            'protocol': protocol,
            'SourcePortRange': source_port_range,
            'SourceAddressPrefix': source_cidr,
            'priority': priority,
            'destinationPortRange': dest_port_range,
            'destinationAddressPrefix': dest_cidr
        }}
        self.connection.request(action, params={"api-version": "2018-04-01"}, method='PUT', data=data)

    def ex_delete_security_rule(self, rule_id):
        """
        Delete security rule by id.
        :param str rule_id: the id of rule
        :return:
        """
        self.connection.request(rule_id, params={"api-version": "2018-04-01"}, method='DELETE')

    def ex_list_node_state(self, id):
        """
        List node state.
        :param str id: node id
        :return: str
        """
        state = NodeState.UNKNOWN
        try:
            action = "%s/InstanceView" % (id,)
            r = self.connection.request(action, params={"api-version": "2018-06-01"})
            for status in r.object["statuses"]:
                if status["code"] in ["ProvisioningState/creating"]:
                    state = NodeState.PENDING
                    break
                elif status["code"] == "ProvisioningState/deleting":
                    state = NodeState.TERMINATED
                    break
                elif status["code"].startswith("ProvisioningState/failed"):
                    state = NodeState.ERROR
                    break
                elif status["code"] == "ProvisioningState/updating":
                    state = NodeState.UPDATING
                    break
                elif status["code"] == "ProvisioningState/succeeded":
                    pass

                if status["code"] == "PowerState/deallocated":
                    state = NodeState.STOPPED
                    break
                elif status["code"] == "PowerState/stopped":
                    state = NodeState.PAUSED
                    break
                elif status["code"] == "PowerState/deallocating":
                    state = NodeState.PENDING
                    break
                elif status["code"] == "PowerState/running":
                    state = NodeState.RUNNING
        except BaseHTTPError:
            pass

        return state

    def ex_list_resource_group_storage_account(self, resource_group):
        """
        Get Storage Account by resource group.
        :param str resource_group: the id of resource group
        :return: list
        """
        action = "/subscriptions/%s/resourceGroups/%s/providers/" \
                 "Microsoft.Storage/storageAccounts/" \
                 % (self.subscription_id, resource_group)
        r = self.connection.request(action, params={"api-version": "2018-02-01"})
        return r.object['value']

    def ex_list_resource_group_networks(self, resource_group):
        """
        Get Networks by resource group.
        :param str resource_group: the id of resource group
        :return: list
        """
        action = "/subscriptions/%s/resourceGroups/%s/providers/" \
                 "Microsoft.Network/virtualnetworks/" \
                 % (self.subscription_id, resource_group)
        r = self.connection.request(action, params={"api-version": "2018-02-01"})
        return r.object['value']

    def list_snapshots(self, ex_resource_group=None, locations=None):
        location_ids = [location.id for location in locations] if locations else None
        snapshots = super(AzureNodeDriver, self).list_snapshots(ex_resource_group)
        if location_ids:
            return filter(lambda x: x.location in location_ids, snapshots)
        return snapshots

    def destroy_node(self, node, ex_destroy_nic=True, ex_destroy_vhd=True,
                     ex_poll_qty=10, ex_poll_wait=10):
        """
        Destroy a node.

        :param node: The node to be destroyed
        :type node: :class:`.Node`

        :param ex_destroy_nic: Destroy the NICs associated with
        this node (default True).
        :type node: ``bool``

        :param ex_destroy_vhd: Destroy the OS disk blob associated with
        this node (default True).
        :type node: ``bool``

        :param ex_poll_qty: Number of retries checking if the node
        is gone, destroying the NIC or destroying the VHD (default 10).
        :type node: ``int``

        :param ex_poll_wait: Delay in seconds between retries (default 10).
        :type node: ``int``

        :return: True if the destroy was successful, raises exception
        otherwise.
        :rtype: ``bool``
        """

        do_node_polling = (ex_destroy_nic or ex_destroy_vhd)

        # This returns a 202 (Accepted) which means that the delete happens
        # asynchronously.
        # If returns 404, we may be retrying a previous destroy_node call that
        # failed to clean up its related resources, so it isn't taken as a
        # failure.
        try:
            self.connection.request(node.id, params={"api-version": "2015-06-15"}, method='DELETE')
        except BaseHTTPError as h:
            if h.code == 202:
                pass
            elif h.code == 204:
                # Returns 204 if node already deleted.
                do_node_polling = False
            else:
                raise

        thread_run(self._clean_node_resource, (node,))

    def ex_create_network_interface(self, name, subnet, resource_group,
                                    location=None, public_ip=None, security_group=None):
        """
        Create a virtual network interface (NIC).
        """

        if location is None:
            if self.default_location:
                location = self.default_location
            else:
                raise ValueError("location is required.")

        target = "/subscriptions/%s/resourceGroups/%s/providers" \
                 "/Microsoft.Network/networkInterfaces/%s" \
                 % (self.subscription_id, resource_group, name)

        data = {
            "location": location.id,
            "tags": {},
            "properties": {
                "ipConfigurations": [{
                    "name": "myip1",
                    "properties": {
                        "subnet": {
                            "id": subnet.id,
                        },
                        "privateIPAllocationMethod": "Dynamic"
                    }
                }]
            }
        }

        if public_ip:
            ip_config = data["properties"]["ipConfigurations"][0]
            ip_config["properties"]["publicIPAddress"] = {
                "id": public_ip.id
            }

        # relate security group and subnet
        if security_group:
            security_group_id = '/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/' \
                                'networkSecurityGroups/%s' \
                                % (self.subscription_id, resource_group, security_group)
            subnet_obj = self.connection.request(subnet.id, params={"api-version": "2015-06-15"}).object
            if subnet_obj:
                subnet_obj["properties"]["networkSecurityGroup"] = {"id": security_group_id}
                self.connection.request(subnet.id,
                                        params={"api-version": "2015-06-15"},
                                        data=subnet_obj,
                                        method='PUT')

        r = self.connection.request(target,
                                    params={"api-version": "2015-06-15"},
                                    data=data,
                                    method='PUT')
        return AzureNic(r.object["id"], r.object["name"], r.object["location"],
                        r.object["properties"])

    def _clean_node_resource(self, node):
        # wait node had been removed.
        self._wait_until_cleared(node.id)

        # clean os disk.
        disk_id = node.extra["properties"]["storageProfile"]["osDisk"]['managedDisk'].get('id')
        self._wait_until_cleared(disk_id)

        # clean nic
        interfaces = node.extra["properties"]["networkProfile"]["networkInterfaces"]
        public_ip_list = []
        for nic in interfaces:
            n = self.ex_get_nic(nic["id"])
            public_ip = n.extra["ipConfigurations"][0]["properties"].get("publicIPAddress")
            if public_ip:
                public_ip_list.append(public_ip['id'])

            self._wait_until_cleared(nic['id'], params={"api-version": "2015-06-15"})

        # clean public ip
        for public_ip in public_ip_list:
            self._wait_until_cleared(public_ip, params={"api-version": "2018-08-01"})

        # clean vhd
        vhd = node.extra["properties"]["storageProfile"]["osDisk"].get("vhd")
        if vhd:
            resource_group = self._get_resource_group(node.id)
            self._ex_delete_old_vhd(resource_group, vhd["uri"])
        LOG.info('clean node resource successfully.')
        return True

    def _wait_until_cleared(self, action, params=None, wait_period=2, timeout=600):
        start = time.time()
        end = start + timeout
        if not params:
            params = {"api-version": RESOURCE_API_VERSION}

        clear = False
        while time.time() < end:
            try:
                self.connection.request(action, params=params, method='DELETE')
            except BaseHTTPError as h:
                if h.code in (404, 204):
                    clear = True
                    break
                gevent.sleep(wait_period)

        if clear:
            LOG.info('Resource clear successfully: %s', action)
        else:
            LOG.error('Resource clear failed: %s', action)


DRIVERS['azure_arm'] = ('public_cloud.extend.azure_arm', 'AzureNodeDriver')
