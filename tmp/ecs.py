# coding:utf-8
from .drivers import ObjMock
from libcloud.utils.xml import findtext, findall
from public_cloud.utils import thread_run, utc2local
from libcloud.common.types import LibcloudError
import time, logging, base64
from libcloud.utils.py3 import urlencode
from libcloud.utils.py3 import ET
from libcloud.compute.drivers.ecs import ECSDriver
from libcloud.compute.drivers.ecs import RESOURCE_EXTRA_ATTRIBUTES_MAP
from libcloud.compute.providers import DRIVERS
from libcloud.compute.base import NodeImage
from libcloud.compute.types import StorageVolumeState
from public_cloud.extend.common import format_security_rule
from libcloud.utils.py3 import _real_unicode as u
import grequests, gevent

LOG = logging.getLogger(__name__)


class ECSNodeDriver(ECSDriver):
    # SECURITY_RULE_KEYS identify a rule
    # We can generate rule uuid through the keys, and recover keys from the uuid
    SECURITY_RULE_KEYS = ['group_id', 'location', 'direction', 'protocol', 'port_range', 'cidr']

    def _generate_security_rule_id(self, data):
        """
        Generate rule id from data.
        :param dict data: source data of rule
        :return: base64 id
        """
        return base64.b64encode(','.join(
            [data[key] for key in self.SECURITY_RULE_KEYS]))

    def _recover_security_rule_id(self, uuid):
        """
        Recover rule data from rule id.
        :param str uuid: the base64 id of rule
        :return: dict
        """
        source = {}
        for i, value in enumerate(base64.b64decode(uuid).split(',')):
            source[self.SECURITY_RULE_KEYS[i]] = value
        return source

    def _wait_until_state(self, nodes, state, wait_period=1, timeout=600):
        node = nodes[0]
        start = time.time()
        end = start + timeout

        while time.time() < end:
            _node = self.ex_get_node(node.id, node.location)
            if _node.state == state:
                return True
            else:
                gevent.sleep(wait_period)
        return False

    def _to_security_rule(self, element, group_id, location):
        # the base data could be able to identify a rule
        base_data = {
            'group_id': group_id, 'location': location,
            'direction': findtext(element, 'Direction', namespace=self.namespace),
            'cidr': findtext(element, 'DestCidrIp', namespace=self.namespace),
            'protocol': findtext(element, 'IpProtocol', namespace=self.namespace),
            'port_range': findtext(element, 'PortRange', namespace=self.namespace)
        }

        rule_id = self._generate_security_rule_id(base_data)

        data = {
            'id': rule_id, 'base64_id': base64.b64encode(rule_id),
            'name': findtext(element, 'Description', namespace=self.namespace),
            'priority': findtext(element, 'Priority', namespace=self.namespace),
            'owner_account': findtext(element, 'SourceGroupOwnerAccount', namespace=self.namespace),
            'policy': findtext(element, 'Policy', namespace=self.namespace).lower(),
            'nic_type': findtext(element, 'NicType', namespace=self.namespace),
            'created_at': utc2local(findtext(element, 'CreateTime', namespace=self.namespace)),
        }
        data.update(base_data)
        format_security_rule(data)  # format rule data
        return data

    def _to_image(self, element):
        _id = findtext(element, 'ImageId', namespace=self.namespace)
        name = findtext(element, 'ImageName', namespace=self.namespace)
        extra = self._get_extra_dict(element, RESOURCE_EXTRA_ATTRIBUTES_MAP['image'])
        extra['disk_device_mappings'] = self._get_disk_device_mappings(element.find('DiskDeviceMappings'))
        image = NodeImage(id=_id, name=name, driver=self, extra=extra)
        image.offer = extra.get('platform')
        image.publisher = extra.get('os_type')
        image.sku = image.version = extra.get('os_name')
        image.size = extra.get('size')
        image.created_at = utc2local(extra.get('creation_time'))
        return image

    @staticmethod
    def _set_location_info(obj):
        if obj.extra.get('region_id'):
            obj.location = obj.extra['region_id']

        if 'zone_id' in obj.extra:
            r_index = obj.extra['zone_id'].rfind('-')
            if r_index > 0:
                obj.extra['display_zone'] = u'可用区 ' + obj.extra['zone_id'][-1].upper()
                obj.location = obj.extra['zone_id'][:r_index]

    def _to_nodes(self, xml_obj):
        """
        Convert response to Node object list

        :param xml_obj: parsed response object
        :return: a list of ``Node``
        :rtype: ``list``
        """
        result = []
        node_elements = findall(xml_obj, 'Instances/Instance', self.namespace)
        for el in node_elements:
            node = self._to_node(el)
            node.size = node.extra['instance_type']
            node.image = node.extra['image_id']
            node.private_ips = [node.extra['vpc_attributes'].get('private_ip_address'), ]
            node.ips = node.public_ips or node.private_ips
            node.created_at = utc2local(node.extra['creation_time'])
            node.volume_attach_enabled = True

            self._set_location_info(node)

            result.append(node)
        return result

    def try_start_node(self, node, interval=30, timeout=300):
        end = time.time() + timeout
        while time.time() < end:
            try:
                self.ex_start_node(node)
                LOG.info("node: %s start successfully.", node.id)
                break
            except Exception as e:
                LOG.warning("node: %s start failed, try again in %s seconds...", node.id, interval)
                LOG.exception(e)
                gevent.sleep(interval)
        try:
            self.create_public_ip(node.id)
            LOG.info('create public ip successfully.')
        except Exception as e:
            LOG.exception(e)
            LOG.warning('create public ip failed.')

    def create_node(self, name, size, image, auth=None, location=None,
                    ex_security_group_id=None, ex_description=None, ex_internet_charge_type='PayByTraffic',
                    ex_internet_max_bandwidth_out=5, ex_internet_max_bandwidth_in=5, ex_zone_id=None,
                    ex_hostname=None, ex_io_optimized=None, ex_system_disk=None, ex_data_disks=None,
                    ex_vswitch_id=None, ex_private_ip_address=None, ex_client_token=None):
        """
        @inherits: :class:`NodeDriver.create_node`

        Create a new node under the location.
        required args are `name`, `size`, `image`, `auth`, `location`, `ex_security_group_id`
        """
        region_id = (location.id if hasattr(location, 'id') else location) or self.region
        params = {'Action': 'CreateInstance',
                  'RegionId': region_id,
                  'ImageId': image.id,
                  'InstanceType': size.id,
                  'InstanceName': name}

        if not ex_security_group_id:
            raise AttributeError('ex_security_group_id is mandatory')
        params['SecurityGroupId'] = ex_security_group_id

        if ex_zone_id:
            params['ZoneId'] = ex_zone_id

        if ex_description:
            params['Description'] = ex_description

        inet_params = self._get_internet_related_params(
            ex_internet_charge_type,
            ex_internet_max_bandwidth_in,
            ex_internet_max_bandwidth_out)
        if inet_params:
            params.update(inet_params)

        if ex_hostname:
            params['HostName'] = ex_hostname

        if auth:
            auth = self._get_and_check_auth(auth)
            params['Password'] = auth.password

        if ex_io_optimized is not None:
            optimized = ex_io_optimized
            if isinstance(optimized, bool):
                optimized = 'optimized' if optimized else 'none'
            params['IoOptimized'] = optimized

        if ex_system_disk:
            system_disk = self._get_system_disk(ex_system_disk)
            if system_disk:
                params.update(system_disk)

        if ex_data_disks:
            data_disks = self._get_data_disks(ex_data_disks)
            if data_disks:
                params.update(data_disks)

        if ex_vswitch_id:
            params['VSwitchId'] = ex_vswitch_id

        if ex_private_ip_address:
            if not ex_vswitch_id:
                raise AttributeError('must provide ex_private_ip_address  '
                                     'and ex_vswitch_id at the same time')
            else:
                params['PrivateIpAddress'] = ex_private_ip_address

        if ex_client_token:
            params['ClientToken'] = ex_client_token

        resp = self.connection.request(self.path, params=params)
        node_id = findtext(resp.object, xpath='InstanceId',
                           namespace=self.namespace)
        node = ObjMock(node_id)
        node.location = region_id
        thread_run(self.try_start_node, (node,), wait=10)
        return node

    def get_headers(self):
        """
        Get ECS request headers.
        :return: dict of headers
        """
        # Extend default headers
        if self.connection is None:
            self.connect()

        headers = self.connection.add_default_headers({})
        # We always send a user-agent header
        headers.update({'User-Agent': self.connection._user_agent()})

        # Indicate that we support gzip and deflate compression
        headers.update({'Accept-Encoding': 'gzip,deflate'})

        port = int(self.connection.port)

        if port not in (80, 443):
            headers.update({'Host': "%s:%d" % (self.connection.host, port)})
        else:
            headers.update({'Host': self.connection.host})

        return headers

    @staticmethod
    def parse_xml(content):
        """
        Parse string to xml object.
        :param str content:
        :return: xml object
        """
        if len(content) == 0:
            return content
        try:
            body = ET.XML(content)
        except ValueError:
            # basically hard-coded to str
            body = ET.XML(content.encode('utf-8'))
        return body

    def get_all_locations_data(self, params, parse_func, locations=None, zone=None):
        """
        Get all data under the available locations. Use grequests.
        :param dict params: request params
        :param parse_func: the func to format the data
        :param list locations: the list of location
        :param str zone: zone id
        :return: list of object
        """

        req_list = []
        results = []
        if not locations:
            locations = self.list_locations()
        if self.connection is None:
            self.connection.connect()

        headers = self.get_headers()
        self.connection.method = 'GET'
        self.connection.action = self.path

        if zone:
            params['ZoneId'] = zone

        for location in locations:
            new_params = {'RegionId': location.id}
            new_params.update(params)
            new_params = self.connection.add_default_params(new_params)  # add common params
            url = 'https://{}{}?{}'.format(self.connection.host, self.path, urlencode(new_params))
            req_list.append(grequests.get(url, headers=headers))

        responses = grequests.map(req_list, size=20)
        for i, resp in enumerate(responses):
            if resp:
                obj = self.parse_xml(resp.content)
                obj.location = locations[i].id
                results.extend(parse_func(obj))

        return results

    def list_snapshots(self, locations=None):
        """
        Get all snapshots under the available locations.
        :return:
        """

        def _parse_response(resp_body):
            snapshot_elements = findall(resp_body, 'Snapshots/Snapshot', namespace=self.namespace)
            snapshots = []
            for each in snapshot_elements:
                snapshot = self._to_snapshot(each)
                snapshot.created_at = utc2local(snapshot.created)
                snapshot.owner = snapshot.owner_id = snapshot.extra.get('source_disk_id')
                snapshot.size = snapshot.extra.get('source_disk_size')
                snapshot.name = snapshot.extra.get('snapshot_name')
                snapshot.location = resp_body.location
                snapshots.append(snapshot)
            return snapshots

        return self.get_all_locations_data({'Action': 'DescribeSnapshots'}, _parse_response, locations)

    def ex_create_security_group(self, name, description=None, client_token=None, location=None):
        """
        Create a new security group
        :param str name: the name of security group
        :param str description: security group description
        :param str client_token: a token generated by client to identify each request.
        :param str location: cloud location
        :return:
        """
        params = {'Action': 'CreateSecurityGroup', 'RegionId': location if location else self.region,
                  'SecurityGroupName': name}

        if description:
            params['Description'] = description
        if client_token:
            params['ClientToken'] = client_token
        resp = self.connection.request(self.path, params)
        return findtext(resp.object, 'SecurityGroupId', namespace=self.namespace)

    def ex_get_node(self, id, location=None):
        """
        Get instance by id.
        :param str id: the instance id
        :param str location: cloud location
        :return: node object
        """
        region_id = location.id if hasattr(location, 'id') else location
        params = {'Action': 'DescribeInstances',
                  'RegionId': region_id or self.region,
                  'InstanceIds': self._list_to_json_array([id, ])
                  }
        nodes = self._request_multiple_pages(self.path, params, self._to_nodes)
        if len(nodes) <= 0:
            raise Exception('Cannot get any instance, by id: %s, location: %s' % (id, location))
        node = nodes[0]
        node.location = region_id
        return node

    def list_nodes(self, ex_node_ids=None, ex_filters=None, locations=None, zone=None):
        """
        Get all location nodes, the method query all region nodes
        """
        return self.get_all_locations_data({'Action': 'DescribeInstances'}, self._to_nodes, locations, zone)

    def ex_list_security_groups(self, location=None):
        """
        Get all location security groups.
        :param location: the security groups' location
        :return: list of security group object
        """
        locations = [location, ] if location else None

        def _parse_response(resp_object):
            sg_elements = findall(resp_object, 'SecurityGroups/SecurityGroup', namespace=self.namespace)
            sgs = []
            for el in sg_elements:
                sg = self._to_security_group(el)
                sg.location = resp_object.location
                sgs.append(sg)
            return sgs

        return self.get_all_locations_data({'Action': 'DescribeSecurityGroups'}, _parse_response, locations)

    def list_volumes(self, ex_volume_ids=None, ex_filters=None, locations=None):
        """
        Get all location Volumes. params `ex_volume_ids` and `ex_filters` were not useful.
        """

        def _add_owner(volume):
            volume.owner_id = volume.owner = volume.extra.get('instance_id')
            # if volume.owner_id:
            #     volume.owner = self.ex_get_node(volume.owner_id, volume.location).name
            # else:
            #     volume.owner = volume.owner_id

        def _parse_response(resp_object):
            disk_elements = findall(resp_object, 'Disks/Disk', namespace=self.namespace)
            volumes = []
            for each in disk_elements:
                volume = self._to_volume(each)
                volume.created_at = utc2local(volume.extra.get('creation_time'))

                volume.device = volume.extra.get('device')
                self._set_location_info(volume)
                _add_owner(volume)
                volumes.append(volume)
            return volumes

        return self.get_all_locations_data({'Action': 'DescribeDisks'}, _parse_response, locations)

    def ex_get_volume(self, volume_id, location):
        params = {'Action': 'DescribeDisks',
                  'RegionId': location,
                  'DiskIds': self._list_to_json_array([volume_id, ])}

        def _parse_response(resp_object):
            disk_elements = findall(resp_object, 'Disks/Disk', namespace=self.namespace)
            volumes = [self._to_volume(each) for each in disk_elements]
            return volumes

        return self._request_multiple_pages(self.path, params, _parse_response)

    def destroy_node(self, node):
        """
        Destroy node. Before destroy, stop node firstly.
        :param node: object of node
        :return: the result of response
        """
        try:
            self.ex_stop_node(node)
        except Exception as e:
            LOG.warning("try stop node: %s failed, maybe the node state was stopped.")
        params = {'Action': 'DeleteInstance', 'InstanceId': node.id}
        resp = self.connection.request(self.path, params)
        return resp.success()

    def create_volume(self, size, name, location=None, snapshot=None, ex_zone_id=None,
                      ex_description=None, ex_disk_category=None, ex_client_token=None):
        """
        Create a new volume.
        :param int size: volume size unit GB
        :param str name: volume name
        :param str location: location id
        :param str snapshot: create volume from snapshot id
        :param str ex_zone_id: zone id
        :param str ex_description: the description of volume
        :param str ex_disk_category: disk type `cloud_efficiency` or `cloud_ssd`
        :param str ex_client_token:
        :return: volume id
        """
        region_id = location.id if hasattr(location, 'id') else location
        params = {'Action': 'CreateDisk',
                  'RegionId': region_id or self.region,
                  'DiskName': name,
                  'Size': size}

        if ex_zone_id is None:
            raise AttributeError('ex_zone_id is required')
        params['ZoneId'] = ex_zone_id

        snapshot_id = snapshot.id if hasattr(snapshot, 'id') else snapshot
        if snapshot_id:
            params['SnapshotId'] = snapshot_id

        if ex_description:
            params['Description'] = ex_description
        if ex_disk_category:
            params['DiskCategory'] = ex_disk_category
        if ex_client_token:
            params['ClientToken'] = ex_client_token

        resp = self.connection.request(self.path, params).object
        volume_id = findtext(resp, 'DiskId', namespace=self.namespace)

        return volume_id

    def detach_volume(self, volume, ex_instance_id=None):
        """
        Detaches a volume from a node.
        :param volume: volume object
        :param ex_instance_id: node object or id
        :return
        """
        ins_id = ex_instance_id.id if hasattr(ex_instance_id, 'id') else ex_instance_id
        params = {'Action': 'DetachDisk',
                  'DiskId': volume.id,
                  'InstanceId': ins_id}
        resp = self.connection.request(self.path, params)
        return resp.success() and self._wait_until_volume_state(volume, StorageVolumeState.AVAILABLE, 0.5)

    def create_volume_snapshot(self, volume, name=None, ex_description=None, ex_client_token=None):
        """
        Creates a snapshot of the storage volume.
        :param volume: volume object
        :param str name: the name of new snapshot
        :param str ex_description:
        :param str ex_client_token:
        :return: snapshot id
        """
        params = {'Action': 'CreateSnapshot', 'DiskId': volume.id}
        if name:
            params['SnapshotName'] = name
        if ex_description:
            params['Description'] = ex_description
        if ex_client_token:
            params['ClientToken'] = ex_client_token

        snapshot_elements = self.connection.request(self.path, params).object
        snapshot_id = findtext(snapshot_elements, 'SnapshotId', namespace=self.namespace)
        return snapshot_id

    def destroy_volume_snapshot(self, snapshot):
        """
        Destroy volume snapshot.
        :param str snapshot: snapshot id or object
        :return:
        """
        params = {'Action': 'DeleteSnapshot'}
        snapshot_id = snapshot.id if hasattr(snapshot, 'id') else snapshot
        params['SnapshotId'] = snapshot_id

        resp = self.connection.request(self.path, params)
        return resp.success()

    def destroy_volume(self, volume):
        """
        Destroy volume.
        :param volume: volume object
        :return:
        """
        params = {'Action': 'DeleteDisk', 'DiskId': volume.id}
        resp = self.connection.request(self.path, params)
        return resp.success()

    def get_image(self, image_id, location=None):
        images = self.list_images([location, ])
        images = filter(lambda x: x.id == image_id, images)
        if len(images) != 1:
            raise LibcloudError('could not find the image with id %s' % image_id, driver=self)
        return images[0]

    def list_images(self, locations=None, ex_image_ids=None, ex_filters=None):
        def _parse_response(resp_body):
            image_elements = findall(resp_body, 'Images/Image', namespace=self.namespace)
            images = []
            for each in image_elements:
                image = self._to_image(each)
                image.location = resp_body.location
                images.append(image)
            return images

        return self.get_all_locations_data({'Action': 'DescribeImages'}, _parse_response, locations)

    def ex_delete_security_group_by_id(self, group_id=None, location=None):
        """
        Delete a new security group.

        :keyword group_id: security group id
        :type group_id: ``str``
        :type location: ``str``
        """
        params = {'Action': 'DeleteSecurityGroup',
                  'RegionId': location or self.region,
                  'SecurityGroupId': group_id}
        resp = self.connection.request(self.path, params)
        return resp.success()

    def ex_list_security_rules(self, group_id, location):
        """
        Get the security rules from group id.
        :param str group_id: security group id
        :param str location: the location of security group
        :return:
        """
        params = {'Action': 'DescribeSecurityGroupAttribute', 'RegionId': location, 'SecurityGroupId': group_id}
        resp = self.connection.request(self.path, params)
        xml_obj = self.parse_xml(resp.body)
        result = []
        security_group_id = findtext(xml_obj, 'SecurityGroupId', namespace=self.namespace)

        permissions = findall(xml_obj.find('Permissions'), 'Permission')
        for element in permissions:
            result.append(self._to_security_rule(element, security_group_id, location))
        return result

    def ex_create_security_rule(self, group_id, location, name, direction, policy, cidr,
                                priority, protocol='tcp', from_port=None, to_port=None, ):
        """
        Create security rule.
        :param str group_id: security group id
        :param str location: the location of security group
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
        direction_map = {'ingress': 'AuthorizeSecurityGroup', 'egress': 'AuthorizeSecurityGroupEgress'}
        port_range = '%s/%s' % (from_port, to_port) if protocol != 'all' else '-1/-1'
        action = direction_map.get(direction, 'AuthorizeSecurityGroup')

        params = {'Action': action, 'RegionId': location, 'SecurityGroupId': group_id,
                  'IpProtocol': protocol, 'PortRange': port_range,
                  'Policy': policy,
                  'SourceCidrIp': '0.0.0.0/0',
                  'DestCidrIp': cidr, 'Priority': priority, 'Description': name}

        self.connection.request(self.path, params=params)

    def ex_delete_security_rule(self, rule_id):
        """
        Delete security rule by id.
        :param str rule_id: the id of rule
        :return:
        """
        source = self._recover_security_rule_id(rule_id)
        direction_map = {'ingress': 'RevokeSecurityGroup', 'egress': 'RevokeSecurityGroupEgress'}
        action = direction_map.get(source['direction'], 'RevokeSecurityGroup')

        params = {'Action': action, 'RegionId': source['location'], 'SecurityGroupId': source['group_id'],
                  'IpProtocol': source['protocol'], 'PortRange': source['port_range'],
                  'SourceCidrIp': '0.0.0.0/0', 'DestCidrIp': source['cidr']}

        self.connection.request(self.path, params=params)

    def reboot_node(self, node, ex_force_stop=False):
        """
        Reboot the given node

        @inherits :class:`NodeDriver.reboot_node`

        :keyword ex_force_stop: if ``True``, stop node force (maybe lose data)
                                otherwise, stop node normally,
                                default to ``False``
        :type ex_force_stop: ``bool``
        """
        params = {'Action': 'RebootInstance',
                  'InstanceId': node.id,
                  'ForceStop': u(ex_force_stop).lower()}
        resp = self.connection.request(self.path, params=params)
        if not resp.success():
            raise Exception('reboot node failed.')

        return resp.success()

    def _wait_until_volume_state(self, volume, state, wait_period=1, timeout=15):
        start = time.time()
        end = start + timeout

        while time.time() < end:
            _volume = self.ex_get_volume(volume.id, volume.location)
            if not _volume:
                raise Exception('cannot find volume id: %s' % (volume.id,))
            if _volume[0].state == state:
                return True
            else:
                gevent.sleep(wait_period)
        return False


DRIVERS['aliyun_ecs'] = ('public_cloud.extend.ecs', 'ECSNodeDriver')
