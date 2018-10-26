# coding:utf-8
import hashlib
from mini_cloud.utils.py3 import b
from mini_cloud.common.base import BaseDriver, ConnectionKey


class UUIDMixin(object):
    """
    Mixin class for get_uuid function.
    """

    def __init__(self):
        self.id = None
        self.driver = None
        self._uuid = None

    def get_uuid(self):
        """
        Unique hash for a node, node image, or node size
        :rtype: ``str``
        """
        if not self._uuid:
            self._uuid = hashlib.sha1(b('%s:%s' % (self.id, self.driver.type))).hexdigest()

        return self._uuid

    @property
    def uuid(self):
        return self.get_uuid()


class Node(UUIDMixin):
    """
    Provide a common interface for handling nodes of all types.
    """

    def __init__(self, node_id, name, state, public_ips, private_ips,
                 size=None, image=None, created_at=None, location=None,
                 volume_attach_enabled=True, extra=None):
        self.id = node_id
        self.name = name
        self.state = state
        self.public_ips = public_ips if public_ips else []
        self.private_ips = private_ips if private_ips else []
        self.size = size
        self.created_at = created_at
        self.image = image
        self.extra = extra or {}
        self.location = location
        # TODO how to show display location ?
        self.volume_attach_enabled = volume_attach_enabled
        super(Node, self).__init__()


class NodeSize(UUIDMixin):
    """
    A Base NodeSize class to derive from.
    """

    def __init__(self, size_id, name, ram, disk, bandwidth, price,
                 cpu_core_count=None, created_at=None, location=None, extra=None):
        self.id = size_id
        self.name = name
        self.ram = ram
        self.disk = disk
        self.cpu_core_count = cpu_core_count
        self.created_at = created_at
        self.location = location
        self.bandwidth = bandwidth
        self.price = price
        self.extra = extra or {}
        super(NodeSize, self).__init__()


class NodeImage(UUIDMixin):
    """
    An operating system image.
    """

    def __init__(self, image_id, name, offer=None, publisher=None, sku=None,
                 version=None, size=None, created_at=None, location=None, extra=None):
        self.id = image_id
        self.name = name
        self.offer = offer
        self.publisher = publisher
        self.sku = sku
        self.version = version
        self.size = size
        self.created_at = created_at
        self.location = location
        self.extra = extra or {}
        super(NodeImage, self).__init__()


class NodeLocation(UUIDMixin):
    """
    A physical location where nodes can be.
    """

    def __init__(self, location_id, name, country=None):
        self.id = location_id
        self.name = name
        self.country = country
        super(NodeLocation, self).__init__()


class StorageVolume(UUIDMixin):
    """
    A base StorageVolume class to derive from.
    """

    def __init__(self, volume_id, name, size, state=None, volume_type=None, task=None,
                 owner=None, owner_id=None, created_at=None, location=None, extra=None):
        self.id = volume_id
        self.name = name
        self.size = size
        self.volume_type = volume_type
        self.task = task
        self.owner = owner
        self.owner_id = owner_id
        self.created_at = created_at
        self.location = location
        self.extra = extra
        self.state = state
        super(StorageVolume, self).__init__()


class VolumeSnapshot(UUIDMixin):
    """
    A base VolumeSnapshot class to derive from.
    """

    def __init__(self, snapshot_id, size=None, created_at=None, state=None, name=None,
                 owner=None, owner_id=None, location=None, extra=None):
        self.id = snapshot_id
        self.name = name
        self.size = size
        self.created_at = created_at
        self.state = state
        self.owner = owner
        self.owner_id = owner_id
        self.location = location
        self.extra = extra or {}
        super(VolumeSnapshot, self).__init__()


class NodeAuthSSHKey(object):
    """
    An SSH key to be installed for authentication to a node.
    """

    def __init__(self, pubkey):
        self.pubkey = pubkey


class NodeAuthPassword(object):
    """
    A password to be used for authentication to a node.
    """

    def __init__(self, password, generated=False):
        self.password = password
        self.generated = generated


class KeyPair(object):
    """
    Represents a SSH key pair.
    """

    def __init__(self, name, public_key, fingerprint, private_key=None, extra=None):
        self.name = name
        self.fingerprint = fingerprint
        self.public_key = public_key
        self.private_key = private_key
        self.extra = extra or {}


class NodeDriver(BaseDriver):
    """
    A base NodeDriver class to derive from

    This class is always subclassed by a specific driver.  For
    examples of base behavior of most functions (except deploy node)
    see the dummy driver.

    """

    connectionCls = ConnectionKey
    name = None
    type = None
    port = None
    features = {'create_node': []}

    """
    List of available features for a driver.
        - :meth:`libcloud.compute.base.NodeDriver.create_node`
            - ssh_key: Supports :class:`.NodeAuthSSHKey` as an authentication
              method for nodes.
            - password: Supports :class:`.NodeAuthPassword` as an
              authentication
              method for nodes.
            - generates_password: Returns a password attribute on the Node
              object returned from creation.
    """

    NODE_STATE_MAP = {}
