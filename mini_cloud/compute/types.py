"""
Base types used by other parts of libcloud
"""


class Type(object):
    @classmethod
    def tostring(cls, value):
        """Return the string representation of the state object attribute
        :param str value: the state object to turn into string
        :return: the uppercase string that represents the state object
        :rtype: str
        """
        return value.upper()

    @classmethod
    def fromstring(cls, value):
        """Return the state object attribute that matches the string
        :param str value: the string to look up
        :return: the state object attribute that matches the string
        :rtype: str
        """
        return getattr(cls, value.upper(), None)


class Provider(Type):
    """
    Defines for each of the supported providers

    Non-Dummy drivers are sorted in alphabetical order. Please preserve this
    ordering when adding new drivers.

    :cvar ALIYUN_ECS: Aliyun ECS driver.
    :cvar AZURE_ARM: Azure Resource Manager (modern) driver.
    """
    AZURE_ARM = 'azure_arm'
    ALIYUN_ECS = 'aliyun_ecs'


class NodeState(Type):
    """
    Standard states for a node

    :cvar RUNNING: Node is running.
    :cvar STARTING: Node is starting up.
    :cvar REBOOTING: Node is rebooting.
    :cvar TERMINATED: Node is terminated. This node can't be started later on.
    :cvar STOPPING: Node is currently trying to stop.
    :cvar STOPPED: Node is stopped. This node can be started later on.
    :cvar PENDING: Node is pending.
    :cvar SUSPENDED: Node is suspended.
    :cvar ERROR: Node is an error state. Usually no operations can be performed
                 on the node once it ends up in the error state.
    :cvar PAUSED: Node is paused.
    :cvar RECONFIGURING: Node is being reconfigured.
    :cvar UNKNOWN: Node state is unknown.
    """
    RUNNING = 'running'
    STARTING = 'starting'
    REBOOTING = 'rebooting'
    TERMINATED = 'terminated'
    PENDING = 'pending'
    UNKNOWN = 'unknown'
    STOPPING = 'stopping'
    STOPPED = 'stopped'
    SUSPENDED = 'suspended'
    ERROR = 'error'
    PAUSED = 'paused'
    RECONFIGURING = 'reconfiguring'
    MIGRATING = 'migrating'
    NORMAL = 'normal'
    UPDATING = 'updating'


class StorageVolumeState(Type):
    """
    Standard states of a StorageVolume
    """
    AVAILABLE = 'available'
    ERROR = 'error'
    INUSE = 'inuse'
    CREATING = 'creating'
    DELETING = 'deleting'
    DELETED = 'deleted'
    BACKUP = 'backup'
    ATTACHING = 'attaching'
    UNKNOWN = 'unknown'
    MIGRATING = 'migrating'
    UPDATING = 'updating'


class VolumeSnapshotState(Type):
    """
    Standard states of VolumeSnapshots
    """
    AVAILABLE = 'available'
    ERROR = 'error'
    CREATING = 'creating'
    DELETING = 'deleting'
    RESTORING = 'restoring'
    UNKNOWN = 'unknown'
    UPDATING = 'updating'


class Architecture(object):
    """
    Image and size architectures.

    :cvar I386: i386 (32 bt)
    :cvar X86_64: x86_64 (64 bit)
    """
    I386 = 0
    X86_X64 = 1
