"""
Provider related utilities
"""
from mini_cloud.compute.types import Provider
from mini_cloud.common.providers import get_driver as _get_provider_driver
from mini_cloud.common.providers import set_driver as _set_provider_driver

__all__ = [
    "Provider",
    "DRIVERS",
    "get_driver"
]

DRIVERS = {
    Provider.AZURE_ARM:
        ('mini_cloud.compute.drivers.azure_arm', 'AzureNodeDriver'),
    Provider.ALIYUN_ECS:
        ('mini_cloud.compute.drivers.ecs', 'ECSDriver'),
}


def get_driver(provider):
    return _get_provider_driver(
        drivers=DRIVERS,
        provider=provider
    )


def set_driver(provider, module, cls):
    return _set_provider_driver(
        drivers=DRIVERS,
        provider=provider,
        module=module,
        cls=cls
    )
