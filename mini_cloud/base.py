from mini_cloud.compute.providers import Provider as ComputeProvider
from mini_cloud.compute.providers import get_driver as get_compute_driver
from mini_cloud.exceptions import DriverTypeNotFoundError


class DriverType(object):
    """ Compute-as-a-Service driver """
    COMPUTE = ComputeProvider


DriverTypeFactoryMap = {
    DriverType.COMPUTE: get_compute_driver,
}


def get_driver(driver_type, provider):
    """
    Get a driver
    """
    try:
        return DriverTypeFactoryMap[driver_type](provider)
    except KeyError:
        raise DriverTypeNotFoundError(driver_type)
