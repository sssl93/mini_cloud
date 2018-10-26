"""
Common methods for obtaining a reference to the provider driver class.
"""

import sys

__all__ = [
    'get_driver',
    'set_driver'
]


def get_driver(drivers, provider):
    """
    Get a driver.
    """
    if provider in drivers:
        mod_name, driver_name = drivers[provider]
        _mod = __import__(mod_name, globals(), locals(), [driver_name])
        return getattr(_mod, driver_name)

    raise AttributeError('Provider %s does not exist' % (provider,))


def set_driver(drivers, provider, module, cls):
    """
    Sets a driver.
    """

    if provider in drivers:
        raise AttributeError('Provider %s already registered' % (provider,))

    drivers[provider] = (module, cls)

    # Check if this driver is valid
    try:
        driver = get_driver(drivers, provider)
    except (ImportError, AttributeError):
        exp = sys.exc_info()[1]
        drivers.pop(provider)
        raise exp

    return driver
