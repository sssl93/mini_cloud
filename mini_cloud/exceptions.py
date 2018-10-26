class CloudException(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message

    def __repr__(self):
        return "[%s]: %s" % (self.code, self.message)


# NotFound Exceptions Define
# NotFound Exception code range 40400 ~ 40499

class DriverTypeNotFoundError(CloudException):
    def __init__(self, driver_type, message=None):
        self.code = 40400
        self.message = message or "Driver type '%s' not found." % (driver_type,)


class ProviderNotFoundError(CloudException):
    def __init__(self, provider, message=None):
        self.code = 40401
        self.message = message or "Provider %s does not exist" % (provider,)


# Conflict Exceptions Define
# Conflict Exception code range 40900 ~ 40999

class ProviderConflictError(CloudException):
    def __init__(self, provider, message=None):
        self.code = 40900
        self.message = message or "Provider %s conflict." % (provider,)
