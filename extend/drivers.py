from libcloud.compute.base import VolumeSnapshot

VolumeSnapshotMock = VolumeSnapshot


class ObjMock:
    def __init__(self, uuid, key='id'):
        setattr(self, key, uuid)
