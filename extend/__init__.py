#!/usr/bin/env python
# coding:utf-8
import ecs
import azure_arm
from types import FunctionType, MethodType


def patch_instance_method(patcher, instance):
    """
    Patch Instance Method.
    :param patcher: class
    :param instance: instance object
    :return:
    """
    if not patcher:
        return

    for attr in dir(patcher):
        if not attr.startswith('__'):
            func = getattr(patcher, attr)
            if isinstance(func, FunctionType):
                setattr(instance, attr, MethodType(func, instance))
