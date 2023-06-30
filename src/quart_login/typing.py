#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import TypeVar, Callable, Union, Awaitable

__author__ = 'luckydonald'

from quart import Request, Websocket

UserId = TypeVar('UserId')

Context = Union[Request, Websocket]

UserCallbackTypeSync = Callable[[], UserId]
UserCallbackTypeAsync = Callable[[], Awaitable[UserId]]
UserCallbackType = Union[UserCallbackTypeSync, UserCallbackTypeAsync]

RequestCallbackTypeSync = Callable[[], Context]
RequestCallbackTypeAsync = Callable[[], Awaitable[Context]]
RequestCallbackType = Union[RequestCallbackTypeSync, RequestCallbackTypeAsync]
