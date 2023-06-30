#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import TypeVar, Callable, Union, Awaitable

__author__ = 'luckydonald'

from quart import Request, Websocket

UserId = TypeVar('UserId')
ResponseStuff = TypeVar('ResponseStuff')

# noinspection DuplicatedCode
Context = Union[Request, Websocket]

UserCallbackTypeSync = Callable[[], UserId]
UserCallbackTypeAsync = Callable[[], Awaitable[UserId]]
UserCallbackType = Union[UserCallbackTypeSync, UserCallbackTypeAsync]

RequestCallbackTypeSync = Callable[[], Context]
RequestCallbackTypeAsync = Callable[[], Awaitable[Context]]
RequestCallbackType = Union[RequestCallbackTypeSync, RequestCallbackTypeAsync]

LocalizeCallbackTypeSync = Callable[[str], str]
LocalizeCallbackTypeAsync = Callable[[str], Awaitable[str]]
# noinspection DuplicatedCode
LocalizeCallbackType = Union[LocalizeCallbackTypeSync, LocalizeCallbackTypeAsync]

UnauthorizedCallbackTypeSync = Callable[[], ResponseStuff]
UnauthorizedCallbackTypeAsync = Callable[[], Awaitable[ResponseStuff]]
UnauthorizedCallbackType = Union[UnauthorizedCallbackTypeSync, UnauthorizedCallbackTypeAsync]

NeedsRefreshCallbackTypeSync = Callable[[], ResponseStuff]
NeedsRefreshCallbackTypeAsync = Callable[[], Awaitable[ResponseStuff]]
NeedsRefreshCallbackType = Union[NeedsRefreshCallbackTypeSync, NeedsRefreshCallbackTypeAsync]

SessionIdentifierGeneratorType = Callable[[], str]
