#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Observe one sequential callable using explicit Unix self/child scopes.

SELF RSS is a cumulative high water through the post-call observation, including
earlier imports/preflight. It is neither an interval RSS delta nor through-exit
memory. CHILDREN CPU deltas cover terminated, waited children and descendants
whose intervening parents waited. No child RSS or process-tree peak is inferred.
"""
import math
import re
import sys
import time

WALL_METHOD = 'monotonic_ns before pre-call getrusage through post-call getrusage; includes selected callable and observation overhead; excludes final outer report encoding/persistence and interpreter exit'
SELF_METHOD = 'getrusage RUSAGE_SELF all calling-process threads; cumulative CPU counters and lifetime RSS high water through observation, including earlier imports/preflight; excludes children; not an interval RSS delta or through-exit memory'
CHILD_CPU_METHOD = 'getrusage RUSAGE_CHILDREN cumulative user/system CPU of terminated waited children and waited descendants; pre/post differences around one sequential callable; no child RSS or simultaneous process-tree memory'
CPU_METHOD = 'native getrusage floating seconds rounded to integer nanoseconds for storage; native CPU precision is not nanosecond precision'


def require(condition):
    if not condition:
        raise ValueError('Driver resource observation refused')


def native_rss_unit(platform):
    require(platform in ('darwin', 'linux'))
    return ('bytes', 1) if platform == 'darwin' else ('KiB', 1024)


def preflight():
    native_rss_unit(sys.platform)
    import resource
    require(all(hasattr(resource, name) for name in ('getrusage', 'RUSAGE_SELF', 'RUSAGE_CHILDREN')))


def cpu_ns(seconds):
    require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0)
    return round(seconds * 1_000_000_000)


def snapshot():
    preflight()
    import resource
    own = resource.getrusage(resource.RUSAGE_SELF)
    waited = resource.getrusage(resource.RUSAGE_CHILDREN)
    unit, factor = native_rss_unit(sys.platform)
    require(type(own.ru_maxrss) is int and own.ru_maxrss > 0)
    return {'self': {'native_peak_rss': own.ru_maxrss, 'native_rss_unit': unit,
                     'process_peak_rss_bytes': own.ru_maxrss * factor,
                     'user_cpu_ns': cpu_ns(own.ru_utime), 'system_cpu_ns': cpu_ns(own.ru_stime)},
            'waited_children_cpu': {'user_cpu_ns': cpu_ns(waited.ru_utime),
                                    'system_cpu_ns': cpu_ns(waited.ru_stime)}}


def observe_call(label, call, retain):
    """Retain the actual observation even when the selected callable raises."""
    preflight()
    require(type(label) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,80}', label))
    returned, exception_type = False, None
    started = time.monotonic_ns()
    before = snapshot()
    try:
        result = call()
        returned = True
        return result
    except BaseException as error:
        exception_type = type(error).__name__
        raise
    finally:
        after = snapshot()
        elapsed = time.monotonic_ns() - started
        retain({'label': label, 'call_returned': returned, 'exception_type': exception_type,
                'capture_platform': sys.platform, 'elapsed_ns': elapsed,
                'wall_method': WALL_METHOD, 'self_method': SELF_METHOD,
                'child_cpu_method': CHILD_CPU_METHOD, 'cpu_storage_method': CPU_METHOD,
                'before': before, 'after': after,
                'self_user_cpu_delta_ns': after['self']['user_cpu_ns'] - before['self']['user_cpu_ns'],
                'self_system_cpu_delta_ns': after['self']['system_cpu_ns'] - before['self']['system_cpu_ns'],
                'waited_children_user_cpu_delta_ns': after['waited_children_cpu']['user_cpu_ns'] - before['waited_children_cpu']['user_cpu_ns'],
                'waited_children_system_cpu_delta_ns': after['waited_children_cpu']['system_cpu_ns'] - before['waited_children_cpu']['system_cpu_ns']})
