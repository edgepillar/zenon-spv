#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Observe a selected owned temporary workspace without reading file contents.

Rows are non-atomic directory/stat traversals, including races and sampling
cost. Their maxima are observed values, never true peak disk or instantaneous
process-tree footprints. This is not a resolver for hostile shared directories.
"""
import os
from pathlib import Path
import re
import stat
import sys
import time

INTERVAL_NS = 100_000_000
MAX_SAMPLES = 2048
MAX_ENTRIES = 8192
MAX_DEPTH = 8
MAX_FILE_BYTES = 256 << 20
METHOD = 'non-atomic lstat/scandir traversal of one selected owned child TMPDIR; logical regular-file lengths and st_blocks*512; races retained; includes observer I/O; no file contents read; not peak disk or an instantaneous footprint'
FIELDS = ('entries', 'directories', 'regular_files', 'file_bytes',
          'allocated_file_bytes', 'largest_file_bytes', 'input_files',
          'input_file_bytes', 'database_files', 'database_file_bytes',
          'database_allocated_file_bytes', 'other_files', 'other_file_bytes',
          'vanished_entries')


def require(condition):
    if not condition:
        raise ValueError('Owned temporary workspace observation refused')


def preflight():
    require(sys.platform in ('darwin', 'linux'))


class Observer:
    def __init__(self, root):
        preflight()
        self.root = Path(root)
        self.selected = self.root.lstat()
        require(stat.S_ISDIR(self.selected.st_mode))
        self.started_ns = time.monotonic_ns()
        self.points = []
        self.last_ns = self.started_ns

    def take(self, boundary):
        require(boundary in ('before-spawn', 'while-waiting', 'after-reap'))
        require(len(self.points) < MAX_SAMPLES)
        opened = self.root.lstat()
        require(stat.S_ISDIR(opened.st_mode) and os.path.samestat(self.selected, opened))
        started = time.monotonic_ns()
        row = dict.fromkeys(FIELDS, 0)
        pending = [(self.root, 0)]
        while pending:
            directory, depth = pending.pop()
            require(depth <= MAX_DEPTH)
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        row['entries'] += 1
                        require(row['entries'] <= MAX_ENTRIES)
                        path = Path(entry.path)
                        try:
                            info = path.lstat()
                        except FileNotFoundError:
                            row['vanished_entries'] += 1
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            row['directories'] += 1
                            pending.append((path, depth + 1))
                            continue
                        require(stat.S_ISREG(info.st_mode) and info.st_size >= 0
                                and hasattr(info, 'st_blocks') and info.st_blocks >= 0)
                        row['regular_files'] += 1
                        row['file_bytes'] += info.st_size
                        row['allocated_file_bytes'] += info.st_blocks * 512
                        row['largest_file_bytes'] = max(row['largest_file_bytes'], info.st_size)
                        require(row['file_bytes'] <= MAX_FILE_BYTES)
                        relative = path.relative_to(self.root)
                        if re.fullmatch(r'input-[0-9]+-[0-9]+\.raw', path.name):
                            category = 'input'
                        elif 'database' in relative.parts[:-1]:
                            category = 'database'
                            row['database_allocated_file_bytes'] += info.st_blocks * 512
                        else:
                            category = 'other'
                        row[category + '_files'] += 1
                        row[category + '_file_bytes'] += info.st_size
            except FileNotFoundError:
                row['vanished_entries'] += 1
        finished = time.monotonic_ns()
        row.update(sequence=len(self.points), boundary=boundary,
                   started_elapsed_ns=started - self.started_ns,
                   finished_elapsed_ns=finished - self.started_ns,
                   observation_elapsed_ns=finished - started)
        self.points.append(row)
        self.last_ns = finished
        return row

    def during_wait(self):
        if time.monotonic_ns() - self.last_ns >= INTERVAL_NS:
            self.take('while-waiting')


def summary(points):
    require(bool(points))
    return {'observed_points': len(points),
            'maximum_observed_regular_file_bytes': max(p['file_bytes'] for p in points),
            'maximum_observed_allocated_file_bytes': max(p['allocated_file_bytes'] for p in points),
            'maximum_observed_input_file_bytes': max(p['input_file_bytes'] for p in points),
            'maximum_observed_database_file_bytes': max(p['database_file_bytes'] for p in points),
            'maximum_observed_database_allocated_file_bytes': max(p['database_allocated_file_bytes'] for p in points),
            'vanished_entries': sum(p['vanished_entries'] for p in points),
            'observation_elapsed_ns': sum(p['observation_elapsed_ns'] for p in points),
            'peak_disk_measured': False, 'instantaneous_footprint_measured': False}
