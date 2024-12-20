"""..."""

# Copyright (C) 2024  Stefano Cuizza

#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.


from colorama import just_fix_windows_console

from .arp import (
    arp_announcement,
    arp_probe,
    arp_pscan,
    arp_reply,
    arp_request,
    arp_scan,
)
from .modules.metadata import authors, summary, version


__all__ = [
    '__author__',
    '__version__',
    'arp_announcement',
    'arp_probe',
    'arp_pscan',
    'arp_reply',
    'arp_request',
    'arp_scan',
]


__author__: str = ', '.join(iter(authors()))
"""The package author(s)."""

__doc__: str = summary()

__version__: str = version()
"""The package version."""


just_fix_windows_console()
