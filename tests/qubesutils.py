#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2017 boring-stuff <boring-stuff@users.noreply.github.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import unittest
from core.qubesutils import sanitize_domain_name, sanitize_service_name

class SanitizationTest(unittest.TestCase):
    domains = ['dom0', 'sys-net', 'sys-usb', 'sys-firewall', 'sys-whonix',
               'debian-8', 'fedora-23', 'whonix-gw', 'whonix-ws']

    services = ['qubes.InputMouse', 'qubes.NotifyTools', 'qubes.ReceiveUpdates',
                'qubes.WindowIconUpdater', 'qubes.SyncAppMenus']

    service_plus = [ 'Type1', 'Addition', 'second_screen', 'test-2' ]

    weird = { "_cc_nts": u"äccénts", "gin_cola": "gin&cola",
              "_$oda.___": "[$oda.]{}", "_script_": "<script>",
              "utf-8-_": u"u\x74f-8-\x01" }

    def test_sanitize_standard_domain_names(self):
        for name in self.domains:
            self.assert_sanitize_domain_name_equals(name, name)

    def test_sanitize_weird_domain_names(self):
        for sanitized in self.weird:
            self.assert_sanitize_domain_name_equals(sanitized,
                                                    self.weird[sanitized])
        self.assert_sanitize_domain_name_equals('2_2', '2+2')

    def test_assert_standard_domain_names(self):
        for name in self.domains:
            self.assert_sanitized_domain_name(False, name)

    def test_assert_weird_domain_names(self):
        for sanitized in self.weird:
            self.assert_sanitized_domain_name(True, self.weird[sanitized])
            self.assert_sanitized_domain_name(False, sanitized)

        self.assert_sanitized_domain_name(True, '2+2')
        self.assert_sanitized_domain_name(False, '2_2')

    def test_sanitize_standard_service_names(self):
        for name in self.services:
            self.assert_sanitize_service_name_equals(name, name)

            for plus in self.service_plus:
                service = name + '+' + plus

                self.assert_sanitize_service_name_equals(service, service)

    def test_sanitize_weird_service_names(self):
        for sanitized in self.weird:
            self.assert_sanitize_service_name_equals(sanitized,
                                                     self.weird[sanitized])

            for plus in self.service_plus:
                sanitized_plus = sanitized + '+' + plus
                weird_plus = self.weird[sanitized] + '+' + plus

                self.assert_sanitize_service_name_equals(sanitized_plus,
                                                         weird_plus)

    def test_assert_standard_service_names(self):
        for name in self.services:
            self.assert_sanitized_service_name(False, name)

            for plus in self.service_plus:
                service = name + '+' + plus

                self.assert_sanitized_service_name(False, service)

    def test_assert_weird_service_names(self):
        for sanitized in self.weird:
            self.assert_sanitized_service_name(True, self.weird[sanitized])
            self.assert_sanitized_service_name(False, sanitized)

            for plus in self.service_plus:
                sanitized_plus = sanitized + '+' + plus
                weird_plus = self.weird[sanitized] + '+' + plus

                self.assert_sanitized_service_name(True, weird_plus)
                self.assert_sanitized_service_name(False, sanitized_plus)

    def assert_sanitize_domain_name_equals(self, expect_sanitized, input_string):
        result = sanitize_domain_name(input_string)

        self.assertEquals(expect_sanitized, result)

    def assert_sanitized_domain_name(self, expect_error, input_string):
        found_error = False

        try:
            sanitize_domain_name(input_string, assert_sanitized = True)
        except AssertionError:
            found_error = True

        self.assertEquals(expect_error, found_error, msg = "Expected error: " \
                          + str(expect_error) + " when parsing domain name '" \
                          + input_string + "'")

    def assert_sanitize_service_name_equals(self, expect_sanitized, input_string):
        result = sanitize_service_name(input_string)

        self.assertEquals(expect_sanitized, result)

    def assert_sanitized_service_name(self, expect_error, input_string):
        found_error = False

        try:
            sanitize_service_name(input_string, assert_sanitized = True)
        except AssertionError:
            found_error = True

        self.assertEquals(expect_error, found_error, msg = "Expected error: " \
                          + str(expect_error) + " when parsing service name '" \
                          + input_string + "'")

if __name__=='__main__':
    unittest.main()
