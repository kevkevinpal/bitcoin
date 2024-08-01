#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test multiple RPC users."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    str_to_b64str,
)

import http.client
import os
from pathlib import Path
import urllib.parse
import subprocess
from random import SystemRandom
import string
import configparser
import sys
from typing import Optional


def call_with_auth(node, user, password, uripath='/', method='getbestblockhash'):
    url = urllib.parse.urlparse(node.url)
    headers = {"Authorization": "Basic " + str_to_b64str('{}:{}'.format(user, password))}

    conn = http.client.HTTPConnection(url.hostname, url.port)
    conn.connect()
    conn.request('POST', uripath, '{"method": "%s"}' % (method,), headers)
    resp = conn.getresponse()
    resp.data = resp.read()
    conn.close()
    return resp


class HTTPBasicsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.supports_cli = False

    def conf_setup(self):
        self.authinfo = []

        #Append rpcauth to bitcoin.conf before initialization
        self.rtpassword = "cA773lm788buwYe4g4WT+05pKyNruVKjQ25x3n0DQcM="
        rpcauth = "rpcauth=rt:93648e835a54c573682c2eb19f882535$7681e9c5b74bdd85e78166031d2058e1069b3ed7ed967c93fc63abba06f31144"

        self.rpcuser = "rpcuser💻"
        self.rpcpassword = "rpcpassword🔑"

        config = configparser.ConfigParser()
        config.read_file(open(self.options.configfile))
        gen_rpcauth = config['environment']['RPCAUTH']

        # Generate RPCAUTH with specified password
        self.rt2password = "8/F3uMDw4KSEbw96U3CA1C4X05dkHDN2BPFjTgZW4KI="
        p = subprocess.Popen([sys.executable, gen_rpcauth, 'rt2', self.rt2password], stdout=subprocess.PIPE, text=True)
        lines = p.stdout.read().splitlines()
        rpcauth2 = lines[1]

        # Generate RPCAUTH without specifying password
        self.user = ''.join(SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(10))
        p = subprocess.Popen([sys.executable, gen_rpcauth, self.user], stdout=subprocess.PIPE, text=True)
        lines = p.stdout.read().splitlines()
        rpcauth3 = lines[1]
        self.password = lines[3]

        # Generate rpcauthfile with one entry
        username = 'rpcauth_single_' + ''.join(SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(10))
        p = subprocess.Popen([sys.executable, gen_rpcauth, "--output", Path(self.options.tmpdir) / 'rpcauth_single', username], stdout=subprocess.PIPE, universal_newlines=True)
        lines = p.stdout.read().splitlines()
        self.authinfo.append( (username, lines[1]) )

        # Generate rpcauthfile with two entries
        username = 'rpcauth_multi1_' + ''.join(SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(10))
        p = subprocess.Popen([sys.executable, gen_rpcauth, "--output", Path(self.options.tmpdir) / 'rpcauth_multi', username], stdout=subprocess.PIPE, universal_newlines=True)
        lines = p.stdout.read().splitlines()
        self.authinfo.append( (username, lines[1]) )
        # Blank lines in between should get ignored
        with open(Path(self.options.tmpdir) / 'rpcauth_multi', "a", encoding='utf8') as f:
            f.write("\n\n")
        username = 'rpcauth_multi2_' + ''.join(SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(10))
        p = subprocess.Popen([sys.executable, gen_rpcauth, "--output", Path(self.options.tmpdir) / 'rpcauth_multi', username], stdout=subprocess.PIPE, universal_newlines=True)
        lines = p.stdout.read().splitlines()
        self.authinfo.append( (username, lines[1]) )

        def gen_userpass(username_prefix, wallet_restrictions=None):
            username = username_prefix + '_' + ''.join(SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(10))
            p = subprocess.Popen([sys.executable, gen_rpcauth, username], stdout=subprocess.PIPE, universal_newlines=True)
            lines = p.stdout.read().splitlines()
            assert "\n" not in lines[1]
            assert lines[1][:8] == 'rpcauth='
            config_line = lines[1]
            self.authinfo.append( (username, lines[3], wallet_restrictions) )
            if not (wallet_restrictions is None):
                config_line += ":" + wallet_restrictions
            return config_line + "\n"

        # Hand-generated rpcauthfile with one entry and no newline
        with open(Path(self.options.tmpdir) / 'rpcauth_nonewline', "a", encoding='utf8') as f:
            f.write(gen_userpass('rpcauth_nonewline')[8:-1])

        if self.is_wallet_compiled():
            # Hand-generated rpcauthfile with wallet restrictions
            with open(Path(self.options.tmpdir) / 'rpcauth_walletrestricted', "a", encoding='utf8') as f:
                f.write(gen_userpass('rpcauth_walletrestricted_allow_all', '')[8:])
                f.write(gen_userpass('rpcauth_walletrestricted_allow_none', '-')[8:])
                f.write(gen_userpass('rpcauth_walletrestricted_allow_one', 'limitedwallet1')[8:])
                # Uses the same username as a privileged one, but with different passwords:
                f.write(gen_userpass('rpcauth_walletrestricted_allow_all', 'limitedwallet1')[8:])
                f.write(gen_userpass('rpcauth_walletrestricted_allow_all', 'limitedwallet2')[8:])
                f.write(gen_userpass('rpcauth_walletrestricted_allow_all', '-')[8:])
                f.write(gen_userpass('rpcauth_walletrestricted_allow_one', 'limitedwallet2')[8:])
                f.write(gen_userpass('rpcauth_walletrestricted_allow_one', '-')[8:])

        with open(self.nodes[0].datadir_path / "bitcoin.conf", "a", encoding="utf8") as f:
            f.write(rpcauth + "\n")
            f.write(rpcauth2 + "\n")
            f.write(rpcauth3 + "\n")
            f.write("rpcauthfile=rpcauth_single\n")
            f.write("rpcauthfile=rpcauth_multi\n")
            f.write("rpcauthfile=rpcauth_nonewline\n")
            if self.is_wallet_compiled():
                f.write("rpcauthfile=rpcauth_walletrestricted\n")
                f.write(gen_userpass('rpcauth_walletrestricted2_allow_all', '') + "\n")
                f.write(gen_userpass('rpcauth_walletrestricted2_allow_none', '-') + "\n")
                f.write(gen_userpass('rpcauth_walletrestricted2_allow_one', 'limitedwallet1') + "\n")
                # Uses the same username as a privileged one, but with different passwords:
                f.write(gen_userpass('rpcauth_walletrestricted2_allow_all', 'limitedwallet1') + "\n")
                f.write(gen_userpass('rpcauth_walletrestricted2_allow_all', 'limitedwallet2') + "\n")
                f.write(gen_userpass('rpcauth_walletrestricted2_allow_all', '-') + "\n")
                f.write(gen_userpass('rpcauth_walletrestricted2_allow_one', 'limitedwallet2') + "\n")
                f.write(gen_userpass('rpcauth_walletrestricted2_allow_one', '-') + "\n")
        with open(self.nodes[1].datadir_path / "bitcoin.conf", "a", encoding="utf8") as f:
            f.write("rpcuser={}\n".format(self.rpcuser))
            f.write("rpcpassword={}\n".format(self.rpcpassword))
        self.restart_node(0)
        self.restart_node(1)

    def test_auth(self, node, user, password, wallet_restrictions=None):
        self.log.info('Correct... %s (wallet_restrictions=%s)' % (user, wallet_restrictions))
        assert_equal(200, call_with_auth(node, user, password).status)

        self.log.info('Wrong...')
        assert_equal(401, call_with_auth(node, user, password + 'wrong').status)

        self.log.info('Wrong...')
        assert_equal(401, call_with_auth(node, user + 'wrong', password).status)

        self.log.info('Wrong...')
        assert_equal(401, call_with_auth(node, user + 'wrong', password + 'wrong').status)

        if not (wallet_restrictions is None):
            for n in range(1, 3):
                wallet_name = f'limitedwallet{n}'
                self.log.info(f'{wallet_name}...')
                resp = call_with_auth(node, user, password, uripath=f'/wallet/{wallet_name}', method='getwalletinfo')
                if wallet_restrictions in ('', f'{wallet_name}'):
                    assert_equal(200, resp.status)
                else:
                    assert_equal(500, resp.status)
                    assert b'"Requested wallet does not exist or is not loaded"' in resp.data

    def test_rpccookieperms(self):
        p = {
            "owner": 0o600,
            "group": 0o640,
            "all": 0o644,
            "440": 0o440,
            "0640": 0o640,
            "444": 0o444,
            "1660": 0o1660,
        }

        if os.name == 'nt':
            self.log.info(f"Skip cookie file permissions checks as OS detected as: {os.name=}")
            return

        self.log.info('Check cookie file permissions can be set using -rpccookieperms')

        cookie_file_path = self.nodes[1].chain_path / '.cookie'
        PERM_BITS_UMASK = 0o7777

        def test_perm(perm: Optional[str]):
            if not perm:
                perm = 'owner'
                self.restart_node(1)
            else:
                self.restart_node(1, extra_args=[f"-rpccookieperms={perm}"])

            file_stat = os.stat(cookie_file_path)
            actual_perms = file_stat.st_mode & PERM_BITS_UMASK
            expected_perms = p[perm]
            assert_equal(expected_perms, actual_perms)
            return actual_perms

        # Remove any leftover rpc{user|password} config options from previous tests
        conf = self.nodes[1].bitcoinconf
        with conf.open('r') as file:
            lines = file.readlines()
        filtered_lines = [line for line in lines if not line.startswith('rpcuser') and not line.startswith('rpcpassword')]
        with conf.open('w') as file:
            file.writelines(filtered_lines)

        self.log.info('Check default cookie permission')
        default_perms = test_perm(None)

        self.log.info('Check custom cookie permissions')
        for perm in p.keys():
            test_perm(perm)

        self.log.info('Check leaving cookie permissions alone')
        unassigned_perms = os.stat(self.nodes[1].chain_path / 'debug.log').st_mode & PERM_BITS_UMASK
        self.restart_node(1, extra_args=["-rpccookieperms=0"])
        actual_perms = os.stat(cookie_file_path).st_mode & PERM_BITS_UMASK
        assert_equal(unassigned_perms, actual_perms)
        self.restart_node(1, extra_args=["-norpccookieperms"])
        actual_perms = os.stat(cookie_file_path).st_mode & PERM_BITS_UMASK
        assert_equal(unassigned_perms, actual_perms)

        self.log.info('Check -norpccookieperms -rpccookieperms')
        self.restart_node(1, extra_args=["-rpccookieperms=0", "-rpccookieperms=1"])
        actual_perms = os.stat(cookie_file_path).st_mode & PERM_BITS_UMASK
        assert_equal(default_perms, actual_perms)
        self.restart_node(1, extra_args=["-norpccookieperms", "-rpccookieperms"])
        actual_perms = os.stat(cookie_file_path).st_mode & PERM_BITS_UMASK
        assert_equal(default_perms, actual_perms)
        self.restart_node(1, extra_args=["-rpccookieperms=1660", "-norpccookieperms", "-rpccookieperms"])
        actual_perms = os.stat(cookie_file_path).st_mode & PERM_BITS_UMASK
        assert_equal(default_perms, actual_perms)

    def run_test(self):
        self.conf_setup()
        self.log.info('Check correctness of the rpcauth config option')
        url = urllib.parse.urlparse(self.nodes[0].url)

        if self.is_wallet_compiled():
            self.nodes[0].createwallet('limitedwallet1')
            self.nodes[0].createwallet('limitedwallet2')

        self.test_auth(self.nodes[0], url.username, url.password)
        self.test_auth(self.nodes[0], 'rt', self.rtpassword)
        self.test_auth(self.nodes[0], 'rt2', self.rt2password)
        self.test_auth(self.nodes[0], self.user, self.password)
        for info in self.authinfo:
            self.test_auth(self.nodes[0], *info)

        self.log.info('Check correctness of the rpcuser/rpcpassword config options')
        url = urllib.parse.urlparse(self.nodes[1].url)

        self.test_auth(self.nodes[1], self.rpcuser, self.rpcpassword)

        init_error = 'Error: Unable to start HTTP server. See debug log for details.'

        self.log.info('Check blank -rpcauth is ignored')
        rpcauth_abc = '-rpcauth=abc:$2e32c2f20c67e29c328dd64a4214180f18da9e667d67c458070fd856f1e9e5e7'
        rpcauth_def = '-rpcauth=def:$fd7adb152c05ef80dccf50a1fa4c05d5a3ec6da95575fc312ae7c5d091836351'
        self.restart_node(0, extra_args=['-rpcauth'])
        self.restart_node(0, extra_args=['-rpcauth=', rpcauth_abc])
        self.restart_node(0, extra_args=[rpcauth_def, '-rpcauth='])
        # ...without disrupting usage of other -rpcauth tokens
        assert_equal(200, call_with_auth(self.nodes[0], 'def', 'abc').status)
        assert_equal(200, call_with_auth(self.nodes[0], 'rt', self.rtpassword).status)
        for info in self.authinfo:
            assert_equal(200, call_with_auth(self.nodes[0], *info[:2]).status)

        self.log.info('Check -norpcauth disables all previous -rpcauth* params')
        self.restart_node(0, extra_args=[rpcauth_def, '-norpcauth'])
        assert_equal(401, call_with_auth(self.nodes[0], 'def', 'abc').status)
        assert_equal(401, call_with_auth(self.nodes[0], 'rt', self.rtpassword).status)
        for info in self.authinfo:
            assert_equal(401, call_with_auth(self.nodes[0], *info[:2]).status)

        self.log.info('Check -norpcauth can be reversed with -rpcauth')
        self.restart_node(0, extra_args=[rpcauth_def, '-norpcauth', '-rpcauth'])
        # FIXME: assert_equal(200, call_with_auth(self.nodes[0], 'def', 'abc').status)
        assert_equal(200, call_with_auth(self.nodes[0], 'rt', self.rtpassword).status)
        for info in self.authinfo:
            assert_equal(200, call_with_auth(self.nodes[0], *info[:2]).status)

        self.log.info('Check -norpcauth followed by a specific -rpcauth=* restores config file -rpcauth=* values too')
        self.restart_node(0, extra_args=[rpcauth_def, '-norpcauth', rpcauth_abc])
        assert_equal(401, call_with_auth(self.nodes[0], 'def', 'abc').status)
        assert_equal(200, call_with_auth(self.nodes[0], 'rt', self.rtpassword).status)
        for info in self.authinfo:
            assert_equal(200, call_with_auth(self.nodes[0], *info[:2]).status)
        self.restart_node(0, extra_args=[rpcauth_def, '-norpcauth', '-rpcauth='])
        assert_equal(401, call_with_auth(self.nodes[0], 'def', 'abc').status)
        assert_equal(200, call_with_auth(self.nodes[0], 'rt', self.rtpassword).status)
        for info in self.authinfo:
            assert_equal(200, call_with_auth(self.nodes[0], *info[:2]).status)

        self.log.info('Check -rpcauth are validated')
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(expected_msg=init_error, extra_args=['-rpcauth=foo'])
        self.nodes[0].assert_start_raises_init_error(expected_msg=init_error, extra_args=['-rpcauth=foo:bar'])
        self.nodes[0].assert_start_raises_init_error(expected_msg=init_error, extra_args=['-rpcauth=foo:bar:baz'])
        self.nodes[0].assert_start_raises_init_error(expected_msg=init_error, extra_args=['-rpcauth=foo$bar:baz'])
        self.nodes[0].assert_start_raises_init_error(expected_msg=init_error, extra_args=['-rpcauth=foo$bar$baz'])

        self.log.info('Check that failure to write cookie file will abort the node gracefully')
        (self.nodes[0].chain_path / ".cookie.tmp").mkdir()
        (self.nodes[0].chain_path / ".cookie.tmp/subdir").mkdir()
        self.nodes[0].assert_start_raises_init_error(expected_msg=init_error)
        (self.nodes[0].chain_path / ".cookie.tmp/subdir").rmdir()
        (self.nodes[0].chain_path / ".cookie.tmp").rmdir()

        (self.nodes[0].chain_path / ".cookie").mkdir()
        (self.nodes[0].chain_path / ".cookie/subdir").mkdir()
        self.nodes[0].assert_start_raises_init_error(expected_msg=init_error)
        (self.nodes[0].chain_path / ".cookie/subdir").rmdir()
        (self.nodes[0].chain_path / ".cookie").rmdir()

        self.log.info('Check that a non-writable cookie file will get replaced gracefully')
        (self.nodes[0].chain_path / ".cookie").mkdir(mode=1)
        self.restart_node(0)

        self.test_rpccookieperms()


if __name__ == '__main__':
    HTTPBasicsTest().main()
