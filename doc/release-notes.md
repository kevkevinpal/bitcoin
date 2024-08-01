27.1 Release Notes
=====================

Bitcoin Knots version 27.1.knots20240801 is now available from:

  <https://bitcoinknots.org/files/27.x/27.1.knots20240801/>

This release includes new features, various bug fixes, and performance
improvements.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/bitcoinknots/bitcoin/issues>

To receive security and update notifications, please subscribe to:

  <https://bitcoinknots.org/list/announcements/join/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes in some cases), then run the
installer (on Windows) or just copy over `/Applications/Bitcoin-Qt` (on macOS)
or `bitcoind`/`bitcoin-qt` (on Linux).

Upgrading directly from very old versions of Bitcoin Core or Knots is
possible, but it might take some time if the data directory needs to be migrated. Old
wallet versions of Bitcoin Knots are generally supported.

Compatibility
==============

Bitcoin Knots is supported on operating systems using the Linux kernel,
macOS 11.0+, and Windows 7 and newer. It is not recommended to use
Bitcoin Knots on unsupported systems.

Known Bugs
==========

In various locations, including the GUI's transaction details dialog and the
"vsize" result in many RPC results, transaction virtual sizes may not account
for an unusually high number of sigops (ie, as determined by the
`-bytespersigop` policy) or datacarrier penalties (ie, `-datacarriercost`).
This could result in reporting a lower virtual size than is actually used for
mempool or mining purposes.

Due to disruption of the shared Bitcoin Transifex repository, this release
still does not include updated translations, and Bitcoin Knots may be unable
to do so until/unless that is resolved.

Notable changes
===============

P2P and network changes
-----------------------

- The prior release re-enabled UPnP and NAT-PMP by default based on the
  understanding that it had been many years since the libraries for these
  had a vulnerability. It turns out, this is not the case, and out of an
  abundance of caution, it has been reverted back to disabled-by-default.
  If you can manually forward the p2p port to your node, that is recommended.

Updated RPCs
------------

- The `sendall` RPC now attempts to include more of the wallet's balance in
  cases where other transactions were recently sent and have not yet
  confirmed. (#28979)

- UTXOs returned by `scantxoutset` now include the `blockhash` (the
  transaction creating the UTXO was confirmed in), as well as the number of
  `confirmations`. (#30515)

Updated REST APIs
-----------------

- Parameter validation for `/rest/getutxos` has been improved by rejecting
  truncated or overly large txids and malformed outpoint indices by raising an
  HTTP_BAD_REQUEST "Parse error". Previously, these malformed requests would be
  silently handled. (#30482, #30444)

Credits
=======

Thanks to everyone who directly contributed to this release:

- Andrew Toth
- Anthony Towns
- Ava Chow
- fanquake
- Hodlinator
- Ishaana Misra
- Jadi
- Konstantin Akimov
- Luis Schwab
- Luke Dashjr
- Lőrinc
- MarcoFalke
- Martin Zumsande
- Max Edwards
- Roman Zeyde
- Ryan Ofsky
- Sebastian Falbesoner
- tdb3
- Will Clark
