# Pre-built binaries of OpenFIPS201 v2.0.0-rc2

The binaries are built for 3 platforms:
* P71D600: J3R452 cards from NXP
* P71D320: J3R180 (and the other variants) cards from NXP
* GENERIC: any other card

The only difference between these platforms is the version string returned by a
`GET VERSION` command.

Additionally, each platform comes in 3 different build types:
* debug: the .cap contains debug symbols, the build is a debug build which allows
  access to the SP800 KDA and KC algorithms for ACVP testing purposes
* release: a release build with the most algorithms supported, including
  3-key Triple-DES (3TDEA / 3K3DES) and RSA 1024
* release-FIPS: this is the build mode that passed the FIPS 140-3 testing
  (pending final verification by the lab)

## Installation

The applet must be the default selected applet on both interfaces, for instance
by setting the `CardReset` privilege.

Example:
```sh
java -jar gp.jar --install OpenFIPS201-v2.0-jc3.0.5-jdk11-release-P71D600-FIPS.cap --privs CardReset
```
