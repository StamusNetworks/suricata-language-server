# Suricata IntelliSense Package

The Suricata IntelliSense Package is Visual Studio Code extension that uses the Suricata Language
Server to provide advanced syntax checking as well as auto-completion when editing Suricata signatures.

![VSCode Screenshot](https://raw.githubusercontent.com/StamusNetworks/suricata-language-server/main/images/vscode-sample.png)

## Installation

The Suricata Language Server needs to be installed separately. It requires Python and a Suricata binary.

## Setup

For the setings on Microsoft Windows, you will need to escape the backslash in the paths you need to enter. With a standard Suricata msi installation
and a standard installation of the server with ``pip`` the settings look like:

* Server Path: ``C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\Scripts\\suricata-language-server.exe``
* Suricata Path: ``C:\\Program Files\\Suricata\\suricata.exe``

