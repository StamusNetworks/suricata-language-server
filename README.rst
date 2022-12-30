========================
Suricata Language Server
========================

Suricata Language Server is an implementation of the Language Server Protocol for Suricata signatures.
It adds syntax check and hints as well as auto-completion to your preferred editor once it is configured.

.. image:: https://raw.githubusercontent.com/StamusNetworks/suricata-language-server/main/images/vscode-sample.png

Suricata Language Server requires Python and a Suricata binary.

The code is based on `Chris Hansen's fortran language server  <https://github.com/hansec/fortran-language-server>`_ and
incorporate code from `Stamus Networks' scirius <https://github.com/StamusNetworks/scirius>`_.

Features and architecture
=========================

Suricata Language Server currently supports auto-completion and advanced syntax checking. Both features are
using the capabilities of the Suricata available on the system. This means that the list of keywords (with
documentation information) is coming for Suricata itself and it is the same for the syntax checking. This
comes at the cost to have Suricata installed on your system but at the same time, it guarantees a strict
checking of signatures with respect to the Suricata version you are running. Pushing signatures to
production will not result in bad surprise as the syntax has already been checked by the same engine.

Syntax checking is done when saving the files. A configuration test is started using Suricata. This
is providing errors to the diagnostic. Warnings and hints are also provided by using a
detection engine analysis done by Suricata. This is returning warnings and hints about the potential
issues seen of the signatures.


Installation
============

You can use pip to install the Suricata language server ::

 pip install suricata-language-server

Run this command with sudo if you want to install it globally.

If you are a Microsoft Windows user and need to install Suricata, you can use the MSI available on `Suricata download page <https://suricata.io/download/>`_.
For Python, the installer from Python website available on their `Download page <https://www.python.org/downloads/windows/>`_ is working well.

Manual Installation
-------------------

After cloning the repository, you need to install first the server by running in the root directory of the project ::

 pip install .

This will add a ``suricata-language-server`` command to the system that will be invoked
transparently by the editors that are configured to use it. You can use ``sudo pip install .``
to install it system wide if needed.

Server options
--------------

See `suricata-language-server -h` for complete and up-to-date help.

* --suricata-binary: path to the suricata binary used for signatures testing (optional)
* --suricata-config: path to the suricata config used for signatures testing (optional)
* --max-lines: don't run suricata tests if file is bigger than this limit (auto-completion only)


Editors Configuration
=====================

Neovim
------

.. image:: https://raw.githubusercontent.com/StamusNetworks/suricata-language-server/main/images/nvim-completion.png

One simple way tis to use `nvim-lspconfig <https://github.com/neovim/nvim-lspconfig>`_ and add the following
snippet to your configuration ::

  local lspconfig = require 'lspconfig'
  local configs = require 'lspconfig.configs'
  -- Check if the config is already defined (useful when reloading this file)
  if not configs.suricata_language_server then
    configs.suricata_language_server = {
      default_config = {
        cmd = {'suricata-language-server'};
        filetypes = {'suricata', 'hog'};
        root_dir = function(fname)
          return lspconfig.util.find_git_ancestor(fname)
        end;
        single_file_support = true;
        settings = {};
      };
    }
  end

If you want to setup a custom suricata binary, you can use the following trick: ::

 local suricata_ls_cmd = {'suricata-language-server', '--suricata-binary=/my/own/suricata'}
 require'lspconfig'.suricata_language_server.setup{
   cmd = suricata_ls_cmd,
   on_attach = on_attach,
 }

Visual Studio code
------------------

Download the Suricata IntelliSense extension published by `Stamus Networks <https://www.stamus-networks.com/>`_
from `Visual studio Marketplace <https://marketplace.visualstudio.com/items?itemName=StamusNetworks.suricata-ls>`_ and install it into your Visual Studio Code instance.
You can also direcly install it from Visual Studio Code via the Extensions menu.

Then you can configure it via the settings. Main settings are the path to the Suricata Language
Server binary and the path to the Suricata binary.

For the settings on Microsoft Windows, you will need to escape the backslash in the paths you need to enter. With a standard Suricata msi installation
and a standard installation of the server with ``pip`` the settings look like:

* Server Path: ``C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python310\\Scripts\\suricata-language-server.exe``
* Suricata Path: ``C:\\Program Files\\Suricata\\suricata.exe``

The Suricata IntelliSense extension is hosted on its `own project on GitHub <https://github.com/StamusNetworks/suricata-ls-vscode>`_.

Sublime Text 3
--------------

You can use the `LSP <https://lsp.sublimetext.io/>`_ Package to provide support for LSP to Sublime Text 3.

To activate Suricata Language Server on .rules file, you need to create a new syntax for Suricata file by using the content of `Suricata Sublime syntax from justjamesnow <https://github.com/justjamesnow/SublimeSuricata/blob/master/suricata.sublime-syntax>`_

To do so you can click on ``Tools > Developer > New Syntax`` then paste the content of the file and modify the text `text.suricata` to `source.suricata`. This will provide syntax highlighting as well as a `source.suricata` Sublime selector that can be used to trigger the Suricata Language Server activation.

To do that, you can setup the Suricata Language Server by following the documentation for the LSP package on `client configuration <https://lsp.sublimetext.io/guides/client_configuration/>`_. You will need to open ``Preferences > Package Settings > LSP > Settings`` and edit the configuration to add the Suricata Language Server.

The following configuration is known to work ::

 {
   "clients": {
     "suricatals": {
       "enabled": true,
       "command": ["/path/to/suricata-language-server", "--suricata-binary=/path/to/suricata"],
       "selector": "source.suricata",
     },
   },
 }

Kate
----

You can use Suricata Language Server in Kate by activating the `LSP Client Plugin <https://docs.kde.org/stable5/en/kate/kate/kate-application-plugin-lspclient.html>`_.

.. image:: https://raw.githubusercontent.com/StamusNetworks/suricata-language-server/main/images/kate-sample.png

Once activated, you can go to ``Settings > Configure Kate > LSP Client`` then open the ``User Server Settings`` tab and add the configuration
for the Language Server Protocol ::

  {
    "servers": {
        "suricata": {
            "command": ["/path/to/suricata-language-server", "--suricata-binary=/path/to/suricata"],
            "highlightingModeRegex": "^.*Suricata.*$"
          }
        }
  }

The second option giving the path to suricata binary is only necessary if you have a binary in a custom location.

Getting help
============

You can get help by:

* Opening an `issue on GitHub <https://github.com/StamusNetworks/suricata-language-server/issues>`_
* Asking on `#suricata-language-server <https://discordapp.com/channels/911231224448712714/927591953967751199>`_ on Discord.
