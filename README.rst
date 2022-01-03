========================
Suricata Language Server
========================

Suricata Language Server is an implementation of the Language Server Protocol for Suricata signatures.
It adds syntax check and hints to your prefered editor once it is configured.

Suricata Language Server requires Python and a Suricata binary.

The code is based on `Chris Hansen's fortran language server  <https://github.com/hansec/fortran-language-server>`_ and
incorporate code from `Stamus Networks' scirius <https://github.com/StamusNetworks/scirius>`_.

Installation
============

You can use pip to install the Suricata language server ::

 pip install suricata-language-server

Run this command with sudo if you want to install it globally.

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

* --suricata-binary: path to the suricata binary used for signatures testing
* --max-lines: don't run suricata tests if file is bigger then this limit (auto-completion only)


Editors Configuration
=====================

Neovim
------

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

 local suricata_ls_cmd = {'suricata-language-server', '--suricata-binary=/home/eric/builds/suricata/bin/suricata'}
 require'lspconfig'.suricata_language_server.setup{
   cmd = suricata_ls_cmd,
   on_attach = on_attach,
 }

Visual Studio code
------------------

Download the suricata-ls extension (suricata-ls-x.x.x.vsix) published by `Stamus Networks <https://www.stamus-networks.com/>`_
and install it into your Visual Studio Code instance.

Then you can configure it via the settings. Main settings are the path to the Suricata Language
Server binary and the path to the Suricata binary.
