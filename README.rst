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

Manual Installation
-------------------

You need to install first the server by running in the root directory of the project ::

 sudo python setup.py install

This will add a ``suricata-language-server`` command to the system that will be invoked
transparently by the editors that are configured to use it.


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
        filetypes = {'suricata'};
        root_dir = function(fname)
          return lspconfig.util.find_git_ancestor(fname)
        end;
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