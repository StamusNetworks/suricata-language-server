{
  description = "Suricata Language Server - LSP for Suricata signatures";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python3;
        pythonPkgs = python.pkgs;
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            python
            pythonPkgs.pip
            pythonPkgs.virtualenv

            # Suricata for validation and tests
            pkgs.suricata

            # Dev tools
            pythonPkgs.black
            pythonPkgs.pylint
            pythonPkgs.pytest

            # Runtime deps available at system level
            pythonPkgs.pygls
            pythonPkgs.docker

            # pre-commit
            pkgs.pre-commit
          ];

          shellHook = ''
            # Create venv if it doesn't exist
            if [ ! -d .venv ]; then
              echo "Creating virtualenv..."
              python -m venv .venv --system-site-packages
              source .venv/bin/activate
              pip install -e . --quiet
            else
              source .venv/bin/activate
            fi

            echo "Suricata Language Server dev shell"
            echo "  python:   $(python --version)"
            echo "  suricata: $(suricata --build-info 2>/dev/null | head -1)"
            echo ""
            echo "Commands:"
            echo "  pytest src/suricatals/          # run tests"
            echo "  pylint --disable=C,R src/suricatals  # lint"
            echo "  black src/                      # format"
          '';
        };
      });
}
