{
  description = "LAN remote-builder discovery with explicit trust";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forEachSystem = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      binaryInfo =
        if builtins.pathExists ./binary-url.json then
          builtins.fromJSON (builtins.readFile ./binary-url.json)
        else
          null;

      mkBinary =
        {
          system,
          tag ? (
            if binaryInfo == null || binaryInfo.latest == "" then
              throw "nix-builder-discovery: binary-url.json has no release"
            else
              binaryInfo.latest
          ),
          package ? "nix-builder-discovery",
        }:
        let
          release =
            binaryInfo.releases.${tag}
              or (throw "nix-builder-discovery: release '${tag}' is not recorded in binary-url.json");
          packageInfo =
            release.packages.${package}
              or (throw "nix-builder-discovery: package '${package}' is not recorded in release '${tag}'");
          pkgs = import nixpkgs { inherit system; };
        in
        pkgs.callPackage ./nix/binary.nix {
          name = package;
          program = packageInfo.program or package;
          inherit (packageInfo) file;
          info = {
            inherit (binaryInfo) repo system;
            inherit (release) tag version;
            inherit (packageInfo) url hash;
          };
        };
    in
    {
      packages = forEachSystem (
        pkgs:
        rec {
          default = pkgs.callPackage ./nix/package.nix { };
          nix-builder-discovery = default;
        }
        // nixpkgs.lib.optionalAttrs
          (binaryInfo != null && binaryInfo.system == pkgs.stdenv.hostPlatform.system && binaryInfo.latest != "")
          {
            nix-builder-discovery-binary = mkBinary { system = pkgs.stdenv.hostPlatform.system; };
          }
      );

      devShells = forEachSystem (pkgs: {
        default = pkgs.callPackage ./nix/devshell.nix { };
      });

      nixosModules.default = import ./nix/module.nix;
      nixosModules.nix-builder-discovery = self.nixosModules.default;

      lib.mkBinary = mkBinary;

      apps = forEachSystem (pkgs: {
        ci = {
          type = "app";
          program = "${
            pkgs.writeShellApplication {
              name = "ci";
              runtimeInputs = [ pkgs.nix ];
              text = "exec nix flake check \"$@\"";
            }
          }/bin/ci";
        };
      });

      checks = forEachSystem (
        pkgs:
        let
          source = pkgs.lib.cleanSource ./.;

          goCheck =
            name: command:
            pkgs.runCommand "check-${name}"
              {
                nativeBuildInputs = [ pkgs.go ];
              }
              ''
                export HOME=$TMPDIR
                export GOCACHE=$TMPDIR/go-cache
                export CGO_ENABLED=0
                cd ${source}
                ${command}
                touch $out
              '';
        in
        {
          package = self.packages.${pkgs.system}.default;
          unit = goCheck "unit" "go test ./...";
          gofmt = goCheck "gofmt" "test -z \"$(gofmt -l .)\"";
          vet = goCheck "vet" "go vet ./...";
          vm = import ./tests/two-node.nix { inherit pkgs; };
          default = pkgs.runCommand "check-default" { } ''
            echo ${self.checks.${pkgs.system}.package} >/dev/null
            echo ${self.checks.${pkgs.system}.unit} >/dev/null
            echo ${self.checks.${pkgs.system}.gofmt} >/dev/null
            echo ${self.checks.${pkgs.system}.vet} >/dev/null
            echo ${self.checks.${pkgs.system}.vm} >/dev/null
            touch $out
          '';
        }
      );

      hydraJobs = self.checks;
    };
}
