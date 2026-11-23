# nix-builder-discovery

Automatic LAN remote-builder discovery with explicit trust.

NBD discovers Nix builders on a local network, pairs devices with an approval on
both machines, and runs each derivation as a job on an idle builder. A lost job
is restarted on another builder after a one-minute reconnect grace.

NBD does not use SSH. Device identity is an automatically generated Ed25519 key,
and the job API uses mutual TLS pinned to the approved key. The builder runs
`nix build` as an unprivileged user, so a client never receives a Nix daemon
connection.

Status: early implementation. The two-node VM test passes. The full trust and retry matrix, and the ojuny integration, are still pending.

## Components

- public info endpoint and LAN discovery
- explicit pairing with trust, skip, and deny
- declarative incoming and outgoing defaults
- lease broker that fans jobs out across builders
- Nix build hook and builder job API
- direct output transfer through the `nbd-import` libstore helper, with an
  optional binary cache
- NixOS module, CLI, and three-plane trust model

The design is in [docs/design.md](docs/design.md).

## NixOS

```nix
{
  inputs.nix-builder-discovery.url = "github:ojuny-project/nix-builder-discovery";

  outputs = inputs@{ nixpkgs, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        inputs.nix-builder-discovery.nixosModules.default
        {
          services.nix-builder-discovery = {
            enable = true;
            defaults.incoming = "allow";
            defaults.outgoing = "allow";
            discovery.auto = true;
          };
        }
      ];
    };
  };
}
```

The module creates the service user, the state directory, the control socket,
the systemd unit, and the private-prefix firewall rules. It sets
`nix.settings.build-hook` to the packaged hook. It does not enable SSH and does
not add a trusted user.

## CLI

```console
$ nix-builder-discovery status
$ nix-builder-discovery peers
$ nix-builder-discovery pending
$ nix-builder-discovery decide <id> trust
$ nix-builder-discovery trust list
$ nix-builder-discovery trust allow <fingerprint>
$ nix-builder-discovery trust deny <fingerprint>
$ nix-builder-discovery trust revoke <fingerprint>
$ nix-builder-discovery trust revoke-default
$ nix-builder-discovery jobs
```

## Development

```console
$ nix develop
$ go test ./...
$ nix flake check
```

The flake checks include the Go unit tests, gofmt, go vet, the package build,
and the two-node VM test.

## Releases

The release workflow follows the other ojuny binaries. A first line on `main`
that starts with `v` and a digit, a pushed `v*` tag, or a manual dispatch builds
the bundled binary, publishes it with the release flake, and records the asset
in `binary-url.json`.

## License

GPL-3.0-only. See [LICENSE](LICENSE).

