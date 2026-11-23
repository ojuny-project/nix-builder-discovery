{
  pkgs,
}:

pkgs.testers.nixosTest {
  name = "nix-builder-discovery";

  nodes.builder =
    { lib, ... }:
    {
      imports = [ ../nix/module.nix ];

      virtualisation.vlans = [ 1 ];

      networking = {
        useDHCP = false;
        firewall.enable = true;
        interfaces.eth1.ipv4.addresses = lib.mkForce [
          {
            address = "192.168.1.1";
            prefixLength = 24;
          }
        ];
      };

      nix.settings = {
        experimental-features = [
          "nix-command"
          "flakes"
        ];
        max-jobs = 1;
        substituters = lib.mkForce [ ];
      };

      services.nix-builder-discovery = {
        enable = true;
        defaults.incoming = "allow";
        defaults.outgoing = "deny";
        discovery.ranges = [ "192.168.1.0/24" ];
        discovery.interval = 5;
        idle.session = false;
        idle.power = false;
        maxConnections = 1;
      };
    };

  nodes.client =
    { lib, ... }:
    {
      imports = [ ../nix/module.nix ];

      virtualisation.vlans = [ 1 ];

      networking = {
        useDHCP = false;
        firewall.enable = true;
        interfaces.eth1.ipv4.addresses = lib.mkForce [
          {
            address = "192.168.1.2";
            prefixLength = 24;
          }
        ];
      };

      nix.settings = {
        experimental-features = [
          "nix-command"
          "flakes"
        ];
        max-jobs = 0;
        substituters = lib.mkForce [ ];
      };

      services.nix-builder-discovery = {
        enable = true;
        defaults.incoming = "deny";
        defaults.outgoing = "allow";
        discovery.ranges = [ "192.168.1.0/24" ];
        discovery.interval = 5;
        idle.session = false;
        idle.power = false;
        maxConnections = 1;
      };
    };

  testScript = ''
    start_all()

    for machine in (builder, client):
        machine.wait_for_unit("nix-builder-discovery.service")
        machine.wait_for_open_port(5056)
        machine.wait_for_open_port(5057)

    client.wait_until_succeeds(
        "nix-builder-discovery peers | grep -q builder",
        timeout=90,
    )

    expression = (
        "cat > /tmp/nbd-smoke.nix <<'EOF'\n"
        "derivation {\n"
        "  name = \"nbd-smoke\";\n"
        "  system = builtins.currentSystem;\n"
        "  builder = \"/bin/sh\";\n"
        "  args = [ \"-c\" \"printf nbd > $out\" ];\n"
        "}\n"
        "EOF\n"
    )
    client.succeed(expression)

    output = client.succeed(
        "nix build --impure --file /tmp/nbd-smoke.nix --no-link --print-out-paths",
        timeout=300,
    ).strip()

    client.succeed(f"grep -q nbd {output}")
    client.succeed("nix-builder-discovery status | grep -q 'jobs: 0/1'")
    client.succeed("nix-builder-discovery trust list | grep -q trusted")
  '';
}
