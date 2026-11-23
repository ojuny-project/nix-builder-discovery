{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.nix-builder-discovery;

  inherit (lib)
    boolToString
    concatStringsSep
    mkEnableOption
    mkIf
    mkOption
    optional
    optionals
    types
    ;

  user = "nix-builder-discovery";
  group = "nix-builder-discovery";

  privateIPv4 = [
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
    "169.254.0.0/16"
  ];

  privateIPv6 = [
    "fc00::/7"
    "fe80::/10"
  ];

  nftRules = ''
    ip saddr { ${concatStringsSep ", " privateIPv4} } tcp dport { ${toString cfg.infoPort}, ${toString cfg.buildPort} } accept
    ip6 saddr { ${concatStringsSep ", " privateIPv6} } tcp dport { ${toString cfg.infoPort}, ${toString cfg.buildPort} } accept
  '';

  iptablesRule =
    table: prefix:
    "${table} -w -A nixos-fw -p tcp -s ${prefix} -m multiport --dports ${toString cfg.infoPort},${toString cfg.buildPort} -j nixos-fw-accept";

  iptablesStopRule =
    table: prefix:
    "${table} -w -D nixos-fw -p tcp -s ${prefix} -m multiport --dports ${toString cfg.infoPort},${toString cfg.buildPort} -j nixos-fw-accept || true";

  iptablesRules = concatStringsSep "\n" (
    map (iptablesRule "iptables") privateIPv4 ++ map (iptablesRule "ip6tables") privateIPv6
  );

  iptablesStopRules = concatStringsSep "\n" (
    map (iptablesStopRule "iptables") privateIPv4 ++ map (iptablesStopRule "ip6tables") privateIPv6
  );
in
{
  options.services.nix-builder-discovery = {
    enable = mkEnableOption "LAN remote-builder discovery with explicit trust";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      description = "The nix-builder-discovery package to run.";
    };

    defaults = {
      incoming = mkOption {
        type = types.enum [
          "ask"
          "allow"
          "deny"
        ];
        default = "ask";
        description = ''
          What to do when another device asks to build here.
          ask shows a prompt, allow trusts automatically, deny refuses.
          deny makes this device client only.
        '';
      };

      outgoing = mkOption {
        type = types.enum [
          "ask"
          "allow"
          "deny"
        ];
        default = "ask";
        description = ''
          What to do when this device wants to build elsewhere.
          ask shows a prompt, allow trusts automatically, deny refuses.
          deny makes this device builder only.
        '';
      };
    };

    systems = mkOption {
      type = types.listOf types.str;
      default = [ pkgs.stdenv.hostPlatform.system ];
      description = "Systems this device offers and requests.";
    };

    infoPort = mkOption {
      type = types.port;
      default = 5056;
      description = "Public info port.";
    };

    buildPort = mkOption {
      type = types.port;
      default = 5057;
      description = "TLS job API port.";
    };

    cacheURL = mkOption {
      type = types.str;
      default = "";
      example = "http://192.168.1.2:5055";
      description = "Binary cache used for inputs and outputs. Empty uses the direct export path.";
    };

    discovery = {
      ranges = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "192.168.1.0/24" ];
        description = "Prefixes scanned for peers. Empty requires discovery.auto.";
      };

      auto = mkOption {
        type = types.bool;
        default = false;
        description = "Use the connected subnet at startup.";
      };

      interval = mkOption {
        type = types.ints.positive;
        default = 60;
        description = "Seconds between discovery scans.";
      };

      timeout = mkOption {
        type = types.ints.positive;
        default = 1500;
        description = "Milliseconds allowed for each probe.";
      };

      workers = mkOption {
        type = types.ints.positive;
        default = 256;
        description = "Concurrent probes during a scan.";
      };
    };

    idle = {
      session = mkOption {
        type = types.bool;
        default = true;
        description = "Only offer builds while the local session is idle.";
      };

      power = mkOption {
        type = types.bool;
        default = true;
        description = "Only offer builds while on AC power when a battery exists.";
      };
    };

    maxConnections = mkOption {
      type = types.ints.positive;
      default = 1;
      description = "Concurrent remote jobs.";
    };

    waitForBuilders = mkOption {
      type = types.bool;
      default = false;
      description = "Wait when every eligible remote is busy instead of building locally.";
    };

    waitTimeout = mkOption {
      type = types.ints.positive;
      default = 1800;
      description = "Seconds to wait for a busy remote.";
    };

    pairTimeout = mkOption {
      type = types.ints.positive;
      default = 60;
      description = "Seconds a pairing request waits for a decision.";
    };

    reconnectGrace = mkOption {
      type = types.ints.positive;
      default = 60;
      description = "Seconds a disconnected job is kept before it is cancelled.";
    };

    maxAttempts = mkOption {
      type = types.ints.positive;
      default = 3;
      description = "Attempts per derivation after transport failures.";
    };

    controlUsers = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "alice" ];
      description = "Users allowed to use the control socket.";
    };

    stateDir = mkOption {
      type = types.str;
      default = "/var/lib/nix-builder-discovery";
      description = "State directory for the identity and trust store.";
    };

    runtimeDir = mkOption {
      type = types.str;
      default = "/run/nix-builder-discovery";
      description = "Runtime directory for the control socket and output archives.";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = true;
      description = "Open the info and build ports to private addresses.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra command line arguments for the service.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.discovery.ranges != [ ] || cfg.discovery.auto;
        message = "services.nix-builder-discovery.discovery.ranges must not be empty unless discovery.auto is enabled.";
      }
      {
        assertion = cfg.infoPort != cfg.buildPort;
        message = "services.nix-builder-discovery.infoPort and buildPort must differ.";
      }
    ];

    users.groups.${group} = {
      members = cfg.controlUsers;
    };

    users.users.${user} = {
      isSystemUser = true;
      group = group;
      home = cfg.stateDir;
      createHome = false;
    };

    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 0700 ${user} ${group} -"
      "d ${cfg.runtimeDir} 0755 ${user} ${group} -"
    ];

    environment.systemPackages = [ cfg.package ];

    nix.settings.build-hook = "${cfg.package}/bin/nix-builder-discovery hook";

    systemd.services.nix-builder-discovery = {
      description = "LAN remote-builder discovery";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [
        "network-online.target"
        "nix-daemon.service"
      ];

      serviceConfig = {
        User = user;
        Group = group;
        ExecStart = lib.escapeShellArgs (
          [
            "${cfg.package}/bin/nix-builder-discovery"
            "serve"
            "--state-dir"
            cfg.stateDir
            "--runtime-dir"
            cfg.runtimeDir
            "--info-port"
            (toString cfg.infoPort)
            "--build-port"
            (toString cfg.buildPort)
            "--incoming-default"
            cfg.defaults.incoming
            "--outgoing-default"
            cfg.defaults.outgoing
            "--system"
            (concatStringsSep "," cfg.systems)
            "--discovery-interval"
            "${toString cfg.discovery.interval}s"
            "--discovery-timeout"
            "${toString cfg.discovery.timeout}ms"
            "--discovery-workers"
            (toString cfg.discovery.workers)
            "--max-connections"
            (toString cfg.maxConnections)
            "--wait-timeout"
            "${toString cfg.waitTimeout}s"
            "--pair-timeout"
            "${toString cfg.pairTimeout}s"
            "--reconnect-grace"
            "${toString cfg.reconnectGrace}s"
            "--max-attempts"
            (toString cfg.maxAttempts)
            "--idle-session=${boolToString cfg.idle.session}"
            "--idle-power=${boolToString cfg.idle.power}"
            "--control-socket"
            "${cfg.runtimeDir}/control.sock"
            "--nix"
            "${config.nix.package}/bin/nix"
          ]
          ++ optional (concatStringsSep "," cfg.discovery.ranges != "") "--discovery-range=${concatStringsSep "," cfg.discovery.ranges}"
          ++ optional cfg.discovery.auto "--discovery-auto"
          ++ optional cfg.waitForBuilders "--wait"
          ++ optional (cfg.cacheURL != "") "--cache-url"
          ++ optional (cfg.cacheURL != "") cfg.cacheURL
          ++ cfg.extraArgs
        );

        Environment = [
          "PATH=${config.nix.package}/bin:/run/current-system/sw/bin"
          "HOME=${cfg.stateDir}"
        ];

        Restart = "always";
        RestartSec = "5s";

        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_NETLINK"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        LockPersonality = true;
        ReadWritePaths = [
          cfg.stateDir
          cfg.runtimeDir
        ];
      };
    };

    networking.firewall.extraInputRules = mkIf (cfg.openFirewall && config.networking.nftables.enable) nftRules;
    networking.firewall.extraCommands = mkIf (cfg.openFirewall && !config.networking.nftables.enable) iptablesRules;
    networking.firewall.extraStopCommands = mkIf (
      cfg.openFirewall && !config.networking.nftables.enable
    ) iptablesStopRules;
  };
}
