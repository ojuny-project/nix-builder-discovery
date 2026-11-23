{
  lib,
  buildGoModule,
  pkgs,
}:

let
  nbdImport = pkgs.callPackage ./import.nix { };
in
buildGoModule {
  pname = "nix-builder-discovery";
  version = "0.1.0";

  src = lib.cleanSource ./..;

  vendorHash = null;

  ldflags = [
    "-X github.com/ojuny-project/nix-builder-discovery/internal/hook.ImportHelper=${nbdImport}/bin/nbd-import"
  ];

  postInstall = ''
    install -Dm755 ${nbdImport}/bin/nbd-import "$out/bin/nbd-import"
  '';

  meta = {
    description = "LAN remote-builder discovery with explicit trust";
    license = lib.licenses.gpl3Only;
    mainProgram = "nix-builder-discovery";
    platforms = lib.platforms.linux;
  };
}
