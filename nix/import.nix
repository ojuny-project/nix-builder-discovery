{
  lib,
  stdenv,
  nix,
  boost,
  pkg-config,
}:

stdenv.mkDerivation {
  pname = "nbd-import";
  version = "0.1.0";

  src = lib.cleanSource ./..;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [
    (lib.getDev nix)
    nix
    boost.dev
  ];

  buildPhase = ''
    runHook preBuild
    c++ -std=c++23 -O2 -o nbd-import cxx/import.cc \
      $(pkg-config --cflags nix-main nix-store) \
      $(pkg-config --libs nix-main nix-store)
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -Dm755 nbd-import "$out/bin/nbd-import"
    runHook postInstall
  '';

  meta = {
    description = "Import Nix export archives while bypassing build output locks";
    license = lib.licenses.gpl3Only;
    platforms = lib.platforms.linux;
    mainProgram = "nbd-import";
  };
}
