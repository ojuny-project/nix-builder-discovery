{
  mkShell,
  go,
  gopls,
  gotools,
  golangci-lint,
  delve,
  git,
  jq,
  curl,
}:

mkShell {
  packages = [
    go
    gopls
    gotools
    golangci-lint
    delve
    git
    jq
    curl
  ];
}
