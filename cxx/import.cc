#include <nix/main/shared.hh>
#include <nix/store/export-import.hh>
#include <nix/store/local-store.hh>
#include <nix/store/store-api.hh>
#include <nix/store/store-open.hh>
#include <nix/util/file-descriptor.hh>
#include <nix/util/serialise.hh>

#include <fcntl.h>

#include <iostream>

int main(int argc, char **argv)
{
    nix::initNix();

    if (argc < 2) {
        std::cerr << "usage: nbd-import <archive> <output>...\n";
        return 2;
    }

    try {
        auto store = nix::openStore("local");
        auto local = store.dynamic_pointer_cast<nix::LocalStore>();
        if (!local) {
            std::cerr << "nbd-import: not a local store\n";
            return 1;
        }

        /*
          The daemon's build goal holds a lock on each output path while the
          build hook runs. Copying the output back through a fresh store
          instance would block on that lock. Nix's own build hook adds the
          paths to locksHeld for the same reason.
        */
        for (int index = 2; index < argc; index++)
            local->locksHeld.insert(argv[index]);

        nix::AutoCloseFD archive{open(argv[1], O_RDONLY)};
        if (!archive) {
            std::cerr << "nbd-import: cannot open " << argv[1] << "\n";
            return 1;
        }

        nix::FdSource source(archive.get());
        auto paths = nix::importPaths(*store, source, nix::NoCheckSigs);

        for (auto & path : paths)
            std::cout << store->printStorePath(path) << "\n";

        return 0;
    } catch (std::exception & error) {
        std::cerr << "nbd-import: " << error.what() << "\n";
        return 1;
    }
}
