# Third-Party Software and License Notices

The `LICENSE` file grants **MIT** permission for the **project-authored scripts, Containerfiles, CI workflows, tests and documentation** only. It does **not** assert copyright ownership over, or relicense, Debian or other third-party software. When distributing the OCI container images, Debian and each included package/dependency continue to be governed by their **own upstream licenses** and applicable attribution, notice, source-availability or redistribution terms.

## Included upstream software

The images are derived from the official Debian sid container base:

- Debian Docker Official Image: <https://hub.docker.com/_/debian>
- Debian Project: <https://www.debian.org/>
- Debian licensing and policy: <https://www.debian.org/legal/licenses/>

Installed third-party packages include (dependencies vary by sid date and architecture):

- **All profiles:** Debian sid base packages plus the shared toolchain from `scripts/install-cli-toolchain.sh` (bash/fish; sid Node/npm/Corepack; Python/pip/virtualenv/pipx; Rust/Cargo; Go; native-build prerequisites; download, archive and text-processing tools), all from the official Debian sid repository; plus the `uv` CLI from PyPI installed through pipx.
- **usb:** shared packages plus `usbutils`, `libusb-1.0-0`, `libusb-1.0-0-dev` and dependencies.
- **nested:** shared packages plus `bubblewrap` and dependencies.

The Containerfiles do **not** remove Debian's installed upstream license files or notices. Pipx-installed uv retains its upstream license. License details may change as `debian:sid` advances, so a static list of individual package license expressions would be inaccurate.

## Check the actual published image

To list all installed Debian packages and their declared versions, for example:

```sh
podman run --rm --entrypoint /bin/sh ghcr.io/owner/repo-strict:latest \
  -c "dpkg-query -W -f='${binary:Package}\t${Version}\n'"
```

Repeat with `repo-usb` and `repo-nested`. Debian package copyright and license notices are usually found under `/usr/share/doc/<package>/copyright`. To inspect the separate uv global pipx installation, run `pipx list --global`; the package metadata and upstream license can be inspected inside that environment.

When redistributing images, comply with the relevant upstream licenses' notice, source-offer and redistribution requirements rather than assuming the root MIT license applies to bundled software.
