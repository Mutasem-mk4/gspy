#!/bin/bash
# Runs only in a disposable CI container; the sbuild chroot is separate.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > >(tee /results/setup.log) 2>&1
cat /etc/os-release > /results/host-os-release.txt
cat /etc/apt/sources.list > /results/host-sources.list 2>/dev/null || true
cp -a /etc/apt/sources.list.d /results/host-sources.list.d
arch=$(dpkg --print-architecture)
printf '%s\n' "$arch" > /results/architecture.txt
apt-get update
apt-cache policy golang-go golang-1.26-go python3-mcp sbuild clang libbpf-dev > /results/host-archive-policy.txt
apt-get install -y sbuild schroot debootstrap devscripts git-buildpackage lintian autopkgtest python3
keyring=/usr/share/keyrings/parrot-archive-keyring.gpg
test -r "$keyring"
# Parrot's packaged debootstrap currently lacks an echo alias. Echo is based
# on Debian 13; this selects the trixie bootstrap algorithm, not Debian APT.
if [ ! -e /usr/share/debootstrap/scripts/echo ]; then
  test -e /usr/share/debootstrap/scripts/trixie
  ln -s trixie /usr/share/debootstrap/scripts/echo
  printf '%s\n' 'echo alias -> trixie bootstrap script; all packages remain from signed Parrot APT' > /results/debootstrap-alias.txt
fi
chroot=/var/lib/sbuild/echo-clean
sbuild-createchroot --arch="$arch" --include=parrot-archive-keyring --keyring="$keyring" \
  echo "$chroot" https://deb.parrot.sh/parrot
cat > "$chroot/etc/apt/sources.list" <<EOF
deb [signed-by=/usr/share/keyrings/parrot-archive-keyring.gpg] https://deb.parrot.sh/parrot echo main contrib non-free non-free-firmware
deb [signed-by=/usr/share/keyrings/parrot-archive-keyring.gpg] https://deb.parrot.sh/parrot echo-security main contrib non-free non-free-firmware
deb [signed-by=/usr/share/keyrings/parrot-archive-keyring.gpg] https://deb.parrot.sh/parrot echo-backports main contrib non-free non-free-firmware
EOF
chroot "$chroot" apt-get update
chroot "$chroot" apt-cache policy golang-go golang-1.26-go python3-mcp > /results/chroot-archive-policy.txt
cp "$chroot/etc/apt/sources.list" /results/chroot-sources.list
name=$(schroot --list | sed -n 's/^chroot:\(echo-.*-sbuild\)$/\1/p' | head -n1)
test -n "$name"
schroot -i -c "$name" > /results/schroot-info.txt
useradd -m -s /bin/bash package-builder
usermod -a -G sbuild package-builder
printf '%s\n' '$chroot_mode = "schroot";' '$run_lintian = 1;' > /home/package-builder/.sbuildrc
mkdir -p /build
chown package-builder:package-builder /build
printf 'tool\tsource\tbuild\tautopkgtest\n' > /results/status.tsv
failed=0
for spec in 'mcpwn-red:0.2.0' 'procscope:1.1.2' 'gspy:0.2.3'; do
  tool=${spec%:*}
  version=${spec#*:}
  parent=/build/$tool
  source=$parent/$tool-$version
  mkdir -p "$source" /results/"$tool"
  if [ "$tool" = mcpwn-red ]; then
    tar -xzf /input/mcpwn-red_0.2.0.orig.tar.gz --strip-components=1 -C "$source"
  else
    tar -xzf "/input/$tool-$version-source.tar.gz" -C "$source"
  fi
  if [ -f "/input/$tool-debian.tar" ]; then
    tar -xf "/input/$tool-debian.tar" -C "$source"
  fi
  tar --exclude=./debian -czf "$parent/${tool}_${version}.orig.tar.gz" -C "$source" .
  chmod +x "$source/debian/rules"
  chown -R package-builder:package-builder "$parent"
  cd "$source"
  deb_version=$(dpkg-parsechangelog -S Version)
  set +e
  runuser -u package-builder -- dpkg-source -b . > /results/"$tool"/source.log 2>&1
  source_exit=$?
  set -e
  if [ "$source_exit" -ne 0 ]; then
    printf '%s\t%s\tNA\tNA\n' "$tool" "$source_exit" >> /results/status.tsv
    failed=1
    continue
  fi
  cd "$parent"
  set +e
  runuser -u package-builder -- sbuild --chroot="$name" --dist=echo --arch="$arch" \
    --no-run-autopkgtest --no-source --no-sign "$parent/${tool}_${deb_version}.dsc" \
    > /results/"$tool"/sbuild.log 2>&1
  build_exit=$?
  set -e
  test_exit=NA
  if [ "$build_exit" -eq 0 ]; then
    # A new schroot session restores the pristine template, separate from sbuild.
    set +e
    autopkgtest "$parent/${tool}_${deb_version}.dsc" "$parent"/*.deb \
      --output-dir=/results/"$tool"/autopkgtest -- schroot "$name" \
      > /results/"$tool"/autopkgtest.log 2>&1
    test_exit=$?
    set -e
    if [ "$test_exit" -ne 0 ] && [ "$test_exit" -ne 8 ]; then failed=1; fi
  else
    failed=1
  fi
  printf '%s\t%s\t%s\t%s\n' "$tool" "$source_exit" "$build_exit" "$test_exit" >> /results/status.tsv
  find "$parent" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.dsc' -o -name '*.changes' -o -name '*.buildinfo' -o -name '*.tar.*' -o -name '*.build' \) \
    -exec cp {} /results/"$tool"/ \;
done
cat /results/status.tsv
exit "$failed"
