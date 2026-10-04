#!/bin/bash
# Second clean build through the pinned helper plus one documented CLI fix.
set -euo pipefail
arch=$(dpkg --print-architecture)
apt-get install -y pristine-tar git
mkdir -p /build/git-sbuildpkg
tar -xf /input/git-sbuildpkg.tar -C /build/git-sbuildpkg
python3 - <<'PY'
from pathlib import Path
import difflib

path = Path('/build/git-sbuildpkg/stage3/build_package.sh')
original = path.read_text()
old = '    -us -uc > "$BUILD_LOG" 2>&1; then'
assert original.count(old) == 1, 'Unexpected official helper; compatibility patch refused'
corrected = original.replace(old, '    > "$BUILD_LOG" 2>&1; then')
path.write_text(corrected)
Path('/results/git-sbuildpkg-compatibility.patch').write_text(''.join(
    difflib.unified_diff(original.splitlines(True), corrected.splitlines(True),
                         fromfile='a/stage3/build_package.sh', tofile='b/stage3/build_package.sh')))
Path('/results/git-sbuildpkg-compatibility.txt').write_text(
    'Pinned helper 7164e1646556027f00e0ac10ceaff839e77ba795 needs one CLI fix: '
    'do not forward dpkg-buildpackage -us -uc flags to sbuild. '
    'The archive sbuild is unsigned by default. The unmodified failure is '
    'recorded in run 37205048556. This run qualifies the patched helper, '
    'not the unmodified upstream revision.\n')
PY
chown -R package-builder:package-builder /build/git-sbuildpkg
runuser -u package-builder -- git config --global user.name 'Mutasem Kharma'
runuser -u package-builder -- git config --global user.email 'kharma.mutasem@gmail.com'
printf '[DEFAULT]\ndebian-branch = debian/latest\nupstream-branch = upstream\npristine-tar = True\n' > /home/package-builder/.gbp.conf
chown package-builder:package-builder /home/package-builder/.gbp.conf
printf 'tool\tgit_sbuildpkg_with_cli_fix\treproducible_debs\n' > /results/rebuild-status.tsv
failed=0
for tool in mcpwn-red procscope gspy; do
  if ! awk -F '\t' -v tool="$tool" '$1 == tool && $3 == 0 { found=1 } END { exit !found }' /results/status.tsv; then
    printf '%s\tSKIP-first-build-failed\tNA\n' "$tool" >> /results/rebuild-status.tsv
    failed=1
    continue
  fi
  directory=/build/gbp-$tool
  mkdir -p "$directory"
  chown package-builder:package-builder "$directory"
  dsc=$(find /results/"$tool" -maxdepth 1 -name '*.dsc' -print -quit)
  runuser -u package-builder -- gbp import-dsc --debian-branch=debian/latest --upstream-branch=upstream \
    --pristine-tar "$dsc" "$directory/repository" > /results/"$tool"/gbp-import.log 2>&1
  runuser -u package-builder -- git -C "$directory/repository" bundle create "$directory/$tool.bundle" --all
  cp "$directory/$tool.bundle" /results/"$tool"/
  mkdir -p "$directory/helper-results"
  chown package-builder:package-builder "$directory/helper-results"
  cd /build/git-sbuildpkg
  set +e
  runuser -u package-builder -- ./process_package.sh "$directory/repository" debian/latest "$arch" \
    "$directory/helper-results" > /results/"$tool"/git-sbuildpkg.log 2>&1
  build_exit=$?
  set -e
  cp -a "$directory/helper-results" /results/"$tool"/rebuild
  identical=NA
  if [ "$build_exit" -eq 0 ]; then
    identical=yes
    for second in "$directory/helper-results/debs/"*.deb; do
      first=/results/$tool/$(basename "$second")
      if ! cmp -s "$first" "$second"; then identical=no; fi
      sha256sum "$first" "$second" >> /results/"$tool"/rebuild-sha256.txt
    done
    if [ "$identical" != yes ]; then failed=1; fi
  else
    tail -n 100 /results/"$tool"/git-sbuildpkg.log
    helper_workspace=$(sed -n 's/^\[Stage1\] Initialized workspace in \(\/tmp\/tmp\.[A-Za-z0-9]*\)$/\1/p' /results/"$tool"/git-sbuildpkg.log | head -n1)
    if [ -n "$helper_workspace" ] && [ -d "$helper_workspace/build" ]; then
      mkdir -p /results/"$tool"/rebuild/failure-logs
      cp "$helper_workspace/build/"*.log /results/"$tool"/rebuild/failure-logs/
      find /results/"$tool"/rebuild/failure-logs -type f -name '*.log' -exec tail -n 60 {} \;
    fi
    failed=1
  fi
  printf '%s\t%s\t%s\n' "$tool" "$build_exit" "$identical" >> /results/rebuild-status.tsv
done
cat /results/rebuild-status.tsv
exit "$failed"
