#!/bin/bash
# Second clean build through the pinned, unmodified Parrot git-sbuildpkg helper.
set -euo pipefail
arch=$(dpkg --print-architecture)
apt-get install -y pristine-tar git
mkdir -p /build/git-sbuildpkg
tar -xf /input/git-sbuildpkg.tar -C /build/git-sbuildpkg
chown -R package-builder:package-builder /build/git-sbuildpkg
runuser -u package-builder -- git config --global user.name 'Mutasem Kharma'
runuser -u package-builder -- git config --global user.email 'kharma.mutasem@gmail.com'
printf '[DEFAULT]\ndebian-branch = debian/latest\nupstream-branch = upstream\npristine-tar = True\n' > /home/package-builder/.gbp.conf
chown package-builder:package-builder /home/package-builder/.gbp.conf
printf 'tool\tgit_sbuildpkg\treproducible_debs\n' > /results/rebuild-status.tsv
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
