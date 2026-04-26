#!/bin/sh
# Called by GoReleaser before hook — bumps complykit-ui/package.json version
VERSION="$1"
UI="../complykit-ui/package.json"
if [ -f "$UI" ]; then
  sed -i.bak "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" "$UI"
  rm -f "$UI.bak"
  echo "  bumped $UI to $VERSION"
fi
