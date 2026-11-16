#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_root="${CAPYVAULT_BUILD_ROOT:-$repo}"
tool_dir="${CAPYVAULT_TOOL_DIR:-$HOME/.local/bin}"
temp_root="$(mktemp -d "${TMPDIR:-/tmp}/CapyVault-AppImage.XXXXXX")"
appdir="$temp_root/AppDir"
appimage_tool="$tool_dir/appimagetool-x86_64.AppImage"
linuxdeploy="$tool_dir/linuxdeploy-x86_64.AppImage"
trap 'case "$temp_root" in "${TMPDIR:-/tmp}"/CapyVault-AppImage.*) rm -rf -- "$temp_root" ;; *) echo "Ruta temporal inesperada; no se ha borrado: $temp_root" >&2 ;; esac' EXIT

mkdir -p "$tool_dir"
if [[ ! -x "$appimage_tool" ]]; then
  curl -fL --retry 3 -o "$appimage_tool" \
    https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
  chmod +x "$appimage_tool"
fi
if [[ ! -x "$linuxdeploy" ]]; then
  curl -fL --retry 3 -o "$linuxdeploy" \
    https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
  chmod +x "$linuxdeploy"
fi

mkdir -p "$repo/dist"
mkdir -p "$appdir/usr/bin" "$appdir/usr/share/applications" "$appdir/usr/share/icons/hicolor/scalable/apps"
cp "$build_root/target/release/capyvault-app" "$appdir/usr/bin/capyvault-app"
cp "$repo/assets/capyvault.svg" "$appdir/usr/share/icons/hicolor/scalable/apps/capyvault.svg"
cp "$repo/assets/capyvault.svg" "$appdir/capyvault.svg"
cat > "$appdir/usr/share/applications/capyvault.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=CapyVault
Comment=Gestor de credenciales cifradas sin conexión
Exec=capyvault-app
Icon=capyvault
Categories=Utility;Security;
Terminal=false
StartupNotify=true
EOF
cat > "$appdir/AppRun" <<'EOF'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/capyvault-app" "$@"
EOF
chmod +x "$appdir/AppRun"
ln -s usr/share/applications/capyvault.desktop "$appdir/capyvault.desktop"
ln -s usr/share/icons/hicolor/scalable/apps/capyvault.svg "$appdir/.DirIcon"

APPIMAGE_EXTRACT_AND_RUN=1 "$linuxdeploy" --appdir "$appdir" \
  --executable "$appdir/usr/bin/capyvault-app" \
  --desktop-file "$appdir/usr/share/applications/capyvault.desktop" \
  --icon-file "$appdir/capyvault.svg"

output="$repo/dist/CapyVault-Linux-x86_64.AppImage"
rm -f "$output"
APPIMAGE_EXTRACT_AND_RUN=1 ARCH=x86_64 "$appimage_tool" "$appdir" "$output"
chmod +x "$output"
sha256sum "$output" > "$output.sha256"
ls -lh "$output" "$output.sha256"
