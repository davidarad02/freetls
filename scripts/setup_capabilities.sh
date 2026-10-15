#!/bin/sh
# Enable pcap-based tests to run as the current user.
#
# On Linux, capturing loopback needs CAP_NET_RAW. Since /tmp is often mounted
# nosuid, file capabilities only work on the root filesystem, so we install a
# copy of tcpdump under $HOME and give it the needed capabilities. Root work is
# done once, via setcap (directly if already root, else pkexec if available).
#
# On macOS, loopback capture needs root (BPF); no file-capability mechanism
# exists, so run the pcap tests under sudo or adjust /dev/bpf* permissions.
set -e

SRC="$(command -v tcpdump 2>/dev/null || true)"
if [ -z "$SRC" ]; then
    echo "tcpdump not found. Install it first (e.g. apt install tcpdump / brew install tcpdump)." >&2
    exit 1
fi

case "$(uname -s)" in
Linux)
    DEPS="$HOME/.local/freetls-deps"
    BIN="$DEPS/bin/tcpdump"
    SETUP="$DEPS/root_setup.sh"

    mkdir -p "$DEPS/bin"
    cp "$SRC" "$BIN"
    cat > "$SETUP" <<EOF
#!/bin/sh
setcap cap_net_raw,cap_net_admin+eip "$BIN" || exit 1
exit 0
EOF
    chmod +x "$SETUP"

    if [ "$(id -u)" = "0" ]; then
        sh "$SETUP"
    elif command -v pkexec >/dev/null 2>&1; then
        pkexec "$SETUP"
    else
        echo "Root privileges are required to set capabilities. Run as root:" >&2
        echo "    sh $SETUP" >&2
        exit 1
    fi
    echo "tcpdump capability installed: $BIN"
    command -v getcap >/dev/null 2>&1 && getcap "$BIN" || true
    ;;
Darwin)
    echo "macOS detected: loopback capture requires root (BPF)."
    echo "Run the pcap tests with sudo, or point FREETLS_TCPDUMP at a tcpdump"
    echo "that has capture permission. Everything else works without root."
    ;;
*)
    echo "Unsupported platform '$(uname -s)'. Install a tcpdump with capture"
    echo "privileges and set FREETLS_TCPDUMP=/path/to/tcpdump."
    ;;
esac
