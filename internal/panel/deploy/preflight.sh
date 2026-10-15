# The preflight of an install over SSH (spec 9): what the panel has to know
# about a server before it installs a node there. It changes nothing on the
# server. It is POSIX sh, and runs under dash, bash and busybox ash, as root or
# through sudo; package deploy sends it with sshx and reads what it prints.
#
# It prints one line: "postern-preflight " and a JSON object whose values are
# all strings in base64. Each is the bytes of what one command printed, its
# error output included, cut at a size, so that nothing here has to be quoted
# whatever a command prints: the panel decodes every value, and parses and
# checks it itself. The key of a command that ran also has a twin that ends in
# _rc, its exit status. The keys of what is not there (no docker, no bash) are
# left out.
#
# The panel puts two lines before the script, which it checks:
#   mgmt_port=<the management port of the node: digits>
#   root=<empty; the tests put a directory there that holds a fake /etc and /proc>
# and shared.sh (PATH, have, bounded, docker_origin), which it shares with the
# setup of Docker.

LC_ALL=C
export LC_ALL

json=
# add KEY VALUE: VALUE, in base64 already, becomes the value of KEY.
add() {
  json="$json${json:+,}\"$1\":\"$2\""
}
# enc LIMIT: the standard input, at most LIMIT bytes of it, in base64 on one line.
enc() {
  head -c "$1" | base64 | tr -d '\n'
}
# val KEY TEXT
val() {
  add "$1" "$(printf '%s' "$2" | enc 4096)"
}
# cmd KEY LIMIT COMMAND...: what COMMAND prints, with its error output, at most
# LIMIT bytes of it, as KEY, and its exit status as KEY_rc.
cmd() {
  c_key=$1
  c_limit=$2
  shift 2
  c_out=$("$@" 2>&1)
  c_rc=$?
  add "$c_key" "$(printf '%s' "$c_out" | enc "$c_limit")"
  val "${c_key}_rc" "$c_rc"
}
# The clock first: the panel compares it with its own.
val format 1
val time "$(date -u +%s)"
val uid "$(id -u)"
val machine "$(uname -m)"
if [ -r "$root/etc/os-release" ]; then
  add os_release "$(enc 16384 < "$root/etc/os-release")"
elif [ -r "$root/usr/lib/os-release" ]; then
  add os_release "$(enc 16384 < "$root/usr/lib/os-release")"
fi

if have bash; then
  cmd bash 256 bash -c 'echo "${BASH_VERSINFO[0]}"'
fi

# The package tools of the server: the setup of Docker adds the Compose v2
# plugin with apt-get, dnf, yum or apk only.
tools=
for t in apt-get dnf yum apk zypper pacman; do
  if have "$t"; then
    tools="$tools$t
"
  fi
done
val package_tools "$tools"

if have docker; then
  val docker "$(command -v docker)"
  val docker_origin "$(docker_origin)"
  # A command that asks the daemon would start a daemon that does not run
  # where systemd listens on its socket (docker.socket), and the preflight
  # changes nothing: whether the daemon runs is asked of systemd, or else of
  # pidof, first. Without either nothing can start it on a call.
  if have systemctl && [ -d "$root/run/systemd/system" ]; then
    if systemctl is-active --quiet docker; then active=yes; else active=no; fi
  elif have pidof; then
    if pidof dockerd > /dev/null 2>&1; then active=yes; else active=no; fi
  else
    active=unknown
  fi
  val docker_active "$active"
  if [ "$active" != no ]; then
    # Commands that ask the daemon are bounded: one that hangs must not hold
    # the whole preflight.
    cmd docker_version 1024 bounded 20 docker version --format '{{.Server.Version}}'
    cmd docker_security 4096 bounded 20 docker info --format '{{.SecurityOptions}}'
    cmd containers 262144 bounded 20 docker ps -a --no-trunc --format '{{.ID}}|{{.Names}}|{{.Label "postern.managed"}}|{{.Status}}'
  fi
  # The version of Compose is that of the plugin, which asks no daemon.
  cmd compose_version 1024 bounded 20 docker compose version
fi

disk=/opt
if [ ! -d "$root/opt" ]; then
  disk=/
fi
val disk_path "$disk"
cmd df 4096 df -Pk "$disk"

# The listening TCP sockets with their processes: ss of iproute2, an ss that
# does not know -H, the netstat of busybox or of net-tools, or else the tables
# of the kernel, which do not say who listens.
if listen=$(ss -ltnpH 2> /dev/null); then
  val listen_tool ss
elif listen=$(ss -ltnp 2> /dev/null); then
  val listen_tool ss
elif listen=$(netstat -ltnp 2> /dev/null); then
  val listen_tool netstat
else
  val listen_tool proc
  listen=$(cat "$root/proc/net/tcp" "$root/proc/net/tcp6" 2> /dev/null)
fi
add listen "$(printf '%s' "$listen" | enc 262144)"

# The control groups of the processes that listen on 443 or on the management
# port: they name the container of a process, and so whether it is Postern's.
pids=$(printf '%s\n' "$listen" | awk -v a=443 -v b="$mgmt_port" '
  {
    n = split($4, f, ":")
    if (f[n] != a && f[n] != b) next
    s = $0
    while (match(s, /pid=[0-9]+/)) {
      print substr(s, RSTART + 4, RLENGTH - 4)
      s = substr(s, RSTART + RLENGTH)
    }
    if ($7 ~ /^[0-9]+\//) {
      split($7, q, "/")
      print q[1]
    }
  }' | sort -un | head -n 32)
groups=
for pid in $pids; do
  groups="${groups}pid $pid
$(head -c 4096 "$root/proc/$pid/cgroup" 2> /dev/null)
"
done
add pids "$(printf '%s' "$groups" | enc 262144)"

if have ip; then
  cmd addrs 65536 ip -o addr show
elif have ifconfig; then
  cmd addrs 65536 ifconfig -a
fi

printf 'postern-preflight {%s}\n' "$json"
