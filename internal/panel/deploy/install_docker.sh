# Sets up Docker for an install over SSH whose admin asked for it (spec 9).
# An engine that is installed is never replaced, and no engine package is
# installed over it:
#
#   - Docker is installed and does not answer: it is started (systemctl,
#     rc-service or service), and given some 20 seconds to answer, since
#     OpenRC and sysvinit return before the daemon does. When it does not
#     answer, the script fails with what Docker says.
#   - Docker runs without the Compose v2 plugin: the plugin of the packages that
#     the engine comes from is installed: docker-compose-plugin for docker-ce,
#     docker-compose-v2 for docker.io of Ubuntu, docker-cli-compose on Alpine.
#     For any other engine (docker.io of Debian, a static binary, a snap) the
#     script fails, and says to install Compose v2 by hand.
#   - Docker is not installed at all: the script of get.docker.com, and when
#     that fails the packages of the distribution (docker.io and
#     docker-compose-v2 with apt, docker and docker-cli-compose with apk).
#
# POSIX sh, run as root by package deploy through sshx; what it prints is the
# log of the job. The panel puts root= (the directory of /etc, /usr and /run,
# empty but for the tests), need_compose= (1 when the install needs Compose v2,
# the kit path; 0 for the Docker command of the node image, which a Docker
# without the plugin will do for: no plugin is added, and none is missed) and
# shared.sh (PATH, have, bounded, docker_origin) before it.

LC_ALL=C
export LC_ALL
export DEBIAN_FRONTEND=noninteractive

# apt_get is apt-get that waits up to two minutes for the lock of dpkg, which
# another apt (unattended-upgrades on a new server) may hold, instead of
# failing at once.
apt_get() {
  apt-get -o DPkg::Lock::Timeout=120 "$@"
}

# answers succeeds when the daemon answers, within 15 seconds; compose when the
# plugin is there, or when the install does not need it.
answers() {
  bounded 15 docker info > /dev/null 2>&1
}
compose() {
  [ "$need_compose" = 0 ] || docker compose version > /dev/null 2>&1
}

# start starts Docker with the service manager of the system. With enable it
# also has it start with the system, which is for a Docker that the script
# installed: one that was there keeps the setting that it had.
start() {
  if have systemctl && [ -d "$root/run/systemd/system" ]; then
    if [ "${1-}" = enable ]; then
      systemctl enable --now docker
    else
      systemctl start docker
    fi
  elif have rc-service; then
    if [ "${1-}" = enable ]; then
      rc-update add docker default
    fi
    rc-service docker start
  elif have service; then
    service docker start
  else
    echo "this system has no service manager that the panel knows: start Docker by hand" >&2
    return 1
  fi
}

# up waits for the daemon to answer, some 20 seconds at most: OpenRC and
# sysvinit start it in the background, and return before it answers.
up() {
  u_waited=0
  until answers; do
    if [ "$u_waited" -ge 20 ]; then
      return 1
    fi
    if [ "$u_waited" = 0 ]; then
      echo "Waiting for Docker to answer, some 20 seconds at most"
    fi
    sleep 1
    u_waited=$((u_waited + 1))
  done
}

ready() {
  echo "Docker is ready: $(docker version --format '{{.Server.Version}}' 2> /dev/null), $(docker compose version 2> /dev/null)"
  exit 0
}

if have docker; then
  echo "==> Docker is installed: it is not installed again"
  if ! answers; then
    echo "==> Starting Docker"
    if start; then
      up
    fi
    if ! answers; then
      echo "Docker does not answer, also after it was started: $(bounded 15 docker info 2>&1 | head -n 5)" >&2
      exit 1
    fi
    echo "Docker answers now; whether it starts with the system is left as it was"
  fi
  if compose; then
    ready
  fi
  origin=$(docker_origin)
  os=
  for f in "$root/etc/os-release" "$root/usr/lib/os-release"; do
    if [ -r "$f" ]; then
      os=$(sed -n 's/^ID=//p' "$f" | tr -d "\"'" | head -n 1)
      break
    fi
  done
  echo "==> Adding the Docker Compose v2 plugin to Docker from ${origin:-packages that the panel does not know}"
  case "$origin:$os" in
    docker-ce:*)
      if have apt-get; then
        apt_get update && apt_get install -y docker-compose-plugin
      elif have dnf; then
        dnf install -y docker-compose-plugin
      elif have yum; then
        yum install -y docker-compose-plugin
      fi
      ;;
    docker.io:ubuntu)
      apt_get update && apt_get install -y docker-compose-v2
      ;;
    alpine:*)
      apk add --no-cache docker-cli-compose
      ;;
    *)
      echo "the panel adds no Compose v2 plugin to this Docker (${origin:-packages that it does not know}${os:+, $os}):" \
        "install Docker Compose v2 by hand, then install the node again" >&2
      exit 1
      ;;
  esac
  if compose; then
    ready
  fi
  echo "the Docker Compose v2 plugin could not be installed: install Docker Compose v2 by hand, then install the node again" >&2
  exit 1
fi

echo "==> Docker is not installed: installing it with the script of https://get.docker.com"
script=$(mktemp) || exit 1
fetched=0
if have curl; then
  curl -fsSL --proto '=https' --tlsv1.2 --max-time 300 -o "$script" https://get.docker.com && fetched=1
elif have wget; then
  wget -q -O "$script" https://get.docker.com && fetched=1
else
  echo "neither curl nor wget is installed, so the script cannot be downloaded"
fi
# The script is downloaded first and then run, so that a download that fails
# is not taken for a script that did nothing.
if [ "$fetched" = 1 ]; then
  sh "$script"
fi
rm -f "$script"
if have docker; then
  if ! answers && start enable; then
    up
  fi
  if answers && compose; then
    ready
  fi
fi

echo "==> The script of get.docker.com did not install Docker: trying the packages of the distribution"
if have docker; then
  # The script of get.docker.com installed an engine that does not work: no
  # second engine goes over it.
  echo "Docker was installed and does not work: see the log above" >&2
  exit 1
fi
if have apt-get; then
  if [ "$need_compose" = 0 ]; then
    apt_get update && apt_get install -y docker.io
  else
    apt_get update && apt_get install -y docker.io docker-compose-v2
  fi
elif have apk; then
  if [ "$need_compose" = 0 ]; then
    apk add --no-cache docker
  else
    apk add --no-cache docker docker-cli-compose
  fi
else
  echo "this system has no package manager that the panel knows" >&2
fi
if have docker; then
  if start enable; then
    up
  fi
  if answers && compose; then
    ready
  fi
fi
echo "Docker could not be installed: install Docker Engine with the Compose v2 plugin by hand, then install the node again" >&2
exit 1
