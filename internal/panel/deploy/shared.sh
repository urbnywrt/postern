# What the preflight and the setup of Docker share; the panel puts it before
# each script, after root=. POSIX sh.

# The tools of the system are looked for in /usr/local/sbin and /usr/local/bin
# as well, which the secure_path of sudo leaves out on some systems: Docker
# installed by hand is there. They come after the directories that PATH has.
for p_dir in "$root/usr/local/sbin" "$root/usr/local/bin"; do
  case ":$PATH:" in
    *":$p_dir:"*) ;;
    *) PATH=$PATH:$p_dir ;;
  esac
done
export PATH

have() {
  command -v "$1" > /dev/null 2>&1
}

# bounded SECONDS COMMAND...: COMMAND, stopped after SECONDS where timeout
# works, so that a Docker daemon that hangs cannot hold a script. A timeout
# that does not take "timeout SECONDS COMMAND" (the -t of an old busybox) is
# not used.
if have timeout && timeout 5 true > /dev/null 2>&1; then
  bounded() {
    b_seconds=$1
    shift
    timeout "$b_seconds" "$@"
  }
else
  bounded() {
    shift
    "$@"
  }
fi

# docker_origin prints the packages that the installed Docker engine comes
# from: docker-ce (those of Docker, deb or rpm), docker.io (those of Debian or
# Ubuntu) or alpine (apk); nothing for an engine of none of these, such as a
# static binary or a snap.
docker_origin() {
  if have dpkg-query; then
    for o_pkg in docker-ce docker.io; do
      if dpkg-query -W -f='${Status}' "$o_pkg" 2> /dev/null | grep -q 'ok installed'; then
        echo "$o_pkg"
        return
      fi
    done
  fi
  if have rpm && rpm -q docker-ce > /dev/null 2>&1; then
    echo docker-ce
    return
  fi
  if have apk && apk info -e docker > /dev/null 2>&1; then
    echo alpine
  fi
}
