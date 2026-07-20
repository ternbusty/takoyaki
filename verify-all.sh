#!/bin/bash
# Verify the features that were implemented but not yet end-to-end tested.
# Run on the VM after `cp build/native/nativeCompile/takoyaki /home/ubuntu/work/takoyaki`.
#
# IMPORTANT: never pipe takoyaki create/start output through a filter (grep, head, …)
# because the init child inherits the parent's stdout fd and holds it open as long
# as the container is running, which deadlocks the pipe consumer. Redirect to a
# file instead (`2>/tmp/foo.log`) and grep the file afterwards.

set -e
BIN=/home/ubuntu/work/takoyaki
WORK=/home/ubuntu/work

cleanup() {
  sudo $BIN delete --force "$1" 2>/dev/null || true
  sudo rm -rf /run/takoyaki "/tmp/takoyaki-$1.sock" 2>/dev/null || true
  sudo rmdir "/sys/fs/cgroup/takoyaki-$2" 2>/dev/null || true
}

run_init_log() {
  # $1 cid  $2 logfile  $3 bundle
  sudo $BIN --debug create --bundle "$3" "$1" >/dev/null 2>"$2" </dev/null
  sudo $BIN --debug start "$1"            >/dev/null 2>>"$2" </dev/null
}

prepare_busybox_rootfs() {
  # $1 bundle path
  mkdir -p "$1"/rootfs/{bin,tmp}
  cp /bin/busybox "$1"/rootfs/bin/
  ( cd "$1"/rootfs/bin && for c in sh ls cat echo grep awk; do ln -sf busybox "$c"; done )
}

echo "===== A. AppArmor (in-container effect) ====="
sudo tee /etc/apparmor.d/takoyaki-test > /dev/null <<'EOF'
abi <abi/4.0>,
include <tunables/global>
profile takoyaki-test flags=(attach_disconnected) {
  include <abstractions/base>
  capability,
  /** rwklmix,
  deny /tmp/aa-blocked w,
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/takoyaki-test
prepare_busybox_rootfs $WORK/aa-bundle
cat > $WORK/aa-bundle/config.json <<'EOF'
{ "ociVersion":"1.0.0","root":{"path":"rootfs"},
  "process":{"args":["/bin/sh","-c","{ echo profile=$(cat /proc/self/attr/current); echo blocked=$(echo X > /tmp/aa-blocked 2>&1 && echo WROTE || echo BLOCKED); echo allowed=$(echo X > /tmp/aa-allowed 2>&1 && echo WROTE || echo BLOCKED); } > /tmp/r.txt"],
             "env":["PATH=/bin"],"cwd":"/","user":{"uid":0,"gid":0},"apparmorProfile":"takoyaki-test"},
  "hostname":"aa","linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"}],"cgroupsPath":"/takoyaki-aa"} }
EOF
cleanup aa aa
run_init_log aa /tmp/A.log $WORK/aa-bundle
sleep 1
cat $WORK/aa-bundle/rootfs/tmp/r.txt 2>&1 | sed 's/^/  /'
cleanup aa aa

echo
echo "===== B. poststart/prestart/poststop hooks ====="
prepare_busybox_rootfs $WORK/hook-bundle
sudo rm -f /tmp/pre.txt /tmp/post.txt /tmp/stop.txt
for h in pre post stop; do
  cat > $WORK/hook-bundle/$h.sh <<EOF
#!/bin/bash
read X
date > /tmp/$h.txt
EOF
  chmod +x $WORK/hook-bundle/$h.sh
done
cat > $WORK/hook-bundle/config.json <<EOF
{ "ociVersion":"1.0.0","root":{"path":"rootfs"},
  "process":{"args":["/bin/sh","-c","sleep 1"],"env":["PATH=/bin"],"cwd":"/","user":{"uid":0,"gid":0}},
  "hostname":"h","linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"}],"cgroupsPath":"/takoyaki-h"},
  "hooks":{"prestart":[{"path":"$WORK/hook-bundle/pre.sh"}],
           "poststart":[{"path":"$WORK/hook-bundle/post.sh"}],
           "poststop":[{"path":"$WORK/hook-bundle/stop.sh"}]} }
EOF
cleanup hk h
run_init_log hk /tmp/B.log $WORK/hook-bundle
sleep 2
sudo $BIN delete --force hk >/dev/null 2>&1
echo "  prestart=$(test -f /tmp/pre.txt && echo FIRED || echo NO)"
echo "  poststart=$(test -f /tmp/post.txt && echo FIRED || echo NO)"
echo "  poststop=$(test -f /tmp/stop.txt && echo FIRED || echo NO)"
sudo rmdir /sys/fs/cgroup/takoyaki-h 2>/dev/null || true

echo
echo "===== C. cpuset (cpu.cpus inside container) ====="
cat > $WORK/hook-bundle/config.json <<EOF
{ "ociVersion":"1.0.0","root":{"path":"rootfs"},
  "process":{"args":["/bin/sh","-c","cat /sys/fs/cgroup/cpuset.cpus 2>&1 > /tmp/cpus.txt"],
             "env":["PATH=/bin"],"cwd":"/","user":{"uid":0,"gid":0}},
  "hostname":"c","linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"}],
                          "cgroupsPath":"/takoyaki-cs",
                          "resources":{"cpu":{"cpus":"0"}}} }
EOF
cleanup cs cs
run_init_log cs /tmp/C.log $WORK/hook-bundle
sleep 1
echo "  cpuset.cpus inside container: $(cat $WORK/hook-bundle/rootfs/tmp/cpus.txt 2>&1)"
cleanup cs cs

echo
echo "===== D. timens offsets (applied in bootstrap.c stage-1) ====="
cat > $WORK/hook-bundle/config.json <<EOF
{ "ociVersion":"1.0.0","root":{"path":"rootfs"},
  "process":{"args":["/bin/sh","-c","{ echo uptime=\$(awk '{print \$1}' /proc/uptime); echo timens_offsets:; cat /proc/self/timens_offsets; } > /tmp/off.txt 2>&1"],
             "env":["PATH=/bin"],"cwd":"/","user":{"uid":0,"gid":0}},
  "hostname":"t","linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"},{"type":"time"}],
                          "cgroupsPath":"/takoyaki-tn",
                          "timeOffsets":{"boottime":{"secs":3600,"nanosecs":0}}} }
EOF
cleanup tn tn
HOST_UPTIME=$(awk '{print int($1)}' /proc/uptime)
run_init_log tn /tmp/D.log $WORK/hook-bundle
sleep 1
echo "  host uptime: ${HOST_UPTIME}s"
sed 's/^/  /' $WORK/hook-bundle/rootfs/tmp/off.txt
cleanup tn tn

echo
echo "===== E. session keyring (debug-log evidence) ====="
cat > $WORK/hook-bundle/config.json <<EOF
{ "ociVersion":"1.0.0","root":{"path":"rootfs"},
  "process":{"args":["/bin/sh","-c","sleep 1"],"env":["PATH=/bin"],"cwd":"/","user":{"uid":0,"gid":0}},
  "hostname":"k","linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"}],"cgroupsPath":"/takoyaki-kr"} }
EOF
cleanup kr kr
run_init_log kr /tmp/E.log $WORK/hook-bundle
sleep 1
grep -E "joined new session keyring|keyctl" /tmp/E.log | sed 's/^/  /' | head -3
cleanup kr kr

echo
echo "===== F. device cgroup eBPF (cgroup v2) ====="
cat > $WORK/hook-bundle/config.json <<EOF
{ "ociVersion":"1.0.0","root":{"path":"rootfs"},
  "process":{"args":["/bin/sh","-c","sleep 1"],"env":["PATH=/bin"],"cwd":"/","user":{"uid":0,"gid":0}},
  "hostname":"d","linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"}],
                          "cgroupsPath":"/takoyaki-dv",
                          "resources":{"devices":[
                            {"allow":false,"access":"rwm"},
                            {"allow":true,"type":"c","major":1,"minor":3,"access":"rwm"}
                          ]}} }
EOF
cleanup dv dv
run_init_log dv /tmp/F.log $WORK/hook-bundle
sleep 1
grep -iE "bpf|device.cgroup|prog_load|prog_attach" /tmp/F.log | sed 's/^/  /' | head -5
cleanup dv dv

echo
echo "===== G. per-mount propagation (private rbind) ====="
mkdir -p $WORK/hook-bundle/rootfs/perm
cat > $WORK/hook-bundle/config.json <<EOF
{ "ociVersion":"1.0.0","root":{"path":"rootfs"},
  "process":{"args":["/bin/sh","-c","grep ' /perm ' /proc/self/mountinfo > /tmp/prop.txt 2>&1; sleep 0"],
             "env":["PATH=/bin"],"cwd":"/","user":{"uid":0,"gid":0}},
  "hostname":"p","linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"}],
                          "cgroupsPath":"/takoyaki-pr"},
  "mounts":[{"destination":"/perm","source":"/tmp","type":"none","options":["rbind","private","ro"]}] }
EOF
cleanup pr pr
run_init_log pr /tmp/G.log $WORK/hook-bundle
sleep 1
echo "  /perm mountinfo line:"
sed 's/^/    /' $WORK/hook-bundle/rootfs/tmp/prop.txt 2>&1 || echo "    (missing)"
cleanup pr pr

echo
echo "===== H. mount idmap (kernel 5.12+, host-prepared userns_fd) ====="
uname -r
# IMPORTANT: this test deliberately does NOT use an enclosing user namespace.
# An idmap mount with a separate per-mount uidMappings is independently useful
# (and easier to set up with bundle ownership) and that's what this verifies.
prepare_busybox_rootfs $WORK/idmap-bundle
rm -f /tmp/idmap-source.txt
echo testhost > /tmp/idmap-source.txt
chown 100000:100000 /tmp/idmap-source.txt
cat > $WORK/idmap-bundle/config.json <<EOF
{ "ociVersion":"1.0.0","root":{"path":"rootfs"},
  "process":{"args":["/bin/sh","-c","ls -ln /idmap/idmap-source.txt > /tmp/idm.txt 2>&1; sleep 0"],
             "env":["PATH=/bin"],"cwd":"/","user":{"uid":0,"gid":0}},
  "hostname":"i","linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"}],
                          "cgroupsPath":"/takoyaki-id"},
  "mounts":[{"destination":"/idmap","source":"/tmp","type":"none","options":["bind","rw"],
             "uidMappings":[{"containerID":0,"hostID":100000,"size":1}],
             "gidMappings":[{"containerID":0,"hostID":100000,"size":1}]}] }
EOF
cleanup id id
mkdir -p $WORK/idmap-bundle/rootfs/idmap
run_init_log id /tmp/H.log $WORK/idmap-bundle
sleep 1
echo "  ls -ln /idmap/idmap-source.txt inside container:"
sed 's/^/    /' $WORK/idmap-bundle/rootfs/tmp/idm.txt 2>&1 || echo "    (missing)"
grep -iE "host-prepared|uid_map|fd inherited" /tmp/H.log | head -3 | sed 's/^/  log: /'
cleanup id id

echo
echo "===== I. exec re-applies restrictions (seccomp/caps/NNP/cgroup/rlimits/AppArmor) ====="
# The exec'd process must NOT inherit the host-side unrestricted state: seccomp
# filter, capability bounding set, no_new_privs, rlimits and cgroup membership
# all have to be re-applied by the exec path itself (setns carries none of them).
prepare_busybox_rootfs $WORK/exec-bundle
mkdir -p $WORK/exec-bundle/rootfs/proc
cat > $WORK/exec-bundle/config.json <<'EOF'
{ "ociVersion":"1.0.0","root":{"path":"rootfs"},
  "process":{"args":["/bin/sh","-c","sleep 30"],
             "env":["PATH=/bin"],"cwd":"/","user":{"uid":0,"gid":0},
             "noNewPrivileges":true,
             "apparmorProfile":"takoyaki-test",
             "capabilities":{"bounding":["CAP_KILL"],"effective":["CAP_KILL"],"permitted":["CAP_KILL"]},
             "rlimits":[{"type":"RLIMIT_NOFILE","hard":512,"soft":512}]},
  "hostname":"ex",
  "linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"uts"},{"type":"ipc"}],
           "cgroupsPath":"/takoyaki-ex",
           "seccomp":{"defaultAction":"SCMP_ACT_ALLOW",
                      "architectures":["SCMP_ARCH_AARCH64"],
                      "syscalls":[{"names":["mkdir","mkdirat"],"action":"SCMP_ACT_ERRNO","errnoRet":1}]}} }
EOF
cleanup ex ex
run_init_log ex /tmp/I.log $WORK/exec-bundle
sleep 1
sudo $BIN --debug exec ex /bin/sh -c '{
  grep Seccomp: /proc/self/status
  grep NoNewPrivs /proc/self/status
  grep CapBnd /proc/self/status
  echo "cgroup=$(cat /proc/self/cgroup)"
  echo "apparmor=$(cat /proc/self/attr/current 2>/dev/null)"
  echo "nofile=$(ulimit -n)"
  mkdir /tmp/mk-test 2>/dev/null && echo "mkdir=ALLOWED(BAD)" || echo "mkdir=BLOCKED(GOOD)"
}' > /tmp/exec-out.txt 2>/tmp/I-exec.log </dev/null || echo "  exec FAILED (see /tmp/I-exec.log)"
sed 's/^/  /' /tmp/exec-out.txt
# Expected: Seccomp: 2, NoNewPrivs: 1, CapBnd: 0000000000000020 (CAP_KILL only),
# cgroup path ending in takoyaki-ex, nofile=512, mkdir blocked by seccomp.
rc=0
sudo $BIN exec ex /bin/sh -c 'exit 7' >/dev/null 2>&1 </dev/null || rc=$?
echo "  exit code propagation (want 7): $rc"
cleanup ex ex

echo
echo "===== DONE ====="
