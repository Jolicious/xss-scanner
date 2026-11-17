#!/bin/bash
# Local release gate: same checks CI runs, minus the pinned-tool install.
set +e
HERE=$(cd "$(dirname "$0")" && pwd)
RC=0
cd "$HERE/.." || exit 1

echo "== shell syntax"
bash -n xss-scan.sh || RC=1
echo "== python syntax"
python3 -m py_compile xss-queue.py xss-report.py || RC=1
echo "== queue regressions"
python3 tests/test_host_status.py || RC=1
echo "== notify regression"
bash tests/test_notify.sh || RC=1
echo "== resume regression"
bash tests/test_resume.sh || RC=1
echo "== browser acceptance (needs nuclei+chromium)"
python3 tests/fixture_suite.py
case $? in
  0) : ;;
  77) echo "skipped (tools missing)" ;;
  *) RC=1 ;;
esac
exit "$RC"
