# shellcheck shell=bash disable=SC2034
# (ref is read by the step that sources this file.)
# Sourced by build.yml's compare steps (vectors, smoke realm): sets `ref`, the
# branch of the repo at $url to compare against.
#   COMPARE_REF set (workflow_dispatch input): exactly that branch; a name
#     outside [A-Za-z0-9._/-] or a branch $url doesn't have fails the run.
#   Else REF (this run's branch, or a PR's head): the same-named branch when
#     $url has it, else main.
# git ls-remote --exit-code: 0 = the branch exists, 2 = it doesn't; anything
# else (network, auth) fails rather than comparing main.
url=${url:?set url before sourcing compare-ref.sh}
ref=main
if [ -n "${COMPARE_REF:-}" ]; then
  if ! [[ "$COMPARE_REF" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    echo "::error::compare_ref '$COMPARE_REF' isn't a branch name"
    exit 1
  fi
  rc=0
  git ls-remote --exit-code --heads "$url" "$COMPARE_REF" >/dev/null || rc=$?
  case "$rc" in
    0) ref="$COMPARE_REF" ;;
    2) echo "::error::$url has no branch $COMPARE_REF (compare_ref)"; exit 1 ;;
    *) echo "::error::git ls-remote $url $COMPARE_REF failed (exit $rc)"; exit 1 ;;
  esac
elif [[ "${REF:-}" =~ ^[A-Za-z0-9._/-]+$ ]] && [ "$REF" != main ]; then
  rc=0
  git ls-remote --exit-code --heads "$url" "$REF" >/dev/null || rc=$?
  case "$rc" in
    0) ref="$REF" ;;
    2) ;;
    *) echo "::error::git ls-remote $url $REF failed (exit $rc)"; exit 1 ;;
  esac
fi
