#! /bin/sh

CRATE_NAME=toluol-proto

BOLD_RED="\033[1;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;93m"
RESET_COLOURS="\033[0m"
DONE="${GREEN} done.${RESET_COLOURS}"
ABORT="${BOLD_RED}Aborting.${RESET_COLOURS}"

read_and_check_input() {
    echo -n "$1 (y/N) "
    read input
    if [[ "$input" != "y" && "$input" != "Y" ]]; then
        abort
    fi
}

abort() {
    echo -e $ABORT
    exit 1
}

version=$(sed 's/^version = "\(.*\)"$/\1/;t;d' Cargo.toml)
read_and_check_input "Detected version $version. Is that correct?"

echo -e "${YELLOW}Go update CHANGELOG.md. Do it now.${RESET_COLOURS}"
read_and_check_input "Finished?"

echo -n "Regenerating Cargo.lock to make sure it is up to date..."
cargo generate-lockfile --quiet
echo -e $DONE

if [[ -n "$(git status --porcelain)" ]]; then
    if [[ -z "$(git status --untracked-files=no --porcelain)" ]]; then 
        echo -e "${YELLOW}There are no uncommitted changes, but there are untracked files.${RESET_COLOURS}"
        read_and_check_input "Do you still want to continue?"
    else 
        echo -e "${BOLD_RED}There are uncommitted changes.${RESET_COLOURS}"
        abort
    fi
else 
    echo -e "${GREEN}Working directory clean.${RESET_COLOURS}"
fi

echo -n 'Dry-running `cargo publish`...'
if cargo publish --dry-run --allow-dirty --quiet ; then
    echo -e " ${GREEN}successful.${RESET_COLOURS}"
else
    echo -e " ${BOLD_RED}failed!${RESET_COLOURS}"
    abort
fi

echo -n "Tagging HEAD as $CRATE_NAME-v$version... "
git tag -f "$CRATE_NAME-v$version"
echo -e $DONE

echo -n "Pushing to origin..."
git push --quiet
echo -e $DONE

echo -n "Publishing new version on crates.io..."
cargo publish --allow-dirty --quiet
echo -e $DONE
