export POLICYCOW_TASKPATH=$(yq e '.pathConfiguration.tasksPath' etc/cowconfig.yaml | tr -d '\r')
export POLICYCOW_RULESPATH=$(yq e '.pathConfiguration.rulesPath' etc/cowconfig.yaml | tr -d '\r')
export POLICYCOW_EXECUTIONPATH=$(yq e '.pathConfiguration.executionPath' etc/cowconfig.yaml | tr -d '\r')
export POLICYCOW_RULEGROUPPATH=$(yq e '.pathConfiguration.ruleGroupPath' etc/cowconfig.yaml | tr -d '\r')
export POLICYCOW_SYNTHESIZERPATH=$(yq e '.pathConfiguration.synthesizersPath' etc/cowconfig.yaml | tr -d '\r')
export POLICYCOW_DOWNLOADSPATH=$(yq e '.pathConfiguration.downloadsPath' etc/cowconfig.yaml | tr -d '\r')
export COW_DATA_PERSISTENCE_TYPE=minio
export COMPOSE_PROJECT_NAME=policycow

# Git Bash on Windows has no sudo (docker needs no elevation there) and rewrites
# Unix-looking arguments such as /bin/sh into Windows paths.
command -v sudo >/dev/null 2>&1 || sudo() { "$@"; }
export MSYS_NO_PATHCONV=1

export COMPOSE_FILE=docker-compose.yaml
export COW_SHELL=/bin/sh
export COW_NETWORK_ARGS="--driver bridge --scope local"

# compose requires etc/.credentials.env; seed it from the template on a fresh checkout
[ -f etc/.credentials.env ] || { [ -f etc/.credentials.env.template ] && cp etc/.credentials.env.template etc/.credentials.env; }

# bind-mount sources must exist before compose starts
mkdir -p "$HOME/tmp/cowctl/minio" exported-data cowexecutions catalog/localcatalog \
    catalog/applicationscope catalog/globalcatalog/{dashboards,rules,methods,rulegroups,tasks,cowexecutions,synthesizers} \
    catalog/globalcatalog/declaratives/{applicationtypes,credentialtypes} \
    catalog/globalcatalog/yamlfiles/{applicationtypes,credentialtypes}
