export POLICYCOW_TASKPATH=$(yq e '.pathConfiguration.tasksPath' etc/cowconfig.yaml)
export POLICYCOW_RULESPATH=$(yq e '.pathConfiguration.rulesPath' etc/cowconfig.yaml)
export POLICYCOW_EXECUTIONPATH=$(yq e '.pathConfiguration.executionPath' etc/cowconfig.yaml)
export POLICYCOW_RULEGROUPPATH=$(yq e '.pathConfiguration.ruleGroupPath' etc/cowconfig.yaml)
export POLICYCOW_SYNTHESIZERPATH=$(yq e '.pathConfiguration.synthesizersPath' etc/cowconfig.yaml)
export POLICYCOW_DOWNLOADSPATH=$(yq e '.pathConfiguration.downloadsPath' etc/cowconfig.yaml)
export COW_DATA_PERSISTENCE_TYPE=minio
export COMPOSE_PROJECT_NAME=policycow