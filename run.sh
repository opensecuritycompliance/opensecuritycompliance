#!/bin/bash

source ./export_env.sh
bash ./up.sh
sudo docker restart cowctl > /dev/null
sudo docker exec -it cowctl $COW_SHELL
