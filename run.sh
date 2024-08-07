#!/bin/bash

source export_env.sh
sh ./up.sh
sudo docker restart cowctl > /dev/null
sudo docker exec -it cowctl /bin/sh