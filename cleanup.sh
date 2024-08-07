#!/bin/bash
# This script is to free up your disk space consuming space in docker 
sudo -E docker rm $(sudo -E docker ps -a |grep "Exited" |awk '{print $1}')
sudo -E docker rmi $(sudo -E docker images |grep "<none>" |awk '{print $3}')

