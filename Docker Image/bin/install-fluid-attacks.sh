#!/bin/bash

echo -e "\n Fluid Attacks Software Installation Starting...\n"

curl -L fluidattacks.com/install/m | sh
# m f /skims --help

git clone <git-hub-repo-link> /root/codesecure

m f /skims scan /root/bin/config.yaml

echo -e "\n Fluid Attacks Installation Complete! \n"