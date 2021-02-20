# !/bin/bash

make runsc && sudo cp ./bazel-bin/runsc/linux_amd64_pure_stripped/runsc /usr/local/bin/runsc-delay && \
sudo rm -rf /tmp/runsc/*
