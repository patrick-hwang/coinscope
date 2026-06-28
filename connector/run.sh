#!/bin/bash
sudo prlimit --nofile=999900 ./main ../netmine.cfg
