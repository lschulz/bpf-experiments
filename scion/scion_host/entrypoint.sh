#!/bin/bash

appdeps.py --file-wait gen/links_ready

# Start AS processes
supervisorctl -c supervisor/supervisord.conf start dispatcher
supervisorctl -c supervisor/supervisord.conf start ${SUPERVISOR_PROCESS_GROUP}:*
