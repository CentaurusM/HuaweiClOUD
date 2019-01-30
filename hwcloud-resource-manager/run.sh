pkill -f hwcloud_
nohup python -u -W ignore  hwcloud_resource_manager.py >> monitor.log 2>&1 &
