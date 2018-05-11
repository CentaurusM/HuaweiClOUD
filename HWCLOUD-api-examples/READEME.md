
# Use HuaweiCloud API to creat vm
## Import enviroment
```
source hec.rc
```
## Creat a virtual machine
``` 
sh vm_create.sh 
```

## Request payload example

### Example1: linux 
```
{
  "server": {
    "availability_zone": "cn-south-2b",
    "name": "ecs-a344",
    "isAutoRename": false,
    "imageRef": "f7fcd4ba-eca3-4b82-bbd2-eb01931a4c6d",
    "flavorRef": "s2.small.1",
    "root_volume": {
      "volumetype": "SAS",
      "size": 40,
      "extendparam": {
        "resourceSpecCode": "SAS",
        "resourceType": "3"
      }
    },
    "data_volumes": [],
    "vpcid": "f1353d72-4eda-4425-a8d1-2d849dd1d594",
    "nics": [
      {
        "subnet_id": "8cfe0447-48ff-4245-985c-9c1bee31f60c",
        "ip_address": "",
        "nictype": "",
        "extra_dhcp_opts": [],
        "binding:profile": {
          "disable_security_groups": false
        }
      }
    ],
    "security_groups": [
      {
        "id": "6c68d016-1b0d-4f0e-a6f8-01b48697bd65"
      }
    ],
    "personality": [],
    "count": 1,
    "extendparam": {
      "chargingMode": 0,
      "regionID": "cn-south-1"
    },
    "metadata": {
      "op_svc_userid": "d2954c70ef054b7bba0e2eb0c601d723",
      "admin_pass": ""
    },
    "tags": [],
    "user_data": "IyEvYmluL2Jhc2gKZWNobyAncm9vdDokNiQxb0pEZDIkSi8zZGcycHZrYTBYTXVLeFB2NFYudC90dk9XYkNmOUZrLklPYXF6cFUyemw4WnN5Ty9yOUhWNTRmekExZFlCRk1IN1l3ZFZrQU15Lk4xbHhwSVo0UTEnIHwgY2hwYXNzd2QgLWU7"
  }
}
```

### windows

```
{
  "server": {
    "availability_zone": "cn-south-2b",
    "name": "ecs-aebd",
    "isAutoRename": false,
    "imageRef": "3edc63bb-c2d4-4626-9ebd-911c9b654213",
    "flavorRef": "s2.small.1",
    "root_volume": {
      "volumetype": "SATA",
      "size": 40,
      "extendparam": {
        "resourceSpecCode": "SATA",
        "resourceType": "3"
      }
    },
    "data_volumes": [],
    "vpcid": "f1353d72-4eda-4425-a8d1-2d849dd1d594",
    "nics": [
      {
        "subnet_id": "8cfe0447-48ff-4245-985c-9c1bee31f60c",
        "ip_address": "",
        "nictype": "",
        "extra_dhcp_opts": [],
        "binding:profile": {
          "disable_security_groups": false
        }
      }
    ],
    "security_groups": [
      {
        "id": "6c68d016-1b0d-4f0e-a6f8-01b48697bd65"
      }
    ],
    "personality": [],
    "count": 1,
    "extendparam": {
      "chargingMode": 0,
      "regionID": "cn-south-1"
    },
    "metadata": {
      "op_svc_userid": "d2954c70ef054b7bba0e2eb0c601d723",
      "admin_pass": "Huawei@123$"
    },
    "tags": []
  }
}
```

# Use openstack client 
## install
``` 
apt-get install python-pip
pip install python-openstackclient
```
## import env
``` 
source hec.rc
```

## test
``` 
openstack server list
```



