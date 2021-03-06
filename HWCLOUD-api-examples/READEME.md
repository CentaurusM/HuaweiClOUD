
## Using HuaweiCloud API
### Import enviroment
```
source hec.rc
```
### Example: Creat a VM via HuaweiCloud API
``` 
sh vm_create.sh 
```

#### Examples of request body

1. Example 1: creat a linux VM by using "user_data" to inject root password 
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

2. Example 2: creat a window VM by using "meta_data" to inject admin password 

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
      "admin_pass": "your-password"
    },
    "tags": []
  }
}
```

## Using openstack-client to manage your HuaweiCLOUD resources 
### Install
``` 
apt-get install python-pip
pip install python-openstackclient
```
### Import env
``` 
source hec.rc
```

### test
``` 
openstack server list
```

## Use s3cmd to manager your Object Storage Service of HuaweiCLOUD
### Install
```
apt-get install s3cmd
```
### Setup
```
mv .s3cfg /root/

# change AK/SK values obtained from your HuaweiCloud
# Adjust other parameters as your need
```


## References
[1] <https://developer.huaweicloud.com/>



