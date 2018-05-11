#!/bin/bash

# see details here: http://developer.hwclouds.com/endpoint.html
HEC_IAM_ENDPOINT="https://iam.$OS_PROJECT_NAME.myhwclouds.com"
HEC_ECS_ENDPOINT="https://ecs.$OS_PROJECT_NAME.myhwclouds.com"
HEC_VPC_ENDPOINT="https://vpc.$OS_PROJECT_NAME.myhwclouds.com"

TOKEN_AUTH_PARAMS='{
  "auth": {
    "identity": {
      "methods": [
        "password"
      ],
      "password": {
        "user": {
          "name": '"\"$OS_USERNAME\""',
          "password": '"\"$OS_PASSWORD\""',
          "domain": {
            "name": '"\"$OS_USERNAME\""'
          }
        }
      }
    },
   "scope": {
      "project": {
        "name": '"\"$OS_PROJECT_NAME\""'
      }
    }
  }
}'


curl -i -X POST ${HEC_IAM_ENDPOINT}/v3/auth/tokens -H 'content-type: application/json' -d "$TOKEN_AUTH_PARAMS" > /tmp/hec_auth_res && {
    TOKEN=`cat /tmp/hec_auth_res | grep "X-Subject-Token"| awk '{print$2}'`
    # echo "HEC Token is: $TOKEN"

    PROJECT_ID=`tail -n 1 /tmp/hec_auth_res|python -c 'import json,sys;print json.load(sys.stdin)["token"]["project"]["id"]'`
    echo "HEC Project ID is: $PROJECT_ID"
}

# echo "token_auth_param:"
# echo $TOKEN_AUTH_PARAMS


CREATE_VM_PARAMS='{
    "server": {
        "availability_zone": "cn-south-2b",
        "name": "ecs-test",
        "imageRef": "9e473a9d-da52-44ab-9973-92b584b645b8",
        "root_volume": {
            "volumetype": "SAS"
        },
        "flavorRef": "g3.4xlarge.4",
        "vpcid": "f1353d72-4eda-4425-a8d1-2d849dd1d594",
        "nics": [
            {
                "subnet_id": "8cfe0447-48ff-4245-985c-9c1bee31f60c"
            }
        ],
	"extendparam": {
	    "chargingMode":0
	},
	"user_data": "IyEvYmluL2Jhc2gKZWNobyAncm9vdDokNiQxb0pEZDIkSi8zZGcycHZrYTBYTXVLeFB2NFYudC90dk9XYkNmOUZrLklPYXF6cFUyemw4WnN5Ty9yOUhWNTRmekExZFlCRk1IN1l3ZFZrQU15Lk4xbHhwSVo0UTEnIHwgY2hwYXNzd2QgLWU7",
	"count": 1
	
    }
}'
echo $CREATE_VM_PARAMS

curl -i -X POST https://ecs.$OS_PROJECT_NAME.myhwclouds.com/v1/${PROJECT_ID}/cloudservers -H "X-Auth-Token:${TOKEN}" -d "$CREATE_VM_PARAMS"

