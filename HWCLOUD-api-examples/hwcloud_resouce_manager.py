import json
import requests
import six

from oslo_config import cfg
from six.moves.urllib import parse

from apscheduler.schedulers.blocking import BlockingScheduler
from datetime import datetime

keystone_authtoken_opts = [
    cfg.StrOpt("project_name"),
    cfg.StrOpt("user"),
    cfg.StrOpt("password"),
    cfg.StrOpt("auth_protocol"),
    cfg.StrOpt("auth_host"),
    cfg.StrOpt("auth_port"),
    cfg.StrOpt("auth_admin_prefix"),
    cfg.StrOpt("auth_version"),
    cfg.StrOpt("http_connect_timeout"),
    cfg.StrOpt("region_name"),
    cfg.StrOpt("region_name_alias"),
    cfg.StrOpt("invalid_pods")
]

CONF = cfg.CONF
auth_config = 'auth.conf'
CONF.register_opts(keystone_authtoken_opts, group="keystone_authtoken")
CONF(args='', default_config_files=[auth_config])


class HTTPClient(object):
    general_headers = {
        "user_agent": "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)",
        'Content-Type': 'application/json'
    }

    proxies = {}

    @staticmethod
    def do_get(url, headers):
        headers.update(HTTPClient.general_headers)
        resp = requests.get(url, headers=headers, verify=False, proxies=HTTPClient.proxies)
        resp_headers = resp.headers
        resp_body = json.loads(resp.text)
        return resp_headers, resp_body

    @staticmethod
    def do_post(url, headers, body):
        headers.update(HTTPClient.general_headers)
        resp = requests.post(url, headers=headers, data=json.dumps(body), proxies=HTTPClient.proxies, verify=False)
        resp_headers = resp.headers
        resp_body = json.loads(resp.text)
        return resp_headers, resp_body

    @staticmethod
    def do_delete(url, headers):
        headers.update(HTTPClient.general_headers)
        resp = requests.delete(url, headers=headers, proxies=HTTPClient.proxies, verify=False)
        return resp


class CloudClient(object):
    token_body = {
        "auth": {
            "identity": {
                "methods": [
                    "password"
                ],
                "password": {
                    "user": {
                        "domain": {
                            "name": CONF.keystone_authtoken.user
                        },
                        "name": CONF.keystone_authtoken.user,
                        "password": CONF.keystone_authtoken.password
                    }
                }
            },
            "scope": {
                "project": {
                    "name": CONF.keystone_authtoken.project_name,
                    "domain": {
                        "name": "Default"
                    }
                }
            }
        }
    }

    def __init__(self):
        self.auth_token = None
        self.catalog = dict()
        self.keystone_url = None
        self._init_keystone()

    def init_admin_token(self):
        headers = {"Accept": "application/json"}
        issue_token_url = "%s/auth/tokens" % self.keystone_url
        resp_headers, resp_body = HTTPClient.do_post(issue_token_url,
                                                     headers,
                                                     self.token_body)
        self.auth_token = resp_headers.get('X-Subject-Token')
        self.catalog = resp_body.get('token').get('catalog')

    def _init_keystone(self):
        auth_url = "%s://%s:%s/%s" % (
            CONF.keystone_authtoken.auth_protocol,
            CONF.keystone_authtoken.auth_host,
            CONF.keystone_authtoken.auth_port,
            CONF.keystone_authtoken.auth_version
        )
        self.keystone_url = auth_url
        self.init_admin_token()

    def get_endpoint(self, endpoint_type, service_name, service_type, region_name):
        if not self.catalog:
            return None
        for cat in self.catalog:
            # print(self.catalog)
            if cat.get('name') == service_name and cat.get('type') == service_type:
                for endpoint in cat.get("endpoints"):
                    if endpoint.get('interface') == endpoint_type and endpoint.get('region') == region_name:

                        return endpoint.get('url')

    def get_all_regions(self):
        url = "https://iam.myhuaweicloud.com:443/v3/services"
        headers = {
            'X-Auth-Token': self.auth_token,
            "Accept": "application/json",
            "X-OpenStack-Nova-API-Version": "2.26"
        }
        resp_headers, resp_body = HTTPClient.do_get(url, headers=headers)
        print("all_region:" , resp_body)
        return resp_body


    @staticmethod
    def get_global_region_name():
        return CONF.keystone_authtoken.region_name

    def get_nova_pods(self):
        if not self.catalog:
            return []
        region_names = []
        global_region_name = self.get_global_region_name()
        for cat in self.catalog:
            if cat.get('name') == 'nova' and cat.get('type') == 'compute':
                for endpoint in cat.get("endpoints"):
                    if endpoint.get('interface') == 'public' and endpoint.get('region') != global_region_name:
                        region_names.append(endpoint.get('region'))
        pod_list = list(set(region_names))
        for invalid_pod in CONF.keystone_authtoken.invalid_pods.split(","):
            pod_list.remove(invalid_pod)
        return pod_list

    def get_nova_availability_zone(self):
        region_names = self.get_nova_pods()
        availability_zones = []
        for region in region_names:
            availability_zones.append(region.split('.')[-1])
        return list(set(availability_zones))

    def get_aggregates(self, region_name):
        nova_url = self.get_endpoint('public', 'nova', 'compute', region_name)
        get_aggregates_url = "%s/os-aggregates" % nova_url
        resp_headers, resp_body = HTTPClient.do_get(get_aggregates_url,
                                                    {'X-Auth-Token': self.auth_token,
                                                     "Accept": "application/json",
                                                     "X-OpenStack-Nova-API-Version": "2.26"}
                                                    )
        return resp_body

    def list_servers(self, region_name,
                     detailed=True, search_opts=None,
                     marker=None, limit=None,
                     sort_keys=None, sort_dirs=None):
        headers = {
            'X-Auth-Token': self.auth_token,
            "Accept": "application/json",
            "X-OpenStack-Nova-API-Version": "2.26"
        }
        nova_url = self.get_endpoint('public', 'nova', 'compute', region_name)
        if search_opts is None:
            search_opts = {}

        qparams = {}

        for opt, val in six.iteritems(search_opts):
            if val:
                if isinstance(val, six.text_type):
                    val = val.encode('utf-8')
                qparams[opt] = val

        detail = ""
        if detailed:
            detail = "/detail"

        result = []
        while True:
            if marker:
                qparams['marker'] = marker
            if limit and limit != -1:
                qparams['limit'] = limit
            if qparams or sort_keys or sort_dirs:
                items = list(qparams.items())
                if sort_keys:
                    items.extend(('sort_key', sort_key) for sort_key in sort_keys)
                if sort_dirs:
                    items.extend(('sort_dir', sort_dir) for sort_dir in sort_dirs)
                new_qparams = sorted(items, key=lambda x: x[0])
                query_string = "?%s" % parse.urlencode(new_qparams)
            else:
                query_string = ""

            _, resp_body = HTTPClient.do_get("%s/servers%s%s" %
                                             (nova_url, detail, query_string),
                                             headers)
            servers = resp_body.get("servers")
            result.extend(servers)

            if not servers or limit != -1:
                break
            marker = result[-1].id
        return result


    def delete_server(self, region_name, server_id):
        headers = {
            'X-Auth-Token': self.auth_token,
            "Accept": "application/json",
            "X-OpenStack-Nova-API-Version": "2.26"
        }
        nova_url = self.get_endpoint('public', 'nova', 'compute', region_name)

        url = "%s/servers/%s" %(nova_url, server_id)
        resp = HTTPClient.do_delete("%s/servers/%s" %
                                             (nova_url, server_id),
                                             headers)

        return resp

    def get_flavor(self, flavor_name):
        nova_url = self.get_endpoint('public', 'nova', 'compute', self.get_global_region_name())
        get_flavor_extra = "%s/flavors/%s/os-extra_specs" % (nova_url, flavor_name)
        resp_headers, resp_body = HTTPClient.do_get(get_flavor_extra,
                                                    {'X-Auth-Token': self.auth_token,
                                                     "Accept": "application/json",
                                                     "X-OpenStack-Nova-API-Version": "2.26"}
                                                    )
        if 'itemNotFound' in resp_body.keys():
            return None
        return resp_body

    def list_bandwith(self, region_name, search_opts=None,
                     marker=None, limit=None,
                     sort_keys=None, sort_dirs=None):
        headers = {
            'X-Auth-Token': self.auth_token,
            "Accept": "application/json",
            "X-OpenStack-Nova-API-Version": "2.26"
        }
        vpc_url = self.get_endpoint('public', 'vpcv2.0', 'vpcv2.0', region_name)
        if search_opts is None:
            search_opts = {}

        qparams = {}

        for opt, val in six.iteritems(search_opts):
            if val:
                if isinstance(val, six.text_type):
                    val = val.encode('utf-8')
                qparams[opt] = val

        detail = ""
        #if detailed:
        #    detail = "/detail"

        result = []
        while True:
            if marker:
                qparams['marker'] = marker
            if limit and limit != -1:
                qparams['limit'] = limit
            if qparams or sort_keys or sort_dirs:
                items = list(qparams.items())
                if sort_keys:
                    items.extend(('sort_key', sort_key) for sort_key in sort_keys)
                if sort_dirs:
                    items.extend(('sort_dir', sort_dir) for sort_dir in sort_dirs)
                new_qparams = sorted(items, key=lambda x: x[0])
                query_string = "?%s" % parse.urlencode(new_qparams)
            else:
                query_string = ""

            _, resp_body = HTTPClient.do_get("%s/bandwidths%s%s" %
                                             (vpc_url, detail, query_string),
                                             headers)
            bandwidths = resp_body.get("bandwidths")
            result.extend(bandwidths)

            if not bandwidths or limit != -1:
                break
            marker = result[-1].id
        return result

    def delete_ip(self, region_name, ip_id):
        headers = {
            'X-Auth-Token': self.auth_token,
            "Accept": "application/json",
            "X-OpenStack-Nova-API-Version": "2.26"
        }
        endpoint = self.get_endpoint('public', 'vpcv2.0', 'vpcv2.0', region_name)

        url = "%s/publicips/%s" %(endpoint, ip_id)
        print url
        #resp = HTTPClient.do_delete(url, headers)

        #return resp


class CloudMonitor(object):

    def __init__(self):
        self.client = CloudClient()
        self.users = {'m00405515':'mafuda',
                      'z00364752':'zhangyi',
                      'z00297223':'zhangjianbin',
                      'z00417897':'zhutun',
                      'l00213780':'lijuan',
                      't00357535':'tianxinghui',
                      'z00393177':'zhangjihai',
                      'wwx493768':'wanglijuan',
                      'z00205886':'zhuziguang',
                      'l00349281':'l00349281'}


    def _auth_users(self, server_name):
        return any(self.users.has_key(item) for item in server_name.lower().split("-"))


    def servers_monitor(self, region_name):
        #self.client.get_all_regions()
        servers =  self.client.list_servers(region_name, detailed=True)
        for server in servers:
            # print server.get('name')
            if not self._auth_users(server.get('name')): 
                print("%s: server: %s is invailed and has been deleted" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), server.get('name')))
                res = self.client.delete_server(region_name, server.get('id'))
                pass

    def bandwidths_monitor(self, region_name):
        bandwidths = self.client.list_bandwith(region_name)
        for bandwidth in bandwidths:
            #print(bandwidth.get('charge_mode'))
            if bandwidth.get('charge_mode') == 'bandwidth':
                #print(bandwidth.get('publicip_info')[0].get('publicip_id'))
                publicips = bandwidth.get('publicip_info')
                for publicip in publicips:
                    print publicip.get('publicip_id')
                    #self.client.delete_ip(region_name, publicip.get('publicip_id'))


    def volumes_monitor(self, region_name):
        pass

    def cost_monitor(self, region_name):
        pass


#if __name__ == '__main__':
def monitor_job(): 
    c = CloudMonitor()
   # regions = ['cn-north-1', 'cn-south-1', 'cn-east-2']
    regions = ['cn-north-1']
    for region in regions:
        print "region:", region
        c.servers_monitor(region)
        #c.bandwidths_monitor(region)
        #c.volumes_monitor(region)

    #print(c.auth_token)


def job():
    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


print("%s Start moinitoring..." % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
sched = BlockingScheduler()
sched.add_job(monitor_job, 'interval', seconds=120)
sched.start()



    # pods = c.get_nova_pods()
    # print(pods)
    # print(c.get_nova_availability_zone())
    # # print c.get_aggregates(pods[0])
    # for p in pods:
    #     print("=" * 100 + " " * 20 + p)
    #     print(c.get_aggregates(p))
    # bandwidths = c.list_bandwith('cn-north-1')
    # for bandwidth in bandwidths:
    #     #print(bandwidth.get('charge_mode'))
    #     if bandwidth.get('charge_mode') == 'bandwidth':
    #         print(bandwidth)
    #         pass
            #Delete_ip_bandwidth()

        #print(c.get_flavor("g3.4xlarge.4"))
    #print(c.get_endpoint('public', 'neutron', 'network', c.get_global_region_name()))


