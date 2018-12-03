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
    def __init__(self, region_name='cn-north-1'):
        self.auth_token = None
        self.catalog = dict()
        self.keystone_url = None
        self.region = region_name
        self._init_keystone()
        self.endpoints = {}

    def init_admin_token(self):
        headers = {"Accept": "application/json"}
        issue_token_url = "%s/auth/tokens" % self.keystone_url

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
                        "name": self.region
                    }
                }
            }
        }

        resp_headers, resp_body = HTTPClient.do_post(issue_token_url,
                                                     headers,
                                                     token_body)

        self.auth_token = resp_headers.get('X-Subject-Token')
        self.catalog = resp_body.get('token').get('catalog')
        # print(self.catalog)

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
        url = "https://iam.myhuaweicloud.com:443/v3/regions"
        headers = {
            'X-Auth-Token': self.auth_token,
            "Accept": "application/json",
            "X-OpenStack-Nova-API-Version": "2.26"
        }
        resp_headers, resp_body = HTTPClient.do_get(url, headers=headers)
        print("all_region:", resp_body)
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

    def get_servers(self, region_name,
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

    def get_public_ips(self, region_name, search_opts=None,
                       marker=None, limit=None, sort_keys=None, sort_dirs=None):
        headers = {
            'X-Auth-Token': self.auth_token,
            "Accept": "application/json",
            "X-OpenStack-Nova-API-Version": "2.26"
        }
        vpc_url = self.get_endpoint('public', 'vpc', 'vpc', region_name)
        if search_opts is None:
            search_opts = {}

        qparams = {}

        for opt, val in six.iteritems(search_opts):
            if val:
                if isinstance(val, six.text_type):
                    val = val.encode('utf-8')
                qparams[opt] = val

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

            _, resp_body = HTTPClient.do_get("%s/publicips%s" %
                                             (vpc_url, query_string),
                                             headers)
            public_ips = resp_body.get("publicips")
            result.extend(public_ips)

            if not public_ips or limit != -1:
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

    def get_bandwidths(self, region_name, search_opts=None,
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

            _, resp_body = HTTPClient.do_get("%s/bandwidths%s" %
                                             (vpc_url, query_string),
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
        endpoint = self.get_endpoint('public', 'vpc', 'vpc', region_name)
        url = "%s/publicips/%s" % (endpoint, ip_id)
        resp = HTTPClient.do_delete(url, headers)
        return resp


class CloudMonitor(CloudClient):
    def __init__(self, region_name):
        self.auth_users = {'m00405515': 'mafuda',
                          'z00364752': 'zhangyi',
                          'z00297223': 'zhangjianbin',
                          'z00417897': 'zhutun',
                          'l00213780': 'lijuan',
                          't00357535': 'tianxinghui',
                          'z00393177': 'zhangjihai',
                          'wwx493768': 'wanglijuan',
                          'z00205886': 'zhuziguang',
                          'l00349281': 'l00349281'}
        super(CloudMonitor, self).__init__(region_name)

    def _auth_users(self, server_name):
        return any(item in self.auth_users.keys() for item in server_name.lower().split("-"))

    def servers_monitoring(self):
        
        def _delete_high_cost_servers(servers):
            # print("%s, T" % datetime.now().hour)
            for server in servers:
                if server.get('flavor').get('id') in ["p1.2xlarge.8", "p1.4xlarge.8, p1.8xlarege.8"]:
                    print("%s: %s：invalid server is deleted: %s, %s"
                          % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                             self.region, server.get('name'), server.get('flavor').get('id')))
                    #self.delete_server(self.region, server.get('id'))
                        
        def _shutdown_high_cost_servers(servers):
            # print("%s, T" % datetime.now().hour)
            for server in servers:
                if server.get('flavor').get('id').split(".")[0] in ["p1"]:
                    print("%s: %s：invalid server is deleted: %s, %s"
                          % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                             self.region, server.get('name'), server.get('flavor').get('id')))
                    #self.delete_server(self.region, server.get('id'))
        
        servers = self.get_servers(self.region, detailed=True)

        # delete unnamed instances
        for server in servers:
            if not self._auth_users(server.get('name')): 
                print("%s: %s：invalid server is deleted: %s, %s"
                      % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         self.region, server.get('name'), server.get('flavor').get('id')))
                # res = self.client.delete_server(self.region, server.get('id'))
                
        
        if datetime.now().hour == 0: 
            # delete P1 instances at night
            _delete_high_cost_servers(servers)
            # shutdown high-cost instances at night
            _shutdown_high_cost_servers(servers)
            

    def network_monitoring(self):
        public_ips = self.get_public_ips(self.region)

        # delete public ips un-bonded to servers
        for public_ip in public_ips:
            if public_ip.get('status') == 'DOWN':
                print("%s: %s：unused float ip is deleted: %s"
                      % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         self.region, public_ip.get('id')))
                self.delete_ip(self.region, public_ip.get('id'))

        # delete public ips charged by bandwidth
        bandwidths = self.get_bandwidths(self.region)
        for bandwidth in bandwidths:
            if bandwidth.get('charge_mode') != 'traffic':
                publicips = bandwidth.get('publicip_info')
                for publicip in publicips:
                    print("%s: %s：non-traffic float ip is deleted: %s"
                          % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                             self.region, publicip.get('publicip_id')))
                    self.delete_ip(self.region, publicip.get('publicip_id'))

    def volumes_monitoring(self, region_name):
        pass

    def cost_monitoring(self, region_name):
        pass

    def run(self):
        self.servers_monitoring()
        self.network_monitoring()


# if __name__ == '__main__':
def monitor_job():
    regions = ['cn-north-1', 'cn-south-1', 'cn-east-2']
    for region in regions:
        monitor = CloudMonitor(region)
        monitor.run()


def job():
    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


if __name__ == '__main__':
    print("%s Start monitoring ..." % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    scheduler = BlockingScheduler()
    scheduler.add_job(monitor_job, 'interval', seconds=180)
    scheduler.start()


