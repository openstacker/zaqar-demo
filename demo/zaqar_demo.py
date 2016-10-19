# Copyright 2016 Catalyst IT Limited
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import argparse
import json
import os
import prettytable
import re
from random import randint
import six
import sys
import time
import traceback
import yaml
import yaql
import websocket
import uuid

from oslo_utils import encodeutils
from oslo_utils import importutils

from aodh import messaging
import oslo_messaging
from aodhclient import client as aodh_client
from glanceclient import client as glance_client
from novaclient import client as nova_client
from heatclient import client as heat_client
from keystoneauth1.identity import generic
from keystoneauth1 import session
from keystoneclient.v3 import client as keystone_client
from mistralclient.api.v2 import client as mistral_client
from zaqarclient.queues import client as zaqar_client

CLIENT_ID = str(uuid.uuid4())

environment_template = """
event_sinks:
- type: zaqar-queue
  target: %s
  ttl: 3600
"""


def arg(*args, **kwargs):
    def _decorator(func):
        func.__dict__.setdefault('arguments', []).insert(0, (args, kwargs))
        return func
    return _decorator


class ZaqarDemo(object):

    def get_base_parser(self):
            parser = argparse.ArgumentParser(
                prog='zaqar_demo',
                description='Demo script for Zaqar(OpenStack messsaging service).',
                add_help=False,
            )

            parser.add_argument(
                '-k', '--insecure',
                default=False,
                action='store_true',
                help=(
                    'Explicitly allow this client to perform '
                    '"insecure SSL" (https) requests. The server\'s '
                    'certificate will not be verified against any '
                    'certificate authorities. This option should '
                    'be used with caution.'))
        
            parser.add_argument(
                '--os-cert',
                help=(
                    'Path of certificate file to use in SSL '
                    'connection. This file can optionally be '
                    'prepended with the private key.'))
        
            parser.add_argument(
                '--os-key',
                help=(
                    'Path of client key to use in SSL '
                    'connection. This option is not necessary '
                    'if your key is prepended to your cert file.'))
        
            parser.add_argument(
                '--os-cacert',
                metavar='<ca-certificate-file>',
                dest='os_cacert',
                default=os.environ.get('OS_CACERT'),
                help=(
                    'Path of CA TLS certificate(s) used to '
                    'verify the remote server\'s certificate. '
                    'Without this option glance looks for the '
                    'default system CA certificates.'))
        
            parser.add_argument(
                '--os-username',
                default=os.environ.get('OS_USERNAME'),
                help='Defaults to env[OS_USERNAME]')
        
            parser.add_argument(
                '--os-password',
                default=os.environ.get('OS_PASSWORD'),
                help='Defaults to env[OS_PASSWORD]')
        
            parser.add_argument(
                '--os-project-id',
                default=os.environ.get(
                    'OS_PROJECT_ID', os.environ.get(
                        'OS_TENANT_ID')),
                help='Defaults to env[OS_PROJECT_ID]')
        
            parser.add_argument(
                '--os-project-name',
                default=os.environ.get(
                    'OS_PROJECT_NAME', os.environ.get(
                        'OS_TENANT_NAME')),
                help='Defaults to env[OS_PROJECT_NAME]')
        
            parser.add_argument(
                '--os-project-domain-id',
                default=os.environ.get('OS_PROJECT_DOMAIN_ID', 'default'),
                help='Defaults to env[OS_PROJECT_DOMAIN_ID]')
        
            parser.add_argument(
                '--os-project-domain-name',
                default=os.environ.get('OS_PROJECT_DOMAIN_NAME', 'Default'),
                help='Defaults to env[OS_PROJECT_DOMAIN_NAME]')
        
            parser.add_argument(
                '--os-user-domain-id',
                default=os.environ.get('OS_USER_DOMAIN_ID', 'default'),
                help='Defaults to env[OS_USER_DOMAIN_ID]')
        
            parser.add_argument(
                '--os-user-domain-name',
                default=os.environ.get('OS_USER_DOMAIN_NAME', 'Default'),
                help='Defaults to env[OS_USER_DOMAIN_NAME]')
        
            parser.add_argument(
                '--os-auth-url',
                default=os.environ.get('OS_AUTH_URL'),
                help='Defaults to env[OS_AUTH_URL]')
        
            parser.add_argument(
                '--os-region-name',
                default=os.environ.get('OS_REGION_NAME'),
                help='Defaults to env[OS_REGION_NAME]')
        
            parser.add_argument(
                '--os-token',
                default=os.environ.get('OS_TOKEN'),
                help='Defaults to env[OS_TOKEN]')

            # Global arguments
            parser.add_argument('-h', '--help',
                                action='store_true',
                                help=argparse.SUPPRESS,
                                )

            parser.add_argument('-d', '--debug',
                                default=False,
                                action='store_true', dest='DEBUG',
                                help='Print the details of running.')

            return parser

    def get_subcommand_parser(self):
        parser = self.get_base_parser()
        self.subcommands = {}
        subparsers = parser.add_subparsers(metavar='<subcommand>')
        submodule = importutils.import_module('zaqar_demo')
        self._find_actions(subparsers, submodule)
        self._find_actions(subparsers, self)
        return parser

    def _find_actions(self, subparsers, actions_module):
        for attr in (a for a in dir(actions_module) if a.startswith('do_')):
            command = attr[3:].replace('_', '-')
            callback = getattr(actions_module, attr)
            desc = callback.__doc__ or ''
            help = desc.strip().split('\n')[0]
            arguments = getattr(callback, 'arguments', [])

            subparser = subparsers.add_parser(command,
                                              help=help,
                                              description=desc,
                                              add_help=False,
                                              formatter_class=HelpFormatter
                                              )
            subparser.add_argument('-h', '--help',
                                   action='help',
                                   help=argparse.SUPPRESS,
                                   )
            self.subcommands[command] = subparser
            for (args, kwargs) in arguments:
                subparser.add_argument(*args, **kwargs)
            subparser.set_defaults(func=callback)

    @arg('command', metavar='<subcommand>', nargs='?',
         help='Display help for <subcommand>.')
    def do_help(self, args):
        """Display help about this program or one of its subcommands.

        """
        if getattr(args, 'command', None):
            if args.command in self.subcommands:
                self.subcommands[args.command].print_help()
            else:
                raise Exception("'%s' is not a valid subcommand" %
                                args.command)
        else:
            self.parser.print_help()

    def authenticate_zaqar_ws(sefl, ws, token, project):
        ws.send(json.dumps({'action': 'authenticate',
                            'headers': {'X-Auth-Token': token,
                                        'Client-ID': CLIENT_ID,
                                        'X-Project-ID': project}}))
        data = json.loads(ws.recv())
        if not data['headers']['status'] == 200:
            raise RuntimeError(data)

    def authenticate(self, args):
        if args.insecure:
            verify = False
        else:
            verify = args.os_cacert or True
        if args.os_cert and args.os_key:
            cert = (args.os_cert, args.os_key)
        else:
            cert = None
    
        if args.os_token:
            kwargs = {
                'token': args.os_token,
                'auth_url': args.os_auth_url,
                'username': args.os_username,
                'project_id': args.os_project_id,
                'project_name': args.os_project_name,
                'project_domain_id': args.os_project_domain_id,
                'project_domain_name': args.os_project_domain_name,
            }
            auth = generic.Token(**kwargs)
            ks_session = session.Session(auth=auth, verify=verify, cert=cert)
        else:
            kwargs = {
                'username': args.os_username,
                'password': args.os_password,
                'auth_url': args.os_auth_url,
                'project_id': args.os_project_id,
                'project_name': args.os_project_name,
                'project_domain_id': args.os_project_domain_id,
                'project_domain_name': args.os_project_domain_name,
                'user_domain_id': args.os_user_domain_id,
                'user_domain_name': args.os_user_domain_name,
            }
            auth = generic.Password(**kwargs)
            ks_session = session.Session(auth=auth, verify=verify, cert=cert)
        self.session = ks_session

    def init_client(self, args):
        try:
            self.authenticate(args)

            self.keystone = keystone_client.Client(versioin='3',
                                                   session=self.session)

            self.zaqar = zaqar_client.Client(version=2, session=self.session)

            ws_url = self.session.auth.get_endpoint(self.session,
                service_type='messaging-websocket')
            self.zaqar_ws = websocket.create_connection(ws_url.replace('http',
                                                                       'ws'))
            self.authenticate_zaqar_ws(self.zaqar_ws, self.session.get_token(),
                                       self.session.get_project_id())

            self.aodh = aodh_client.Client("2", session=self.session)

            # Create Mistral client
            mistral_srv = self.keystone.services.find(type='workflowv2')
            mistral_endpoint = self.keystone.endpoints.find(
                service_id=mistral_srv.id, interface='public')
            self.mistral_url = mistral_endpoint.url

            self.mistral = mistral_client.Client(
                mistral_url=mistral_endpoint.url,
                auth_token=self.session.get_token())

            # Create Heat client
            heat_srv = self.keystone.services.find(type='orchestration')
            heat_endpoint = self.keystone.endpoints.find(service_id=heat_srv.id,
                                                         interface='public')
            heat_url = heat_endpoint.url.replace('$(project_id)s',
                                                 self.session.get_project_id())
            self.heat = heat_client.Client('1', endpoint=heat_url,
                                           token=self.session.get_token())

            self.glance = glance_client.Client('1', session=self.session)
            self.nova = nova_client.Client('2', sesson=session)
            self.debug = args.DEBUG
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_exception(exc_type, exc_value, exc_traceback,
                                      limit=2, file=sys.stdout)
            sys.exit(1)

    def main(self, argv):
        parser = self.get_base_parser()
        (options, args) = parser.parse_known_args(argv)

        subcommand_parser = self.get_subcommand_parser()
        self.parser = subcommand_parser

        if options.help or not argv:
            self.do_help(options)
            return 0

        args = subcommand_parser.parse_args(argv)
        if args.func == self.do_help:
            self.do_help(args)
            return 0

        try:
            self.init_client(args)
            args.func(self, args)
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_exception(exc_type, exc_value, exc_traceback,
                                      file=sys.stdout)
            sys.exit(1)


class HelpFormatter(argparse.HelpFormatter):
    def start_section(self, heading):
        # Title-case the headings
        heading = '%s%s' % (heading[0].upper(), heading[1:])
        super(HelpFormatter, self).start_section(heading)


def send_message(ws, project, action, body=None):
    msg = {'action': action,
           'headers': {'Client-ID': CLIENT_ID, 'X-Project-ID': project}}
    if body:
        msg['body'] = body
    ws.send(json.dumps(msg))
    data = json.loads(ws.recv())
    if data['headers']['status'] not in (200, 201):
        raise RuntimeError(data)


@arg('--queue-name', type=str, default='auto_healing',
     help='Queue name.')
@arg('--stack-name', type=str, default='auto_healing',
     help='Stack name.')
def do_demo(shell, args):
    init_env(shell)

    # 0. Create stack with Heat
    print("Start to create stack in Heat...")
    stack_yaml = open('./auto_healing_heat.yaml', 'r')
    stack_stack_queue_name = "stack_status_queue"
    send_message(shell.zaqar_ws, shell.session.get_project_id(),
                 'queue_create',
                 {'queue_name': stack_stack_queue_name})
    send_message(shell.zaqar_ws, shell.session.get_project_id(),
                 'subscription_create',
                 {'queue_name': stack_stack_queue_name, 'ttl': 3600})
    environment = environment_template % stack_stack_queue_name
    stack_resp = shell.heat.stacks.create(stack_name=args.stack_name,
                                          template=stack_yaml.read(),
                                          parameters={},
                                          environment=environment)
    root_stack_id = stack_resp['stack']['id']

    while True:
        data = json.loads(shell.zaqar_ws.recv())['body']['payload']
        if data['resource_type'] == 'OS::Heat::Stack':
            if data['resource_status'] != 'IN_PROGRESS':
                print data['resource_status_reason']
                break
    shell.zaqar_ws.close()

    server_id_map = {}
    server_name_map = {}
    stack = shell.heat.stacks.get(root_stack_id)
    print_dict(stack.to_dict())
    for output in stack.outputs:
        if output['output_key'] == 'server_id_map':
            server_id_map = output['output_value']
        if output['output_key'] == 'server_name_map':
            server_name_map = output['output_value']
    autoscaling_resource = shell.heat.resources.list(root_stack_id)[0]
    print_dict(autoscaling_resource.to_dict())
    stack_id = autoscaling_resource.physical_resource_id    
    prompt_yes_no('Stack created successfully. Ready to go to next?')

    print('Start to create workflow in Mistral...')
    # 0. Inject stack info into workflow template
    wf = yaml.load(open('./auto_healing_mistral.yaml'))
    for param in wf['auto_healing']['input']:
        if isinstance(param, dict):
            if "server_id_map" in param:
                param['server_id_map'] = dict([(str(k), str(v)) for k, v
											  in server_id_map.items()])
            if "server_name_map" in param:
                param['server_name_map'] = dict([(str(k), str(v)) for k, v
												in server_name_map.items()])
            if "stack_id" in param:
                param['stack_id'] = str(stack_id)
            if "root_stack_id" in param:
                param['root_stack_id'] = str(root_stack_id)

    yaml.dump(wf, open('./auto_healing_mistral.yaml', 'w+'))
    
    workflow_yaml = open('./auto_healing_mistral.yaml')
    workflow = shell.mistral.workflows.create(workflow_yaml)
    print_dict(workflow[0].to_dict())
    prompt_yes_no('Workflow created successfully. Ready to go to next?')

    # 1. Create a queue in Zaqar and get signed info
    print("Start to create queue in Zaqar")
    my_queue = shell.zaqar.queue(args.queue_name)
    paths = ["messages", "subscriptions"]
    methods = ['GET', 'PATCH', 'POST', 'PUT']
    presigned = my_queue.signed_url(paths=paths, methods=methods)
    print_dict(presigned)
    prompt_yes_no('Queue created successfully. Ready to go to next?')

    print('Start to create subscriptions on queue...')
    # 2. Create Mistral subscription
    subscriber = 'trust+' + shell.mistral_url + '/executions'
    post_data = ('{"input": "$zaqar_message$", "workflow_id": "%s"}' %
                 workflow[0].id)
    sub_mistral = shell.zaqar.subscription(args.queue_name,
                                           subscriber=subscriber,
                                           ttl=102400,
                                           options={'post_data': post_data})
    print_dict({'subscriber': sub_mistral.subscriber,
                'options': sub_mistral.options})

	# 3. Create email subscription
    sub_email = shell.zaqar.subscription(args.queue_name,
                                         subscriber='mailto:flwang@catalyst.net.nz',
                                         ttl=102400,
                                         options={'subject':
                                                  'Alarm from stack: %s' %
                                                  root_stack_id})
    print_dict({'subscriber': sub_email.subscriber,
                'options': sub_email.options})
    prompt_yes_no('Subscriptions created successfully. Ready to go to next?')

    # 4. Create alarm in Aodh based on above signed queue and instance info
    print("Start to create alarm in Aodh...")
    instance_id = '359e0916-0811-41f2-833f-bdbbb7f6694e'
    actions = ['zaqar://?signature={0}&expires={1}&paths={2}'
               '&methods={3}&project_id={4}&queue_name={5}' \
               .format(presigned['signature'],
                       presigned['expires'],
                       ','.join(presigned['paths']),
                       ','.join(presigned['methods']),
                       presigned['project'],
                       args.queue_name)]

    for instance_id in server_id_map.values():
        alarm_info = {'alarm_actions': actions,
                      'name': 'auto_healing',
                      'type': 'event',
                      'severity': 'critical',
                      "event_rule": {
                            "event_type": "compute.instance.update",
                            "query" : [
                                            {
                                                "field" : "traits.instance_id",
                                                "type" : "string",
                                                "value" : instance_id,
                                                "op" : "eq",
                                            },
                                            {
                                                "field" : "traits.state",
                                                "type" : "string",
                                                "value" : "stopped",
                                                "op" : "eq",
                                            },
                                        ]
                            }
                      }
        alarm = shell.aodh.alarm.create(alarm_info)
        print_dict(alarm)
    print("Alarms created successfully.")    

    # 5. Trigger event to Ceilometer so as to trigger alarm
    #msg_body = {'severity': 'low', 'alarm_name': 'auto_healing', 'current': 'alarm', 'alarm_id': '9b1e5f05-bfa3-4151-a9a9-d18f18ca21a1', 'reason': 'Event <id=809c61c7-0bd9-4082-a88a-5b242ad842fc,event_type=compute.instance.update> hits the query <query=[{"field": "traits.instance_id", "op": "eq", "type": "string", "value": "359e0916-0811-41f2-833f-bdbbb7f6694e"}, {"field": "traits.state", "op": "eq", "type": "string", "value": "stopped"}]>.', 'reason_data': {'type': 'event', 'event': {'event_type': 'compute.instance.update', 'traits': [['state', 1, 'stopped'], ['user_id', 1, '8540af4e98c246e7adb1d2e70c21807d'], ['service', 1, 'compute'], ['disk_gb', 2, 0], ['instance_type', 1, 'cirros256'], ['tenant_id', 1, '870f7fd75a1c4dc49a8091ca99626b88'], ['root_gb', 2, 0], ['ephemeral_gb', 2, 0], ['instance_type_id', 2, 1], ['vcpus', 2, 1], ['memory_mb', 2, 256], ['instance_id', 1, server_id_map.values()[0]], ['host', 1, 'feilong-ThinkPad-X1-Carbon-2nd'], ['request_id', 1, 'req-5a312569-60e0-4282-bf95-2e00ebdf532b'], ['project_id', 1, '870f7fd75a1c4dc49a8091ca99626b88'], ['launched_at', 4, '2016-10-12T21:55:59']], 'message_signature': 'ecedefc4507a03cf5e0e479815e4eee9c4c3c28aacb164ad00d04f242172b65e', 'raw': {}, 'generated': '2016-10-13T04:16:31.672126', 'message_id': '809c61c7-0bd9-4082-a88a-5b242ad842fc'}}, 'previous': 'insufficient data'}
    #my_queue.post([{'body': msg_body}])
    

    # 6. Verify if the alarm has been forwarded by Zaqar to Mistral, see if
    # there is a new execution
    #print_list(my_queue.messages(), ['queue_name', 'body', 'ttl'])

    # NOTE(flwang): Mistral doesn't support filter executions by workflow id
    #executions = shell.mistral.executions.list()
    #for exc in executions:
    #    if exc.workflow_id == workflow[0].id:
    #        print_dict(exc.to_dict())

    # 7. Verify if Heat has mark the resource as unhealthy
    
    # 8. Verify if the stack has been updated


def init_env(shell):
    print("""
                           _ooOoo_
                          o8888888o
                          88" . "88
                          (| -_- |)
                          O\  =  /O
                       ____/`---'\____
                     .'  \\|     |//  `.
                    /  \\|||  :  |||//  \                  
                   /  _||||| -:- |||||- \                       
                   |   | \\\  -  ///  |   |
                   | \_|  ''\---/''  |   |
                   \  .-\__  `-`  ___/-. /
                 ___`. .'  /--.--\  `. . __
              ."" '<  `.___\_<|>_/___.'  >'"".
             | | :  `- \`.;`\ _ /`;.`/ - ` : | |
             \  \ `-.   \_ __\ /__ _/   .-` /  /
        ======`-.____`-.___\_____/___.-`____.-'======
                           `=---='
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                 Buddha Bless       No Bug
    """)
    print("\n\n\nStart to initialize environment...")
    stacks = shell.heat.stacks.list()
    for stack in stacks:
        shell.heat.stacks.delete(stack.id)

    alarms = shell.aodh.alarm.list()
    for alarm in alarms:
        shell.aodh.alarm.delete(alarm['alarm_id'])

    workflows = shell.mistral.workflows.list()
    for workflow in workflows:
        try:
            shell.mistral.workflows.delete(workflow.id)
        except:
            pass

    queues = shell.zaqar.queues()
    for queue in queues:
        queue.delete()

    stacks = list(shell.heat.stacks.list())
    while stacks:
        data = json.loads(shell.zaqar_ws.recv())['body']['payload']
        if data['resource_type'] == 'OS::Heat::Stack':
            if data['resource_status'] != 'DELETE_IN_PROGRESS':
                print data['resource_status_reason']
                break
        stacks = list(shell.heat.stacks.list())
    if prompt_yes_no('Environment is clean now. Ready to go?') == False:
        return


def fake_error_event():
    from aodh import service
    conf = service.prepare_service(argv=[], config_files=[])
    transport = messaging.get_transport(conf, 'fake://', cache=False)
    msg_notifier = oslo_messaging.Notifier(
            transport, topics=['alarm.all'], driver='messaging',
            publisher_id='test-publisher')
    event1 = {'event_type': 'compute.instance.update',
              'traits': ['foo', 'bar'],
              'message_id': '20d03d17-4aba-4900-a179-dba1281a3451',
              'generated': '2016-04-23T06:50:21.622739'}

    msg_notifier.sample({}, 'event', event1)


def call_until_true(func, duration, sleep_for):
    now = time.time()
    timeout = now + duration
    while now < timeout:
        if func():
            return True
        time.sleep(sleep_for)
        now = time.time()
    return False


def print_dict(d, max_column_width=80):
    pt = prettytable.PrettyTable(['Property', 'Value'], caching=False)
    pt.align = 'l'
    pt.max_width = max_column_width
    [pt.add_row(list(r)) for r in six.iteritems(d)]
    print(encodeutils.safe_encode(pt.get_string(sortby='Property')))


def print_list(objs, fields, formatters={}):
    pt = prettytable.PrettyTable([f for f in fields], caching=False)
    pt.align = 'l'

    for o in objs:
        row = []
        for field in fields:
            if field in formatters:
                row.append(formatters[field](o))
            else:
                field_name = field.lower().replace(' ', '_')
                if type(o) == dict and field in o:
                    data = o[field_name]
                else:
                    data = getattr(o, field_name, None) or ''
                row.append(data)
        pt.add_row(row)

    print(encodeutils.safe_encode(pt.get_string()))


def prompt_yes_no(question, default="no"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def main():
    try:
        ZaqarDemo().main(sys.argv[1:])
    except KeyboardInterrupt:
        print("Terminating...")
        sys.exit(1)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_exception(exc_type, exc_value, exc_traceback,
                                  limit=2, file=sys.stdout)


if __name__ == '__main__':
    main()