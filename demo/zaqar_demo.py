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
import os
import prettytable
import re
import six
import sys
import traceback

from oslo_utils import encodeutils
from oslo_utils import importutils

from aodhclient import client as aodh_client
from heatclient import client as heat_client
from keystoneauth1.identity import generic
from keystoneauth1 import session
from keystoneclient.v3 import client as keystone_client
from mistralclient.api.v2 import client as mistral_client
from zaqarclient.queues import client as zaqar_client


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
            self.aodh = aodh_client.Client("2", session=self.session)

            # Create Mistral client
            mistral_srv = self.keystone.services.find(type='workflowv2')
            mistral_endpoint = self.keystone.endpoints.find(service_id=mistral_srv.id,
                                                           interface='public')
            self.mistral_url = mistral_endpoint.url

            self.mistral = mistral_client.Client(mistral_url=mistral_endpoint.url,
                                                 auth_token=self.session.get_token())

            # Create Heat client
            heat_srv = self.keystone.services.find(type='orchestration')
            heat_endpoint = self.keystone.endpoints.find(service_id=heat_srv.id,
                                                           interface='public')
            heat_url = heat_endpoint.url.replace('$(project_id)s',
                                                 self.session.get_project_id())
            self.heat = heat_client.Client('1', endpoint=heat_url,
                                           token=self.session.get_token())

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


@arg('--queue-name', type=str, nargs='*', default='beijing',
     help='Queue name.')
def do_demo(shell, args):
    # 0. Create stack with Heat include 2 instances

    # 0. Create Mistral workflow
    try:
        shell.mistral.workflows.delete('auto_healing')
    except:
        pass
    workflow_yaml = open('./auto_healing.yaml')
    workflow = shell.mistral.workflows.create(workflow_yaml)
    print_dict(workflow[0].to_dict())

    # 1. Create a queue in Zaqar and get signed info
    my_queue = shell.zaqar.queue(args.queue_name)
    paths = ["messages", "subscriptions"]
    methods = ['GET', 'PATCH', 'POST', 'PUT']
    presigned = my_queue.signed_url(paths=paths, methods=methods)
    print_dict(presigned)

    # 2. Create Mistral subscription
    subscriber = 'trust+' + shell.mistral_url + '/executions'
    post_data = ('{"input": "$zaqar_message$", "workflow_id": "%s"}' %
                 workflow[0].id)
    sub = shell.zaqar.subscription(args.queue_name,
                                   subscriber=subscriber,
                                   ttl=3600,
                                   options={'post_data': post_data})
    print_dict({'subscriber': sub.subscriber, 'options': sub.options})

    
    #my_queue.post([{'body': {'pre_check': 'fake_instance_id'}}])

    # 3. Create email subscription

    # 4. Create alarm in Aodh based on above signed queue info
    instance_id = '68549451-986a-4b42-85f7-3fbdb22b367a'
    actions = ['zaqar://?signature={0}&expires={1}&paths={2}'
               '&methods={3}&project_id={4}&queue_name={5}' \
               .format(presigned.signature,
                       presigned.expires,
                       presigned.paths,
                       presigned.methods,
                       presigned.project_id,
                       args.queue_name)]
    alarm_info = {'alarm_actions': actions,
                  'name': 'auto_healing',
                  'type': 'event',
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
                                            "value" : "error",
                                            "op" : "eq",
                                        },
                                    ]
                        }
                  }
    alarm = shell.aodh.alarm.create(alarm_info)
    print_dict(alarm)

    # 5. Post fake data into Ceilometer to trigger alarm


    # 6. Verify if the alarm has been forwarded by Zaqar to Mistral, see if
    # there is a new execution
    messages = myqueue.messages()
    print_list(messages, ['body'])

    executions = shell.mistral.executions.list()
    print_list(executions, ['id', 'workflow_id', 'workflow_name', 'state'])
    # 7. Verify if Heat has mark the resource as unhealthy

    # 8. Verify if the stack has been updated


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