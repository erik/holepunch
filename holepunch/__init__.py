'''Punches holes in your security.

Usage:
  holepunch  [--tcp | --udp] [--cidr=<custom_cidr>] SECURITY_GROUP (PORT_RANGE... | --all)
  holepunch (-h | --help)

Options:
  -h --help              Show this screen.
  --cidr=<custom_cidr>   CIDR expression to apply rules to [defaults to this
                         machine's ip/32]
  --all                  Open ports 0-65535.
  -t --tcp               Open TCP ports to ingress.
  -u --udp               Open UDP ports to ingress.
'''

from __future__ import print_function

import atexit
from difflib import SequenceMatcher
import json
import signal

import boto3
import botocore
from docopt import docopt
import ipgetter


ec2 = boto3.client('ec2')


def find_intended_security_group(group_name):
    grps = ec2.describe_security_groups()['SecurityGroups']

    if not len(grps):
        return

    distances = sorted([
        (SequenceMatcher(None, group_name, grp['GroupName']).ratio(), grp)
        for grp in grps
    ])

    score, best_match = distances[-1]

    # TODO: Tune this.
    if score < 0.35:
        return

    print('\nDid you mean: %s [%f]?' % (best_match['GroupName'], score))


# TODO: There's probably more nuance to this.
def get_local_cidr():
    return '%s/32' % ipgetter.myip()


def parse_port_ranges(port_strings):
    ranges = []

    for s in port_strings:
        # TODO: handle int parse ValueErrors
        split = map(int, s.split('-'))

        # TODO: fail more sanely here
        assert len(split) in [1, 2]

        # Single port range
        if len(split) == 1:
            p1, p2 = int(split[0]), int(split[0])
        elif len(split) == 2:
            p1, p2 = map(int, split)

        assert p1 <= p2, 'Ports must be correctly ordered'
        assert all(0 <= p <= 65535 for p in [p1, p2]), 'Ports must be in range'
        ranges.append((p1, p2))

    return ranges


# TODO: Need to handle case when one or more of the rules already exists
def apply_ingress_rules(group, ip_permissions):
    print('Applying rules... ', end='')

    ec2.authorize_security_group_ingress(**{
        'GroupId': group['GroupId'],
        'IpPermissions': ip_permissions,
    })

    print('Done')


def revert_ingress_rules(group, ip_permissions):
    print('Reverting rules... ', end='')

    ec2.revoke_security_group_ingress(**{
        'GroupId': group['GroupId'],
        'IpPermissions': ip_permissions,
    })

    print('Done')


def confirm(message):
    resp = raw_input('%s [y/N] ' % message)
    return resp.lower() in ['yes', 'y']


def holepunch(args):
    group_name = args['SECURITY_GROUP']
    try:
        groups = ec2.describe_security_groups(GroupNames=[group_name])
        assert len(groups['SecurityGroups']) == 1, 'TODO: handle this ambiguity'
        group = groups['SecurityGroups'][0]
    except botocore.exceptions.ClientError:
        print('Unknown security group: %s' % group_name)
        return find_intended_security_group(group_name)

    if args['--all']:
        port_ranges = [(0, 65535)]
    else:
        port_ranges = parse_port_ranges(args['PORT_RANGE'])

    protocols = set()
    cidr = get_local_cidr()

    # TODO: Should this include ICMP?
    if args['--udp']:
        protocols.add('udp')
    if args['--tcp']:
        protocols.add('tcp')
    # Default to TCP
    if not (args['--udp'] or args['--tcp']):
        protocols.add('tcp')

    ip_perms = []
    for proto in protocols:
        for from_port, to_port in port_ranges:
            ip_perms.append({
                'IpProtocol': proto,
                'FromPort': from_port,
                'ToPort': to_port,
                'IpRanges': [{'CidrIp': cidr}]
            })

    print('Changes to be made to:'
          '  - {group_id} - {group_name}'
          '\n{hr}\n{perms}\n{hr}'.format(
              hr='='*60, group_name=group['GroupName'],
              group_id=group['GroupId'],
              perms=json.dumps(ip_perms, indent=4)))

    if not confirm('Apply security group ingress?'):
        print('Okay, aborting...')
        return

    # Ensure that we revert ingress rules when the program exits
    atexit.register(revert_ingress_rules, group=group, ip_permissions=ip_perms)
    apply_ingress_rules(group, ip_perms)

    print('Ctrl-c to revert')

    # Just eat the signal
    signal.signal(signal.SIGINT, lambda _1, _2: None)
    # Wait until we receive a SIGINT
    signal.pause()


def main():
    args = docopt(__doc__, version='0.0.0')
    holepunch(args)


if __name__ == '__main__':
    main()
