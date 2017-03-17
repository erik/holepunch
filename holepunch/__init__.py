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

import atexit
from difflib import SequenceMatcher
import json

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
            port = int(split[0])
            ranges.append((port, port))
        elif len(split) == 2:
            p1, p2 = map(int, split)
            ranges.append((p1, p2))

    print ranges


def apply_ingress_rules(group, protocols, port_ranges):
    print 'Applying rules!', protocols, port_ranges


def revert_ingress_rules(group, protocols, port_ranges):
    print 'Reverting rules!', protocols, port_ranges


def holepunch(args):
    print args

    group_name = args['SECURITY_GROUP']
    try:
        group = ec2.describe_security_groups(GroupNames=[group_name])
    except botocore.exceptions.ClientError:
        print('Unknown security group: %s' % group_name)
        return find_intended_security_group(group_name)

    port_ranges = parse_port_ranges(args['PORT_RANGE'])

    # Ensure that we revert ingress rules when the program exits
    atexit.register(revert_ingress_rules, group=group, rules={})
    print json.dumps(group)

if __name__ == '__main__':
    args = docopt(__doc__, version='0')
    holepunch(args)
