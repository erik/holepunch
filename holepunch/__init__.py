'''Punches holes in your security.

Usage:
  holepunch [options] GROUP (PORTS... | --all)
  holepunch (-h | --help)

Arguments:
  GROUP    Name or group id of security group to modify.
  PORTS    List of ports or port ranges (e.g. 8080-8082) to open.

Options:
  --all              Open ports 0-65535.
  -c --comment=TEXT  Description of security group ingress [default: holepunch].
  --cidr ADDR        Address range (CIDR notation) ingress applies to [defaults to external_ip/32]
  -h --help          Show this screen.
  -t --tcp           Open TCP ports to ingress [default].
  -u --udp           Open UDP ports to ingress.
  -y --yes           Don't prompt before writing rules.
'''

from __future__ import print_function

import atexit
from difflib import SequenceMatcher
import json
import signal
import urllib2

import boto3
from docopt import docopt

from holepunch.version import __version__


ec2 = boto3.client('ec2')


def find_intended_security_group(group_name):
    '''If there's a typo, try to return the intended security group name'''
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

    print('\nDid you mean: %s?' % best_match['GroupName'])


# TODO: There's probably more nuance to this.
def get_local_cidr():
    # AWS VPCs don't support IPv6 (wtf...) so force IPv4
    external_ip = urllib2.urlopen("http://ipv4.icanhazip.com").read().strip()
    return '%s/32' % external_ip


def parse_port_ranges(port_strings):
    ranges = []

    for s in port_strings:
        # TODO: handle int parse ValueErrors
        split = map(int, s.split('-'))

        # TODO: fail more sanely here
        assert len(split) in [1, 2]

        # Single port range
        if len(split) == 1:
            (p1, p2) = (split[0], split[0])
        elif len(split) == 2:
            (p1, p2) = split

        assert p1 <= p2, 'Ports must be correctly ordered'
        assert all(0 <= p <= 65535 for p in [p1, p2]), 'Ports must be in range'
        ranges.append((p1, p2))

    return ranges


def apply_ingress_rules(group, ip_permissions):
    print('Applying rules... ', end='')

    ec2.authorize_security_group_ingress(**{
        'GroupId': group['GroupId'],
        'IpPermissions': ip_permissions
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
    group_name = args['GROUP']

    groups = []

    # Try to lookup based on group name and group id
    for filter_name in ['group-name', 'group-id']:
        matches = ec2.describe_security_groups(Filters=[{
            'Name': filter_name,
            'Values': [group_name]
        }])

        groups.extend(matches['SecurityGroups'])

    if not groups:
        print('Unknown security group: %s' % group_name)
        return find_intended_security_group(group_name)

    elif len(groups) > 1:
        print('More than one group matches "%s", use group id instead' %
              group_name)
        for grp in groups:
            print('- %s %s' % (grp['GroupId'], grp['GroupName']))
        return

    group = groups[0]

    if args['--all']:
        port_ranges = [(0, 65535)]
    else:
        port_ranges = parse_port_ranges(args['PORTS'])

    protocols = set()
    cidr = args['--cidr'] or get_local_cidr()

    # TODO: Should this include ICMP?
    if args['--udp']:
        protocols.add('udp')
    if args['--tcp']:
        protocols.add('tcp')

    # Default to TCP
    if not protocols:
        protocols.add('tcp')

    ip_perms = []
    for proto in protocols:
        for from_port, to_port in port_ranges:
            permission = {
                'IpProtocol': proto,
                'FromPort': from_port,
                'ToPort': to_port,
                'IpRanges': [{
                    'CidrIp': cidr,
                    'Description': args['--comment']
                }]
            }

            # We don't want to (and cannot) duplicate rules
            for perm in group['IpPermissions']:

                # These keys are checked for simple equality, if they're not
                # all the same no need to check IpRanges.
                keys = ['IpProtocol', 'FromPort', 'ToPort']

                if not all(perm.get(k) == permission[k] for k in keys):
                    continue

                # For IpRanges, we need to ignore the Description and check if
                # the CidrIp is the same.
                if any(ip['CidrIp'] == cidr for ip in perm.get('IpRanges', [])):
                    print('Skipping existing permission: %s' % json.dumps(permission))
                    break

            else:
                ip_perms.append(permission)

    if not ip_perms:
        print('No changes to make.')
        return

    print('Changes to be made to: {group_name} [{group_id}]'
          '\n{hr}\n{perms}\n{hr}'.format(
              hr='='*60, group_name=group['GroupName'],
              group_id=group['GroupId'],
              perms=json.dumps(ip_perms, indent=4)))

    if not args['--yes'] and not confirm('Apply security group ingress?'):
        print('Okay, aborting...')
        return

    # Ensure that we revert ingress rules when the program exits
    atexit.register(revert_ingress_rules, group=group, ip_permissions=ip_perms)
    apply_ingress_rules(group, ip_perms)

    print('Ctrl-c to revert')

    # Make sure we have a chance to clean up the security group rules gracefully
    # by ignoring common signals.
    for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
        signal.signal(sig, lambda _1, _2: None)

    # Sleep until we receive a SIGINT
    signal.pause()


def main():
    args = docopt(__doc__, version=__version__)
    holepunch(args)


if __name__ == '__main__':
    main()
