'''Punches holes in your security.

Usage:
  holepunch [options] GROUP (PORTS... | --all)
  holepunch (-h | --help)

Arguments:
  GROUP    Name or group id of security group to modify.
  PORTS    List of ports or port ranges (e.g. 8080-8082) to open.

Options:
  --all                 Open ports 0-65535.
  -c --comment=TEXT     Description of security group ingress [default: holepunch].
  --cidr ADDR           Address range (CIDR notation) ingress applies to [defaults to external_ip/32]
  -h --help             Show this screen.
  -p --profile=NAME     Use a specific AWS profile, equivalent to setting `AWS_PROFILE=NAME`
  -r --remove-existing  Remove ingress rules at exit even if they weren't created by holepunch.
  -t --tcp              Open TCP ports to ingress [default].
  -u --udp              Open UDP ports to ingress.
  -y --yes              Don't prompt before writing rules.
'''

from __future__ import print_function

import atexit
from difflib import SequenceMatcher
import json
import signal
import sys

try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen

import boto3
from docopt import docopt

from holepunch.version import __version__


# Hack for Python2
try:
    input = raw_input
except NameError:
    pass


def find_intended_security_group(security_groups, group_name):
    '''If there's a typo, try to return the intended security group name'''
    if not len(security_groups):
        return

    scores = [
        SequenceMatcher(None, group_name, grp['GroupName']).ratio()
        for grp in security_groups
    ]

    # Find the closest match
    distances = sorted(zip(scores, security_groups), key=lambda tpl: tpl[0])
    score, best_match = distances[-1]

    if score > 0.35:
        return best_match['GroupName']


# TODO: There's probably more nuance to this.
def get_local_cidr():
    # AWS VPCs don't support IPv6 (wtf...) so force IPv4
    external_ip = urlopen("http://ipv4.icanhazip.com").read().decode('utf-8').strip()
    return '%s/32' % external_ip


def parse_port_ranges(port_strings):
    ''' ['80-8082', '443', '22-29'] -> [(80, 8082), (443, 443), (22, 29)] '''
    ranges = []

    for s in port_strings:
        split = list(map(int, s.split('-')))

        if len(split) not in [1, 2]:
            raise ValueError('Expected port or port range (e.g `80`, `8080-8082`)')

        # Single port, convert to range, e.g. 80 -> 80-80
        if len(split) == 1:
            (p1, p2) = (split[0], split[0])

        elif len(split) == 2:
            (p1, p2) = split

        if p1 > p2:
            raise ValueError('Port range must be ordered from low to high')

        if not all(0 <= p <= 65535 for p in [p1, p2]):
            raise ValueError('Ports must be in range 0-65535')

        ranges.append((p1, p2))

    return ranges


def apply_ingress_rules(ec2_client, group, ip_permissions):
    print('Applying rules... ', end='')

    ec2_client.authorize_security_group_ingress(**{
        'GroupId': group['GroupId'],
        'IpPermissions': ip_permissions
    })

    print('Done')


def revert_ingress_rules(boto_args, group, ip_permissions):
    print('Reverting rules... ', end='')

    # Create a new boto session instead of reusing existing one, which
    # may have expired while we were asleep.
    boto_session = boto3.session.Session(**boto_args)
    ec2_client = boto_session.client('ec2')

    ec2_client.revoke_security_group_ingress(**{
        'GroupId': group['GroupId'],
        'IpPermissions': ip_permissions,
    })

    print('Done')


def confirm(message):
    resp = input('%s [y/N] ' % message)
    return resp.lower() in ['yes', 'y']


def find_matching_security_groups(ec2_client, name):
    groups = []

    # Try to lookup based on group name and group id
    for filter_name in ['group-name', 'group-id']:
        matches = ec2_client.describe_security_groups(Filters=[{
            'Name': filter_name,
            'Values': [name]
        }])

        groups.extend(matches['SecurityGroups'])

    return groups


def build_ingress_permissions(security_group, cidr, port_ranges, protocols, description):
    new_perms, existing_perms = [], []

    for proto in protocols:
        for from_port, to_port in port_ranges:
            permission = {
                'IpProtocol': proto,
                'FromPort': from_port,
                'ToPort': to_port,
                'IpRanges': [{'CidrIp': cidr, 'Description': description}]
            }

            # We don't want to (and cannot) duplicate rules
            for perm in security_group['IpPermissions']:

                # These keys are checked for simple equality, if they're not
                # all the same no need to check IpRanges.
                keys = ['IpProtocol', 'FromPort', 'ToPort']

                if not all(perm.get(k) == permission[k] for k in keys):
                    continue

                # For IpRanges, we need to ignore the Description and check if
                # the CidrIp is the same.
                if any(ip['CidrIp'] == cidr for ip in perm.get('IpRanges', [])):
                    existing_perms.append(permission)
                    print('Not adding existing permission: %s' % json.dumps(permission))
                    break

            else:
                new_perms.append(permission)

    return new_perms, existing_perms


def holepunch(args):
    group_name = args['GROUP']

    if args['--all']:
        port_ranges = [(0, 65535)]
    else:
        try:
            port_ranges = parse_port_ranges(args['PORTS'])
        except ValueError as exc:
            print('invalid port range: %s' % exc)
            return False

    profile_name = args['--profile']

    boto_session = boto3.session.Session(profile_name=profile_name)
    ec2_client = boto_session.client('ec2')

    groups = find_matching_security_groups(ec2_client, group_name)

    if not groups:
        print('Unknown security group: %s' % group_name)
        all_groups = ec2_client.describe_security_groups()['SecurityGroups']
        intended = find_intended_security_group(all_groups, group_name)

        if intended:
            print('\nDid you mean: "%s"?' % intended)

        return False

    elif len(groups) > 1:
        print('More than one group matches "%s", use group id instead' %
              group_name)

        for grp in groups:
            print('- %s %s' % (grp['GroupId'], grp['GroupName']))

        return False

    group = groups[0]

    protocols = set()
    cidr = args['--cidr'] or get_local_cidr()

    if args['--udp']:
        protocols.add('udp')
    if args['--tcp']:
        protocols.add('tcp')

    # Default to TCP
    if not protocols:
        protocols.add('tcp')

    new_perms, existing_perms = build_ingress_permissions(
        group, cidr, port_ranges, protocols, args['--comment'])

    to_remove = new_perms.copy()
    if args['--remove-existing']:
        to_remove.extend(existing_perms)

    if not new_perms and not to_remove:
        print('No changes to make.')
        return True

    print('Changes to be made to: {group_name} [{group_id}]'
          '\n{hr}\n{perms}\n{hr}'.format(
              hr='='*60, group_name=group['GroupName'],
              group_id=group['GroupId'],
              perms=json.dumps(new_perms, indent=4)))

    if not args['--yes'] and not confirm('Apply security group ingress?'):
        print('Okay, aborting...')
        return True

    # Ensure that we revert ingress rules when the program exits
    atexit.register(revert_ingress_rules,
                    boto_args={'profile_name': profile_name},
                    group=group,
                    ip_permissions=to_remove)

    if new_perms:
        apply_ingress_rules(ec2_client, group, new_perms)

    print('Ctrl-c to revert')

    # Make sure we have a chance to clean up the security group rules gracefully
    # by ignoring common signals.
    for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
        signal.signal(sig, lambda _1, _2: None)

    # Sleep until we receive a SIGINT
    signal.pause()

    return True


def main():
    args = docopt(__doc__, version=__version__)
    success = holepunch(args)

    if not success:
        sys.exit(1)


if __name__ == '__main__':
    main()
