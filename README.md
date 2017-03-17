# holepunch
Punch holes in your AWS account security.

`holepunch` is meant for times when you need to temporarily open ingress to an
AWS security group, perhaps for development or testing remotely without a VPN
set up.

This is really bad practice, but `holepunch` will make sure that security group
rules will be reverted when you are done.

After running `holepunch`, just hit `Ctrl-c` to clear out the modified rules.

## Installation

```
pip install holepunch
```

AWS credentials can be set up in any of the places that [Boto3 knows to look.](http://boto3.readthedocs.io/en/latest/guide/configuration.html)

## Examples

To modify security group `foo_bar` to inbound traffic from this machine's local
IP to TCP port 22 (ssh):

```
holepunch foo_bar 22 --tcp
```

Adding multiple TCP port ranges:

```
holepunch foo_bar 22 80 8080-8081 --tcp
```
