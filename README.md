# holepunch
Punch holes in your AWS account security.

`holepunch` is meant for times when you need to temporarily open ingress to an
AWS security group, perhaps for development or testing remotely without a VPN
set up.

This is really bad practice, but `holepunch` will make sure that security group
rules will be reverted when you are done.

After running `holepunch`, just hit `Ctrl-c` to clear out the modified rules.

You can also run `holepunch` only for the duration of a shell command with
`--command`.

By default, `holepunch` will refuse to remove rules that existed before it
was run. This can be toggled with the `--remove-existing` flag.

## Installation

```
pip install holepunch
```

AWS credentials can be set up in any of the places that [Boto3 knows to look.](http://boto3.readthedocs.io/en/latest/guide/configuration.html)

## Examples

To modify security group `foo_bar` to permit inbound traffic from this
machine to TCP port 22 (ssh):

```
holepunch foo_bar 22 --tcp
```

Modifying a security group using its id also works:

```
holepunch sg-62153838 443 --tcp
```

Apply security group rules and then `ssh` into a host. Rules will be
reverted when SSH connection ends.

```
holepunch foo_bar 22 --command "ssh bastion"
```

Adding multiple TCP port ranges:

```
holepunch foo_bar 22 80 8080-8081 --tcp
```

Explicitly setting the IP range the rules apply to:

```
holepunch foo_bar --cidr=192.168.0.0/16 22 80
```
