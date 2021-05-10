---
layout: "vultr"
page_title: "Vultr: vultr_instance"
sidebar_current: "docs-vultr-resource-instance"
description: |-
  Provides a Vultr instance resource. This can be used to create, read, modify, and delete instances on your Vultr account.
---

# vultr_instance

Provides a Vultr instance resource. This can be used to create, read, modify, and delete instances on your Vultr account.

## Example Usage

Create a new instance:

```hcl
resource "vultr_instance" "my_instance" {
	plan = "vc2-1c-1gb"
	region = "sea"
	os_id = "167"
}
```

Create a new instance with options:

```hcl
resource "vultr_instance" "my_instance" {
	plan = "vc2-1c-1gb"
	region = "sea"
	os_id = "167"
	label = "my-instance-label"
	tag = "my-instance-tag"
	hostname = "my-instance-hostname"
	enable_ipv6 = true
	backups = "enabled"
	ddos_protection = true
	activation_email = false
}
```

## Argument Reference

The following arguments are supported:

* `region` - (Required) The ID of the region that the instance is to be created in.
* `plan` - (Required) The ID of the plan that you want the instance to subscribe to.
* `os_id` - (Optional) The ID of the operating system to be installed on the server.
* `iso_id` - (Optional) The ID of the ISO file to be installed on the server.
* `app_id` - (Optional) The ID of the Vultr application to be installed on the server.
* `snapshot_id` - (Optional) The ID of the Vultr snapshot that the server will restore for the initial installation. 
* `script_id` - (Optional) The ID of the startup script you want added to the server.
* `firewall_group_id` - (Optional) The ID of the firewall group to assign to the server.
* `private_network_ids` - (Optional) A list of private network IDs to be attached to the server.
* `ssh_key_ids` - (Optional) A list of SSH key IDs to apply to the server on install (only valid for Linux/FreeBSD).
* `user_data` - (Optional) Generic data store, which some provisioning tools and cloud operating systems use as a configuration file. It is generally consumed only once after an instance has been launched, but individual needs may vary.
* `backups` - (Optional) Whether automatic backups will be enabled for this server (these have an extra charge associated with them). Values can be enabled or disabled.
* `enable_ipv6` - (Optional) Whether the server has IPv6 networking activated.
* `enable_private_network` - (Optional) Whether the server has private networking support enabled.
* `activation_email` - (Optional) Whether an activation email will be sent when the server is ready.
* `ddos_protection` - (Optional) Whether DDOS protection will be enabled on the server (there is an additional charge for this).
* `hostname` - (Optional) The hostname to assign to the server.
* `tag` - (Optional) The tag to assign to the server.
* `label` - (Optional) A label for the server.
* `reserved_ip_id` - (Optional) ID of the floating IP to use as the main IP of this server.
* `backups_schedule` - (Optional) A block that defines the way backups should be scheduled. While this is an optional field if `backups` are `enabled` this field is mandatory. The configuration of a `backups_schedule` is listed below.

`backups_schedule` supports the following:

* `type` - Type of backup schedule Possible values are `daily`, `weekly`, `monthly`, `daily_alt_event`, or `daily_alt_odd`.
* `hour` - (Optional) Hour of day to run in UTC.
* `dow` - (Optional) Day of week to run. `1 = Sunday`, `2 = Monday`, `3 = Tuesday`, `4 = Wednesday`, `5 = Thursday`, `6 = Friday`, `7 = Saturday`
* `dom` - (Optional) Day of month to run. Use values between 1 and 28.

## Attributes Reference

The following attributes are exported:

* `id` - ID of the server.
* `region` - The ID of the region that the server is in.
* `os` - The string description of the operating system installed on the server.
* `ram` - The amount of memory available on the server in MB.
* `disk` - The description of the disk(s) on the server.
* `main_ip` - The server's main IP address.
* `vcpu_count` - The number of virtual CPUs available on the server.
* `default_password` - The server's default password.
* `date_created` - The date the server was added to your Vultr account.
* `allowed_bandwidth` - The server's allowed bandwidth usage in GB.
* `netmask_v4` - The server's IPv4 netmask.
* `gateway_v4` - The server's IPv4 gateway.
* `status` - The status of the server's subscription.
* `power_status` - Whether the server is powered on or not.
* `server_status` - A more detailed server status (none, locked, installingbooting, isomounting, ok).
* `v6_network` - The IPv6 subnet.
* `v6_main_ip` - The main IPv6 network address.
* `v6_network_size` - The IPv6 network size in bits.
* `internal_ip` - The server's internal IP address.
* `kvm` - The server's current KVM URL. This URL will change periodically. It is not advised to cache this value.
* `plan` - The ID of the plan that server is subscribed to.
* `os_id` - The ID of the operating system installed on the server.
* `iso_id` - The ID of the ISO file installed on the server.
* `app_id` - The ID of the Vultr application installed on the server.
* `snapshot_id` - The ID of the Vultr snapshot that the server was restored from.
* `script_id` - The ID of the startup script that was added to the server.
* `firewall_group_id` - The ID of the firewall group assigned to the server.
* `private_network_ids` - A list of private network IDs attached to the server.
* `ssh_key_ids` - A list of SSH key IDs applied to the server on install.
* `user_data` - Generic data store, which some provisioning tools and cloud operating systems use as a configuration file. It is generally consumed only once after an instance has been launched, but individual needs may vary.
* `backups` - Whether automatic backups are enabled for this server.
* `enable_ipv6` - Whether the server has IPv6 networking activated.
* `enable_private_network` - (Deprecated) Whether the server has private networking support enabled.
* `activation_email` - Whether an activation email was sent when the server was ready.
* `ddos_protection` - Whether DDOS protection is enabled on the server.
* `hostname` - The hostname assigned to the server.
* `tag` - The tag assigned to the server.
* `label` - A label for the server.
* `features` - Array of which features are enabled.
* `backups_schedule` - (Optional) A block that defines the way backups should be scheduled.


## Import

Servers can be imported using the server `ID`, e.g.

```
terraform import vultr_server.my_server b6a859c5-b299-49dd-8888-b1abbc517d08
```