#!/bin/sh

. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"

proto_qmi_init_config() {
	proto_config_add_string "device:device"
	proto_config_add_string apn
	proto_config_add_string auth
	proto_config_add_string username
	proto_config_add_string password
	proto_config_add_string pincode
	proto_config_add_string delay
	proto_config_add_string modes
	proto_config_add_string regtimeout
	proto_config_add_string settlewait
}

qmi_disconnect() {
       # disable previous autoconnect state using the global handle
       # do not reuse previous wds client id to prevent hangs caused by stale data
       /etc/init.d/umtsd stop
}

proto_qmi_setup() {
	local interface="$1"

	local device apn auth username password pincode delay modes cid pdh regtimeout settlewait
	json_get_vars device apn auth username password pincode delay modes regtimeout settlewait

	[ -n "$device" ] || {
		logger -p daemon.err -t "qmi[$$]" "No control device specified"
		proto_notify_error "$interface" NO_DEVICE
		proto_block_restart "$interface"
		return 1
	}
	[ -c "$device" ] || {
		logger -p daemon.err -t "qmi[$$]" "The specified control device does not exist"
		proto_notify_error "$interface" NO_DEVICE
		proto_block_restart "$interface"
		return 1
	}

  /etc/init.d/umtsd start

	proto_init_update "*" 1
	proto_send_update "$interface"

	json_init
	json_add_string name "${interface}_dhcp"
	json_add_string ifname "@$interface"
	json_add_string proto "dhcp"
	json_close_object
	ubus call network add_dynamic "$(json_dump)"

	json_init
	json_add_string name "${interface}_dhcpv6"
	json_add_string ifname "@$interface"
	json_add_string proto "dhcpv6"
	json_close_object
	ubus call network add_dynamic "$(json_dump)"
}

proto_qmi_teardown() {
	local interface="$1"

	local device
	json_get_vars device

	logger -p daemon.info -t "qmi[$$]" "Stopping network"

  /etc/init.d/umtsd stop

	proto_init_update "*" 0
	proto_send_update "$interface"
}

add_protocol qmi

