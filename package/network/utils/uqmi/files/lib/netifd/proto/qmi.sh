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
       uqmi -s -d "$device" \
               --stop-network 0xffffffff \
               --autoconnect > /dev/null
}

antenna_test() {
  modes=$1
  for antenna in `seq 0 3`; do
    echo $antenna > /sys/devices/wibe-antenna.4/antenna
    antenna_name=$(cat /sys/devices/wibe-antenna.4/antenna)
    echo heartbeat > /sys/class/leds/wibe:${antenna_name}:green/trigger

    for t in `seq 1 ${regtimeout:-60}`; do
      uqmi -s -d "$device" --get-serving-system | grep "registered" >/dev/null && break
      sleep 1
    done
    if uqmi -s -d "$device" --get-serving-system | grep "registered" >/dev/null; then
      sleep ${settlewait:-10}
      signalinfo=$(uqmi -s -d "$device" --get-signal-info)
      logger -p daemon.info -t "qmi[$$]" "${modes}, ${antenna_name}, ${signalinfo}"
    else
      logger -p daemon.info -t "qmi[$$]" "${modes}, ${antenna_name}, registration failed"
    fi
    echo none > /sys/class/leds/wibe:${antenna_name}:green/trigger
  done
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

	[ -n "$delay" ] && sleep "$delay"

	while uqmi -s -d "$device" --get-pin-status | grep '"UIM uninitialized"' > /dev/null; do
		sleep 1;
	done

	[ -n "$pincode" ] && {
		uqmi -s -d "$device" --verify-pin1 "$pincode" || {
			logger -p daemon.err -t "qmi[$$]" "Unable to verify PIN"
			proto_notify_error "$interface" PIN_FAILED
			proto_block_restart "$interface"
			return 1
		}
	}

	[ -n "$apn" ] || {
		logger -p daemon.err -t "qmi[$$]" "No APN specified"
		proto_notify_error "$interface" NO_APN
		proto_block_restart "$interface"
		return 1
	}

  qmi_disconnect

  uqmi -s -d "$device" --set-data-format 802.3
  uqmi -s -d "$device" --wda-set-data-format 802.3

  echo 0 > /sys/class/leds/wibe:front:green/brightness
  echo 0 > /sys/class/leds/wibe:back:green/brightness
  echo 0 > /sys/class/leds/wibe:left:green/brightness
  echo 0 > /sys/class/leds/wibe:right:green/brightness

  if [ -n "$modes" ]; then
    if [ "$modes" == "detect" ]; then
      logger -p daemon.info -t "qmi[$$]" "Testing UMTS and LTE modes"
      uqmi -s -d "$device" --set-network-modes "lte"
      antenna_test "lte"
      uqmi -s -d "$device" --set-network-modes "umts"
      antenna_test "umts"
      # Save modes so we don't re-run auto-detect
      # Choose antenna with greatest signal
      # Run a speed test between 3G and 4G.
      # Continue with starting the network
    else
      [ -n "$modes" ] && uqmi -s -d "$device" --set-network-modes "$modes"
      [ -n "$antenna" ] && [ "$antenna" == "detect" ] && antenna_test "$modes"
    fi
  fi

	logger -p daemon.info -t "qmi[$$]" "Waiting for network registration"
	while uqmi -s -d "$device" --get-serving-system | grep '"searching"' > /dev/null; do
		sleep 5;
	done

	logger -p daemon.info -t "qmi[$$]" "Starting network $apn"
	cid=`uqmi -s -d "$device" --get-client-id wds`
	[ $? -ne 0 ] && {
		logger -p daemon.err -t "qmi[$$]" "Unable to obtain client ID"
		proto_notify_error "$interface" NO_CID
		proto_block_restart "$interface"
		return 1
	}

  uqmi -s -d "$device" --set-client-id wds,"$cid" \
    --start-network "$apn" \
    ${auth:+--auth-type $auth} \
    ${username:+--username $username} \
    ${password:+--password $password} \
    --autoconnect > /dev/null

	if ! uqmi -s -d "$device" --get-data-status | grep '"connected"' > /dev/null; then
		logger -p daemon.err -t "qmi[$$]" "Connection lost"
		proto_notify_error "$interface" NOT_CONNECTED
		return 1
	fi

	logger -p daemon.info -t "qmi[$$]" "Connected, starting DHCP"
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
	local cid=$(uci_get_state network $interface cid)

	logger -p daemon.info -t "qmi[$$]" "Stopping network"
  qmi_disconnect
	[ -n "$cid" ] && {
		uqmi -s -d "$device" --set-client-id wds,"$cid" --release-client-id wds
		uci_revert_state network $interface cid
	}

	proto_init_update "*" 0
	proto_send_update "$interface"
}

add_protocol qmi

