/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>

#include "client/command.h"
#include "client/dbus-proxy.h"
#include "client/device.h"
#include "client/display.h"

struct ap {
	bool started;
};

static void *ap_create(void)
{
	return l_new(struct ap, 1);
}

static void ap_destroy(void *data)
{
	struct ap *ap = data;

	l_free(ap);
}

static const struct proxy_interface_type_ops ap_ops = {
	.create = ap_create,
	.destroy = ap_destroy,
};

static const char *get_started_tostr(const void *data)
{
	const struct ap *ap = data;

	return ap->started ? "yes" : "no";
}

static void update_started(void *data, struct l_dbus_message_iter *variant)
{
	struct ap *ap = data;
	bool value;

	if (!l_dbus_message_iter_get_variant(variant, "b", &value)) {
		ap->started = false;

		return;
	}

	ap->started = value;
}

static const struct proxy_interface_property ap_properties[] = {
	{ "Started",  "b", update_started,  get_started_tostr },
	{ }
};

static struct proxy_interface_type ap_interface_type = {
	.interface = IWD_ACCESS_POINT_INTERFACE,
	.properties = ap_properties,
	.ops = &ap_ops,
};

static void check_errors_method_callback(struct l_dbus_message *message,
								void *user_data)
{
	dbus_message_has_error(message);
}

static void display_ap_inline(const char *margin, const void *data)
{
	const struct proxy_interface *ap_i = data;
	const struct ap *ap = proxy_interface_get_data(ap_i);
	struct proxy_interface *device_i =
		proxy_interface_find(IWD_DEVICE_INTERFACE,
					proxy_interface_get_path(ap_i));
	const char *identity;

	if (!device_i)
		return;

	identity = proxy_interface_get_identity_str(device_i);
	if (!identity)
		return;

	display("%s%-*s%-*s\n", margin,
			20, identity,
			8, get_started_tostr(ap));
}

static enum cmd_status cmd_list(const char *device_name, char **argv, int argc)
{
	const struct l_queue_entry *entry;
	struct l_queue *match =
		proxy_interface_find_all(IWD_ACCESS_POINT_INTERFACE,
						NULL, NULL);

	display_table_header("Devices in Access Point Mode", MARGIN "%-*s%-*s",
				20, "Name",
				8, "Started");

	if (!match) {
		display("No devices in access point mode available.\n");
		display_table_footer();

		return CMD_STATUS_DONE;
	}

	for (entry = l_queue_get_entries(match); entry; entry = entry->next) {
		const struct proxy_interface *ap = entry->data;
		display_ap_inline(MARGIN, ap);
	}

	display_table_footer();

	l_queue_destroy(match, NULL);

	return CMD_STATUS_DONE;
}

static enum cmd_status cmd_start(const char *device_name, char **argv, int argc)
{
	const struct proxy_interface *ap_i;

	if (argc < 2)
		return CMD_STATUS_INVALID_ARGS;

	if (strlen(argv[0]) > 32) {
		display("Network name cannot exceed 32 characters.\n");

		return CMD_STATUS_INVALID_VALUE;
	}

	if (strlen(argv[1]) < 8) {
		display("Passphrase cannot be shorted than 8 characters.\n");

		return CMD_STATUS_INVALID_VALUE;
	}

	ap_i = device_proxy_find(device_name, IWD_ACCESS_POINT_INTERFACE);
	if (!ap_i) {
		display("No ap on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(ap_i, "Start", "ss",
						check_errors_method_callback,
						argv[0], argv[1]);

	return CMD_STATUS_TRIGGERED;
}

static enum cmd_status cmd_stop(const char *device_name, char **argv, int argc)
{
	const struct proxy_interface *ap_i =
		device_proxy_find(device_name, IWD_ACCESS_POINT_INTERFACE);

	if (!ap_i) {
		display("No ap on device: '%s'\n", device_name);
		return CMD_STATUS_INVALID_VALUE;
	}

	proxy_interface_method_call(ap_i, "Stop", "",
						check_errors_method_callback);

	return CMD_STATUS_TRIGGERED;
}

static const struct command ap_commands[] = {
	{ NULL, "list", NULL, cmd_list, "List devices in AP mode", true },
	{ "<wlan>", "start", "<\"network name\"> <passphrase>", cmd_start,
		"Start an access point\n\t\t\t\t\t\t    called \"network "
		"name\" with\n\t\t\t\t\t\t    a passphrase" },
	{ "<wlan>", "stop", NULL,   cmd_stop, "Stop a started access\n"
		"\t\t\t\t\t\t    point" },
	{ }
};

static char *family_arg_completion(const char *text, int state)
{
	return device_arg_completion(text, state, ap_commands,
						IWD_ACCESS_POINT_INTERFACE);
}

static char *entity_arg_completion(const char *text, int state)
{
	return command_entity_arg_completion(text, state, ap_commands);
}

static struct command_family ap_command_family = {
	.caption = "Access Point",
	.name = "ap",
	.command_list = ap_commands,
	.family_arg_completion = family_arg_completion,
	.entity_arg_completion = entity_arg_completion,
};

static int ap_command_family_init(void)
{
	command_family_register(&ap_command_family);

	return 0;
}

static void ap_command_family_exit(void)
{
	command_family_unregister(&ap_command_family);
}

COMMAND_FAMILY(ap_command_family, ap_command_family_init,
							ap_command_family_exit)

static int ap_interface_init(void)
{
	proxy_interface_type_register(&ap_interface_type);

	return 0;
}

static void ap_interface_exit(void)
{
	proxy_interface_type_unregister(&ap_interface_type);
}

INTERFACE_TYPE(ap_interface_type, ap_interface_init, ap_interface_exit)
