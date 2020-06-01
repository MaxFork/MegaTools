/*
 *  megatools - Mega.nz client library and tools
 *  Copyright (C) 2013  Ondřej Jirman <megous@megous.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <string.h>
#include "shell.h"
#include "config.h"
#include "lib/alloc.h"

extern struct shell_tool shell_tool_df;
extern struct shell_tool shell_tool_dl;
extern struct shell_tool shell_tool_get;
extern struct shell_tool shell_tool_ls;
extern struct shell_tool shell_tool_mkdir;
extern struct shell_tool shell_tool_put;
extern struct shell_tool shell_tool_reg;
extern struct shell_tool shell_tool_rm;
extern struct shell_tool shell_tool_copy;
extern struct shell_tool shell_tool_test;
extern struct shell_tool shell_tool_export;

static struct shell_tool* tools[] = {
	&shell_tool_dl,
	&shell_tool_df,
	&shell_tool_ls,
	&shell_tool_test,
	&shell_tool_export,
	&shell_tool_get,
	&shell_tool_put,
	&shell_tool_copy,
	&shell_tool_mkdir,
	&shell_tool_rm,
	&shell_tool_reg,
};

int main(int ac, char *av[])
{
	gc_free gchar* cmd_basename = g_path_get_basename(av[0]);
	gchar* cmd_name = NULL;

	if (g_str_has_suffix(cmd_basename, ".exe"))
		cmd_basename[strlen(cmd_basename) - 4] = '\0';
	if (g_str_has_prefix(cmd_basename, "mega"))
		cmd_name = cmd_basename + 4;

	if (cmd_name) {
		// try to run a specifc <command> if we're run via mega<command>[.exe]
		for (int i = 0; i < G_N_ELEMENTS(tools); i++) {
			if (!strcmp(cmd_name, tools[i]->name))
				return tools[i]->main(ac, av);
		}
	}

	if (ac > 1) {
		// otherwise try to find a command name based on the first argument
		for (int i = 0; i < G_N_ELEMENTS(tools); i++) {
			if (!strcmp(av[1], tools[i]->name)) {
				av[1] = g_strdup_printf("megatools %s", av[1]);

				return tools[i]->main(ac - 1, av + 1);
			}
		}
	}

	// show usage if we failed to run any specific command
	g_print("Usage:\n");

	for (int i = 0; i < G_N_ELEMENTS(tools); i++)
		if (tools[i]->usages)
			for (int j = 0; tools[i]->usages[j]; j++)
				g_print("  megatools %s %s\n", tools[i]->name, tools[i]->usages[j]);

	g_print("\n");
	g_print("Run: megatools <command> --help for detailed options for each command.\n");

	g_print("\n");
	g_print("megatools " VERSION " - command line tools for Mega.nz\n");
	g_print("Written by Ondrej Jirman <megous@megous.com>, 2013-2018\n");
	g_print("Go to http://megatools.megous.com for more information\n");
	return 1;
}
