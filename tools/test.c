/*
 *  megatools - Mega.nz client library and tools
 *  Copyright (C) 2019  Ondřej Jirman <megous@megous.com>
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

#include "tools.h"
#include "shell.h"

static gboolean opt_is_file;
static gboolean opt_is_folder;

static GOptionEntry entries[] = {
	{ "file", 'f', 0, G_OPTION_ARG_NONE, &opt_is_file, "Test for files only", NULL },
	{ "folder", 'd', 0, G_OPTION_ARG_NONE, &opt_is_folder, "Test for folders only", NULL },
	{ NULL }
};

static int test_main(int ac, char *av[])
{
	struct mega_session *s;
	gc_error_free GError *local_err = NULL;
	int ret = 0;

	tool_init(&ac, &av, "- test for existence of files stored at mega.nz", entries, TOOL_INIT_AUTH);
	
	if (opt_is_file && opt_is_folder) {
		g_printerr("ERROR: You can't combine -f and -d\n");
		tool_fini(NULL);
		return 3;
	}

	if (ac < 2) {
		g_printerr("ERROR: You must pass at least one remote path\n");
		tool_fini(NULL);
		return 3;
	}

	s = tool_start_session(TOOL_SESSION_OPEN);
	if (!s) {
		tool_fini(NULL);
		return 3;
	}
	
	for (gint j = 1; j < ac; j++) {
		gchar *path = av[j];
		struct mega_node *n = mega_session_stat(s, path);
		
		if (!n) {
			ret = 1;
		} else if (n->type != MEGA_NODE_FILE && opt_is_file) {
			if (ret != 1)
				ret = 2;
		} else if (n->type != MEGA_NODE_FOLDER && opt_is_folder) {
			if (ret != 1)
				ret = 2;
		}
	}

	tool_fini(s);
	return ret;
}

const struct shell_tool shell_tool_test = {
	.name = "test",
	.main = test_main,
	.usages = (char*[]){
		"[-f|-d] <remotepaths>...",
		NULL
	},
};
