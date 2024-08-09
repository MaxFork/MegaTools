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

static GOptionEntry entries[] = {
	{ NULL }
};

static int export_main(int ac, char *av[])
{
	struct mega_session *s;
	gc_error_free GError *local_err = NULL;
	GSList* l = NULL, *i;
	int ret = 1;

	tool_init(&ac, &av, "- create public link for files at mega.nz", entries, TOOL_INIT_AUTH);
	
	if (ac < 2) {
		g_printerr("ERROR: You must pass at least one remote path\n");
		tool_fini(NULL);
		return 1;
	}

	s = tool_start_session(TOOL_SESSION_OPEN);
	if (!s) {
		tool_fini(NULL);
		return 1;
	}
	
	for (gint j = 1; j < ac; j++) {
		gchar *path = av[j];
		struct mega_node *n = mega_session_stat(s, path);
		
		if (!n) {
			g_printerr("ERROR: Remote file not found: %s\n", path);
			goto out_slist_free;
		} else if (n->type != MEGA_NODE_FILE) {
			g_printerr("ERROR: Remote path is not a file: %s\n", path);
			goto out_slist_free;
		}

		l = g_slist_prepend(l, n);
	}

	l = g_slist_reverse(l);

	if (!mega_session_addlinks(s, l, &local_err)) {
		g_printerr("ERROR: Can't read links info from mega.nz: %s\n", local_err->message);
		goto out_slist_free;
	}

	for (i = l; i; i = i->next) {
		struct mega_node* n = i->data;

		if (n->link) {
			gc_free gchar* link = mega_node_get_link(n, TRUE);
			g_print("%s\n", link);
		} else {
			gc_free gchar *node_path = mega_node_get_path_dup(n);
			g_printerr("WARNING: Missing link for %s\n", node_path);
		}
	}

	ret = 0;

out_slist_free:
	g_slist_free(l);
	tool_fini(s);
	return ret;
}

const struct shell_tool shell_tool_export = {
	.name = "export",
	.main = export_main,
	.usages = (char*[]){
		"<remotepaths>...",
		NULL
	},
};
