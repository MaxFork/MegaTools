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

#include "tools.h"
#include "shell.h"

static gboolean opt_names;
static gboolean opt_recursive;
static gboolean opt_long;
static gboolean opt_human;
static gboolean opt_export;
//static gboolean opt_color;
static gboolean opt_header;
static gboolean opt_print0;

static GOptionEntry entries[] = {
	{ "names", 'n', 0, G_OPTION_ARG_NONE, &opt_names,
	  "List names of files only (will be disabled if you specify multiple paths)", NULL },
	{ "recursive", 'R', 0, G_OPTION_ARG_NONE, &opt_recursive, "List files in subdirectories", NULL },
	{ "long", 'l', 0, G_OPTION_ARG_NONE, &opt_long, "Use a long listing format", NULL },
	{ "header", '\0', 0, G_OPTION_ARG_NONE, &opt_header, "Show columns header in long listing", NULL },
	{ "human", 'h', 0, G_OPTION_ARG_NONE, &opt_human, "Human readable sizes", NULL },
	{ "print0", '0', 0, G_OPTION_ARG_NONE, &opt_print0, "Separate file paths with NULs", NULL },
	//{ "color",         'c',   0, G_OPTION_ARG_NONE,    &opt_color,        "Use color highlighting of node types",        NULL },
	{ "export", 'e', 0, G_OPTION_ARG_NONE, &opt_export, "Show mega.nz download links (export)", NULL },
	{ NULL }
};

static gint compare_node(struct mega_node *a, struct mega_node *b)
{
	gchar path1[4096];
	gchar path2[4096];

	if (mega_node_get_path(a, path1, 4096) && mega_node_get_path(b, path2, 4096))
		return strcmp(path1, path2);
	return 0;
}

static int ls_main(int ac, char *av[])
{
	struct mega_session *s;
	gc_error_free GError *local_err = NULL;
	GSList *l = NULL, *i;
	gint j;

	tool_init(&ac, &av, "- list files stored at mega.nz", entries, TOOL_INIT_AUTH);
	
	if (opt_long && opt_print0) {
		g_printerr("ERROR: You can't combine --print0 and --long\n");
		tool_fini(NULL);
		return 1;
	}

	s = tool_start_session(TOOL_SESSION_OPEN);
	if (!s) {
		tool_fini(NULL);
		return 1;
	}

	// gather nodes
	if (ac == 1) {
		l = mega_session_ls_all(s);
		opt_names = FALSE;
	} else {
		if (ac > 2 || opt_recursive)
			opt_names = FALSE;

		for (j = 1; j < ac; j++) {
			gchar *path = av[j];

			struct mega_node *n = mega_session_stat(s, path);
			if (n && (n->type == MEGA_NODE_FILE || !opt_names))
				l = g_slist_append(l, n);

			l = g_slist_concat(l, mega_session_ls(s, path, opt_recursive));
		}
	}

	l = g_slist_sort(l, (GCompareFunc)compare_node);

	// export if requested
	if (opt_export && !mega_session_addlinks(s, l, &local_err)) {
		g_printerr("ERROR: Can't read links info from mega.nz: %s\n", local_err->message);
		g_slist_free(l);
		tool_fini(s);
		return 1;
	}

	if (l && opt_long && opt_header && !opt_export) {
		g_print("===================================================================================\n");
		g_print("%-11s %-11s %-1s %13s %-19s %s\n", "Handle", "Owner", "T", "Size", "Mod. Date",
			opt_names ? "Filename" : "Path");
		g_print("===================================================================================\n");
	}

	for (i = l; i; i = i->next) {
		struct mega_node *n = i->data;
		gc_free gchar *node_path = mega_node_get_path_dup(n);

		if (opt_export)
			g_print("%-70s ", n->link ? mega_node_get_link(n, TRUE) : "");

		if (opt_long) {
			GDateTime *dt = g_date_time_new_from_unix_local(n->timestamp);
			gc_free gchar *time_str = g_date_time_format(dt, "%Y-%m-%d %H:%M:%S");
			g_date_time_unref(dt);

			gc_free gchar *size_str = NULL;
			if (opt_human)
				size_str = n->size > 0 ? g_format_size_full(n->size, G_FORMAT_SIZE_IEC_UNITS) :
							 g_strdup("-");
			else
				size_str = n->size > 0 ? g_strdup_printf("%" G_GUINT64_FORMAT, n->size) : g_strdup("-");

			g_print("%-11s %-11s %d %13s %19s %s\n", n->handle, n->user_handle ? n->user_handle : "",
				n->type, size_str, n->timestamp > 0 ? time_str : "", opt_names ? n->name : node_path);
		} else {
			g_print("%s", opt_names ? n->name : node_path);
			if (opt_print0)
				putchar('\0');
			else
				g_print("\n");
		}
	}

	g_slist_free(l);
	tool_fini(s);
	return 0;
}

const struct shell_tool shell_tool_ls = {
	.name = "ls",
	.main = ls_main,
	.usages = (char*[]){
		"[-e] [-h] [--header] [-l] [-R] [-n] [<remotepaths>...]",
		NULL
	},
};
