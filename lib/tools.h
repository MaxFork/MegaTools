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

#ifndef __TOOLS_H
#define __TOOLS_H

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <stdlib.h>
#include <string.h>
#include "mega.h"
#include "alloc.h"

typedef enum {
	TOOL_SESSION_OPEN = 1,
	TOOL_SESSION_AUTH_ONLY = 2,
	TOOL_SESSION_AUTH_OPTIONAL = 4,
} ToolSessionFlags;

typedef enum {
	TOOL_INIT_AUTH = 1, // accept auth options, require them
	TOOL_INIT_AUTH_OPTIONAL = 2, // accept auth options, optionally
	TOOL_INIT_UPLOAD_OPTS = 4, // accept upload options
	TOOL_INIT_DOWNLOAD_OPTS = 8, // accept download options
} ToolInitFlags;

void tool_init(gint *ac, gchar ***av, const gchar *tool_name, GOptionEntry *tool_entries, ToolInitFlags flags);
struct mega_session *tool_start_session(ToolSessionFlags flags);
void tool_fini(struct mega_session *s);

void tool_show_progress(const gchar *file, const struct mega_status_data *data);
gboolean tool_is_stdout_tty(void);
gchar* tool_prompt_input(void);

#define ESC_CLREOL "\x1b[0K"
#define ESC_WHITE "\x1b[37;1m"
#define ESC_GREEN "\x1b[32;1m"
#define ESC_YELLOW "\x1b[33;1m"
#define ESC_BLUE "\x1b[34;1m"
#define ESC_GRAY "\x1b[30;1m"
#define ESC_NORMAL "\x1b[0m"

DEFINE_CLEANUP_FUNCTION(struct mega_session*, tool_fini)
#define gc_tool_fini CLEANUP(tool_fini)

#endif
