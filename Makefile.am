# global flags

SUBDIRS = docs

COMMANDS = df dl get ls test export mkdir put reg rm copy

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = \
	$(GLIB_CFLAGS) \
	$(OPENSSL_CFLAGS) \
	$(LIBCURL_CFLAGS) \
	-DG_LOG_DOMAIN=\"Mega\" \
	-I$(srcdir)/lib \
	-I$(srcdir) \
	-std=c99

LDADD = \
	$(GLIB_LIBS) \
	$(OPENSSL_LIBS) \
	$(LIBCURL_LIBS)

# tools

EXTRA_DIST = lib/sjson.c

bin_PROGRAMS = megatools
megatools_SOURCES = \
	lib/sjson.gen.c \
	lib/sjson.h \
	lib/http.c \
	lib/http.h \
	lib/mega.c \
	lib/mega.h \
	lib/tools.c \
	lib/tools.h \
	lib/alloc.h \
	lib/mega.h \
	tools/df.c \
	tools/dl.c \
	tools/get.c \
	tools/ls.c \
	tools/test.c \
	tools/export.c \
	tools/mkdir.c \
	tools/put.c \
	tools/reg.c \
	tools/rm.c \
	tools/copy.c \
	tools/shell.c \
	tools/shell.h

# Use an object directory
AUTOMAKE_OPTIONS = subdir-objects

if INSTALL_COMPAT_SYMLINKS

install-exec-hook:
	cd $(DESTDIR)$(bindir) && \
	for cmd in $(COMMANDS) ; do \
		rm -f mega$$cmd$(EXEEXT) ; \
		$(LN_S) megatools$(EXEEXT) mega$$cmd$(EXEEXT) ; \
	done

endif

# Cleanup rule to remove .o files
clean-objects:
	@echo "Cleaning up object files..."
	rm -f ./lib/*.o ./tools/*.o

# Hook the cleanup rule after the installation
install: all install-exec clean-objects

# docs

MAN1 = megatools $(addprefix megatools-,$(COMMANDS))
MAN5 = megarc

man1_MANS = $(addprefix docs/,$(addsuffix .1, $(MAN1)))
man5_MANS = $(addprefix docs/,$(addsuffix .5, $(MAN5)))

EXTRA_DIST += $(man1_MANS) $(man5_MANS)

EXTRA_DIST += LICENSE HACKING contrib/bash-completion/megatools

doc_DATA = LICENSE NEWS TODO README INSTALL HACKING

EXTRA_DIST += \
	docs/auth-options.txt \
	docs/basic-options.txt \
	docs/download-options.txt \
	docs/footer.txt \
	docs/megarc.txt \
	$(addsuffix .txt,$(addprefix docs/megatools-,$(COMMANDS))) \
	docs/megatools.txt \
	docs/network-options.txt \
	docs/remote-paths.txt \
	docs/upload-options.txt \
	docs/asciidoc.conf \
	docs/Makefile
