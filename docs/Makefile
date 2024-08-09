# build docs

VERSION = 1.10.3
COMMANDS = df dl get ls test export mkdir put reg rm copy

COMMON_DEPS = \
	asciidoc.conf \
	footer.txt \
	$(wildcard *-options.txt) \
	remote-paths.txt

all:

define MAN_template =
$(1).$(2): $(1).txt $(COMMON_DEPS)
	a2x --asciidoc-opts="-f asciidoc.conf -o $$@" --destination-dir . -f manpage $$<
	test $$(subst -,_,$$@) = $$@ || mv -f $$(subst -,_,$$@) $$@
	@sed -i 's/megatools_/megatools-/' $$@
	@sed -i 's/\[FIXME: manual]/Megatools Manual/' $$@
	@sed -i 's/\[FIXME: source]/megatools $(VERSION)/' $$@

all: $(1).$(2)
clean-$(1).$(2):
	rm $(1).$(2)
clean: clean-$(1).$(2)
endef

$(foreach cmd,$(COMMANDS),$(eval $(call MAN_template,megatools-$(cmd),1)))
$(eval $(call MAN_template,megatools,1))
$(eval $(call MAN_template,megarc,5))

maintainer-clean:
distclean:
install-exec:
install: