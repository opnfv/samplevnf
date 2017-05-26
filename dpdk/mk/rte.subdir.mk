#   BSD LICENSE
#
#   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#
# .mk to build subdirectories
#

include $(RTE_SDK)/mk/internal/rte.install-pre.mk
include $(RTE_SDK)/mk/internal/rte.clean-pre.mk
include $(RTE_SDK)/mk/internal/rte.build-pre.mk

CLEANDIRS = $(addsuffix _clean,$(DIRS-y) $(DIRS-n) $(DIRS-))

VPATH += $(SRCDIR)
_BUILD = $(DIRS-y)
_INSTALL = $(INSTALL-FILES-y) $(SYMLINK-FILES-y)
_CLEAN = $(CLEANDIRS)

.PHONY: all
all: install

.PHONY: install
install: build _postinstall

_postinstall: build

.PHONY: build
build: _postbuild

.SECONDEXPANSION:
.PHONY: $(DIRS-y)
$(DIRS-y):
	@[ -d $(CURDIR)/$@ ] || mkdir -p $(CURDIR)/$@
	@echo "== Build $S/$@"
	@$(MAKE) S=$S/$@ -f $(SRCDIR)/$@/Makefile -C $(CURDIR)/$@ all

.PHONY: clean
clean: _postclean

%_clean:
	@echo "== Clean $S/$*"
	@if [ -f $(SRCDIR)/$*/Makefile -a -d $(CURDIR)/$* ]; then \
		$(MAKE) S=$S/$* -f $(SRCDIR)/$*/Makefile -C $(CURDIR)/$* clean ; \
	fi
	@rm -f $(_BUILD_TARGETS) $(_INSTALL_TARGETS) $(_CLEAN_TARGETS)

#
# include .depdirs and define rules to order priorities between build
# of directories.
#
include $(RTE_OUTPUT)/.depdirs

define depdirs_rule
$(1): $(sort $(patsubst $(S)/%,%,$(LOCAL_DEPDIRS-$(S)/$(1))))
endef

$(foreach d,$(DIRS-y),$(eval $(call depdirs_rule,$(d))))


# use a "for" in a shell to process dependencies: we don't want this
# task to be run in parallel.
.PHONY: depdirs
depdirs:
	@for d in $(DIRS-y); do \
		if [ -f $(SRCDIR)/$$d/Makefile ]; then \
			$(MAKE) S=$S/$$d -f $(SRCDIR)/$$d/Makefile depdirs ; \
		fi ; \
	done

.PHONY: depgraph
depgraph:
	@for d in $(DIRS-y); do \
		echo "    \"$(S)\" -> \"$(S)/$$d\"" ; \
		if [ -f $(SRCDIR)/$$d/Makefile ]; then \
			$(MAKE) S=$S/$$d -f $(SRCDIR)/$$d/Makefile depgraph ; \
		fi ; \
	done

include $(RTE_SDK)/mk/internal/rte.install-post.mk
include $(RTE_SDK)/mk/internal/rte.clean-post.mk
include $(RTE_SDK)/mk/internal/rte.build-post.mk

.PHONY: FORCE
FORCE:
