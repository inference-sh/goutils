.PHONY: release release-patch release-minor release-major test

BUMP ?= patch

# Consumers that pin this module, for the local shortcut below only.
#
# Keeping them current is NOT this repo's job: each consumer runs its own
# dependabot against gomod and opens a pull request when a tag appears here.
# A module reaching into the repos that use it points the dependency the
# wrong way, and the CI version of it committed straight to their branches,
# which in a shared checkout arrives mid-edit.
CONSUMERS := api cli engine uploader

# Compute next tag from latest semver tag.
LATEST_TAG := $(shell git tag --sort=-v:refname | head -1)
MAJOR := $(shell echo $(LATEST_TAG) | sed 's/v//' | cut -d. -f1)
MINOR := $(shell echo $(LATEST_TAG) | sed 's/v//' | cut -d. -f2)
PATCH := $(shell echo $(LATEST_TAG) | sed 's/v//' | cut -d. -f3)

ifeq ($(BUMP),major)
  NEXT_TAG := v$(shell echo $$(($(MAJOR)+1))).0.0
else ifeq ($(BUMP),minor)
  NEXT_TAG := v$(MAJOR).$(shell echo $$(($(MINOR)+1))).0
else
  NEXT_TAG := v$(MAJOR).$(MINOR).$(shell echo $$(($(PATCH)+1)))
endif

test:
	GOWORK=off go build ./... && go test ./...

# release tags and publishes. That is the whole job; dependabot takes it
# from there in each consumer.
#
# It then offers a shortcut: when you tagged because something in this
# checkout needs the new symbol now, waiting for a pull request is silly, so
# it points any consumer present at the new version. It does not commit
# there — those trees may hold someone else's work, and staging go.mod
# alongside it would sweep that in.
release:
	@if [ -n "$$(git status --porcelain)" ]; then echo "error: uncommitted changes"; exit 1; fi
	@echo "==> testing without go.work (what consumers' CI sees)"
	@$(MAKE) test
	@echo "==> tagging $(NEXT_TAG) (was $(LATEST_TAG))"
	git tag $(NEXT_TAG)
	git push origin HEAD $(NEXT_TAG)
	@echo "==> warming the module proxy"
	@curl -sf "https://proxy.golang.org/github.com/inference-sh/goutils/@v/$(NEXT_TAG).info" >/dev/null || \
		echo "    (proxy not warm yet; a consumer's first go get will fetch direct)"
	@echo "==> local shortcut: pointing checked-out consumers at $(NEXT_TAG)"
	@echo "    (dependabot opens the real pull requests; this is for work in flight)"
	@for c in $(CONSUMERS); do \
		if [ -d ../$$c ]; then \
			(cd ../$$c && GOWORK=off go get github.com/inference-sh/goutils@$(NEXT_TAG) >/dev/null 2>&1 && go mod tidy >/dev/null 2>&1) \
				&& echo "    $$c updated" \
				|| echo "    $$c FAILED — bump it by hand"; \
		else \
			echo "    $$c not checked out, skipped"; \
		fi; \
	done
	@echo ""
	@echo "released $(NEXT_TAG)."
	@echo ""
	@echo "Left uncommitted on purpose — these trees may hold work in progress,"
	@echo "so committing for you could sweep in someone else's change. Commit"
	@echo "only what you actually need now; dependabot will raise the rest:"
	@echo ""
	@for c in $(CONSUMERS); do \
		if [ -d ../$$c ] && [ -n "$$(cd ../$$c && git status --porcelain -- go.mod go.sum)" ]; then \
			echo "    cd go/$$c && git add go.mod go.sum && git commit -m 'deps: goutils $(NEXT_TAG)'"; \
		fi; \
	done
	@echo ""
	@echo "Any consumer not listed above was already on $(NEXT_TAG)."

release-patch: ; @$(MAKE) release BUMP=patch
release-minor: ; @$(MAKE) release BUMP=minor
release-major: ; @$(MAKE) release BUMP=major
