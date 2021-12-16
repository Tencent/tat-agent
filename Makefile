.PHONY: test static release stop run t clean build
ifndef QCI_TRIGGER
	QCI_TRIGGER = root
endif

VERSION ?= $(shell git rev-parse --short HEAD || echo "GitNotFound")
DOCKER_REGISTRY=csighub.tencentyun.com
AGENT_IMG=$(DOCKER_REGISTRY)/tat-develop/tat_agent

# test all case
lib-test:
	cargo test --lib -- --nocapture --skip ontime

integration-test:
	cargo test --test http_test

arch ?= x86_64
rust_target =
in_docker ?= true
ifeq ($(arch),x86_64)
	rust_target = x86_64-unknown-linux-musl
else ifeq ($(arch), i686)
	rust_target = i686-unknown-linux-musl
else ifeq ($(arch), i586)
	rust_target = i586-unknown-linux-musl
endif

# ensure cross installed. we use it for cross-compile.
ifeq (, $(shell which cross))
$(info "cross not found, install it now.")
$(shell cargo install cross)
endif

# build a pure static binary in debug mode
static:
ifeq ($(rust_target), )
$(error `$(arch)` not exists or not supported yet.)
endif

ifeq ($(in_docker),true)
	cross build --target=$(rust_target)
else
	cargo build --target=$(rust_target)
endif

	ln -f target/$(rust_target)/debug/tat_agent tat_agent

# build a pure static binary in release
release:
ifeq ($(in_docker),true)
	cross build --release --target=x86_64-unknown-linux-musl
	cross build --release --target=i686-unknown-linux-musl
else
	cargo build --release --target=x86_64-unknown-linux-musl
	cargo build --release --target=i686-unknown-linux-musl
endif

	ln -f target/x86_64-unknown-linux-musl/release/tat_agent tat_agent
	ln -f target/i686-unknown-linux-musl/release/tat_agent tat_agent32
	install/release.sh

# stop the daemon via systemctl, or kill directly by pid
stop:
	systemctl stop tat_agent || kill -9 `cat /var/run/tat_agent.pid`

# build via make release and then install it
run:
	make release
	install/install.sh

# build a pure static binary for debugging
build:
	cargo build --target=x86_64-unknown-linux-musl
	ln -f target/x86_64-unknown-linux-musl/debug/tat_agent tat_agent

# a shortcut for fuzzy matching
# usage: make t m=partial_of_testcase_name
t:
	cargo test $(m) --lib -- --nocapture

# notice：agent image only used for E2E environment.
build-img:
	$(info VERSION: $(VERSION))
	mkdir -p ./bin
	ln -f tat_agent ./bin/tat_agent
	docker build --tag $(AGENT_IMG):$(VERSION) -f Dockerfile ./bin
	rm -r ./bin

# notice：agent image only used for E2E environment.
push-img:
	$(info image: $(AGENT_IMG):$(VERSION))
	docker push $(AGENT_IMG):$(VERSION)

# notice：agent image only used for E2E environment.
all-img: static build-img push-img

clean:
	rm .*.sh 2> /dev/null || true
	rm tasks/* 2> /dev/null || true
