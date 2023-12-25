VERSION ?= $(shell cargo pkgid | awk -F'@' '{sub(/[ \t]+$$/, "", $$2); print $$2}')
DOCKER_REGISTRY=csighub.tencentyun.com
AGENT_IMG=$(DOCKER_REGISTRY)/tat-develop/tat_agent
# test 
test:
	cargo test --package tat_agent -- --nocapture --skip ontime

linux_32_bin:
	(RUSTFLAGS='-C target-feature=+crt-static' cross build --bin utmpx -r --target i686-unknown-linux-gnu)
	cross build --bin tat_agent -r --target=i686-unknown-linux-musl
	mkdir -p release/linux-32
	cp ./target/i686-unknown-linux-musl/release/tat_agent ./release/linux-32
	cp ./target/i686-unknown-linux-gnu/release/utmpx ./release/linux-32

linux_32_update_pkg: linux_32_bin
	rm -f ./release/tat_agent_linux_install_i686_*.zip
	cd ./release/linux-32 && \
	cp ../../install/{tat_agent_service,tat_agent_service.conf,tat_agent.service,*.sh} ./ && \
	zip ../tat_agent_linux_install_i686_${VERSION}.zip  * 

linux_64_bin:
	(RUSTFLAGS='-C target-feature=+crt-static' cross build --bin utmpx -r --target x86_64-unknown-linux-gnu)
	cross build --bin tat_agent -r --target=x86_64-unknown-linux-musl
	mkdir -p release/linux-64
	cp ./target/x86_64-unknown-linux-musl/release/tat_agent ./release/linux-64
	cp ./target/x86_64-unknown-linux-gnu/release/utmpx ./release/linux-64

linux_64_update_pkg: linux_64_bin
	rm -f ./release/tat_agent_linux_install_x86_64_*.zip
	cd ./release/linux-64 && \
	cp ../../install/{tat_agent_service,tat_agent_service.conf,tat_agent.service,*.sh} ./ && \
	zip ../tat_agent_linux_install_x86_64_${VERSION}.zip  * 

linux_arm64_bin:
	cross build --bin tat_agent -r --target=aarch64-unknown-linux-musl
	cross build --bin utmpx -r --target aarch64-unknown-linux-gnu
	mkdir -p release/linux-arm64
	cp ./target/aarch64-unknown-linux-musl/release/tat_agent ./release/linux-arm64
	cp ./target/aarch64-unknown-linux-gnu/release/utmpx ./release/linux-arm64

linux_arm64_update_pkg: linux_arm64_bin
	rm -f ./release/tat_agent_linux_install_aarch64_*.zip
	cd ./release/linux-arm64 && \
	cp ../../install/{tat_agent_service,tat_agent_service.conf,tat_agent.service,*.sh} ./ && \
	zip ../tat_agent_linux_install_aarch64_${VERSION}.zip * 


linux_install_pkg: linux_32_bin linux_64_bin linux_arm64_bin
	rm -rf ./release/linux-all
	mkdir  ./release/linux-all
	cd  ./release/linux-all && \
	cp ../../install/{tat_agent_service,tat_agent_service.conf,tat_agent.service,*.sh} ./ && \
	cp ../linux-32/tat_agent  ./tat_agent32 && \
	cp ../linux-32/utmpx  ./utmpx32 && \
	cp ../linux-64/tat_agent  ./tat_agent && \
	cp ../linux-64/utmpx  ./utmpx && \
	cp ../linux-arm64/tat_agent  ./tat_agent_aarch64 && \
	cp ../linux-arm64/utmpx  ./utmpx_aarch64 && \
	rm -f ./release/tat_agent_linux_install_${VERSION}.tar.gz && \
	tar -czf ../tat_agent_linux_install_${VERSION}.tar.gz * --transform "s,^,tat_agent_linux_install_${VERSION}/,"


release: linux_install_pkg linux_32_update_pkg linux_64_update_pkg linux_arm64_update_pkg


build:
	cargo build 

# notice：agent image only used for E2E environment.
build-img: linux_64_bin
	$(info VERSION: $(VERSION))
	docker build --tag $(AGENT_IMG):$(VERSION) -f Dockerfile ./target/x86_64-unknown-linux-musl/release

# notice：agent image only used for E2E environment.
push-img:
	$(info image: $(AGENT_IMG):$(VERSION))
	docker push $(AGENT_IMG):$(VERSION)

clean:
	rm .*.sh 2> /dev/null || true
	rm tasks/* 2> /dev/null || true
