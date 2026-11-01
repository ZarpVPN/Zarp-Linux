.PHONY: build test runtime demo package test-packets check-release

build:
	mkdir -p build
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags='-s -w' -o build/zarpd ./cmd/zarpd
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags='-s -w' -o build/zarpctl ./cmd/zarpctl

runtime:
	python3 tools/fetch-runtime.py

test: build
	python3 tools/check-repo.py
	go test -race ./internal/... ./cmd/...
	QT_QPA_PLATFORM=offscreen python3 -m unittest discover -s desktop/tests
	python3 -m unittest discover -s tools/tests
	python3 tools/compact-quic-fake.py --check

test-packets:
	bash scripts/test-netns.sh

check-release:
	python3 tools/release.py version

demo: build
	python3 desktop/zarp.py --demo

package: build
	bash tools/build-native-runtime.sh build/native-runtime
	python3 tools/native-packages.py --runtime build/native-runtime/runtime
