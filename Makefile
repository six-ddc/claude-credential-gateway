# 网关和设备端是同一个二进制的两种角色(`claude-credential-gateway` / `claude-credential-gateway device`)。
# 设备端二进制放在 dist/device/<os>/<arch>,由网关经 SSH exec 分发给已认证设备,
# 所以网关机上要先 make device-bins。

BIN := claude-credential-gateway
DEVICE_PLATFORMS ?= darwin/arm64 darwin/amd64 linux/amd64 linux/arm64
GOFLAGS := -trimpath -ldflags='-s -w'

.PHONY: build device-bins test all clean

all: build device-bins

build:
	go build $(GOFLAGS) -o $(BIN) .

device-bins:
	@for p in $(DEVICE_PLATFORMS); do \
		echo "  build dist/device/$$p"; \
		GOOS=$${p%/*} GOARCH=$${p#*/} CGO_ENABLED=0 go build $(GOFLAGS) -o dist/device/$$p . || exit 1; \
	done

test:
	go vet ./... && go test ./...

clean:
	rm -rf $(BIN) dist
