.PHONY: all all-with-yak yak build build-web install dev serve test e2e clean

all: build build-web

# Full setup including yaklang binary build from source.
# Requires Go toolchain; may fail if yaklang has CGO or other build dependencies.
all-with-yak: yak build build-web

# Build yaklang binary from source and copy to bin/.
# NOTE: This requires a working Go build toolchain. yaklang may have CGO
# dependencies or other build requirements; if the build fails the Makefile
# prints a warning and you should rely on a yak binary already in PATH.
yak:
	@echo "Building yaklang from source..."
	@mkdir -p bin
	cd /home/zpy/goproject/IRify_SAST/yaklang && \
	go build -o /home/zpy/goproject/IRify_SAST/irify-benchmark/bin/yak common/yak/cmd/yak.go && \
	echo "Yaklang built successfully: bin/yak" || \
	echo "Yaklang build failed (missing dependencies or build errors). Falling back to PATH lookup."

install:
	cd web && npm install

build:
	@mkdir -p bin
	go build -o bin/irify-benchmark ./cmd/irify-benchmark

build-web: install
	cd web && npm run build

dev:
	./scripts/dev.sh

serve: build build-web
	@echo "Serving production build on http://localhost:8080"
	./bin/irify-benchmark server --static web/dist --port 8080

test:
	go test ./...

e2e: build
	./scripts/e2e-test.sh

clean:
	rm -rf bin/ build/ web/dist/
