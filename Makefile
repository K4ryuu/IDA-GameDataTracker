# GameDataTracker Makefile - Docker multi-platform build

# Platform detection
UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)
ifeq ($(UNAME_S),Windows_NT)
    PLATFORM := Windows
else ifeq ($(UNAME_S),Darwin)
    PLATFORM := Darwin
    LLVM_DIR := $(shell brew --prefix llvm 2>/dev/null || echo /opt/homebrew/opt/llvm)
    LLD_LINK := $(shell which lld-link 2>/dev/null || echo /opt/homebrew/bin/lld-link)
    XWIN_DIR := $(HOME)/.xwin
else ifeq ($(UNAME_S),Linux)
    PLATFORM := Linux
    LLVM_DIR := /usr/lib/llvm-15
    LLD_LINK := $(shell which lld-link 2>/dev/null || echo lld-link)
    XWIN_DIR := $(HOME)/.xwin
else
    PLATFORM := Windows
endif

.PHONY: build build-windows build-all build-clean clean check-docker local

check-docker:
	@which docker > /dev/null || (printf "\n[!] Docker is not installed or not in PATH\n\n" && \
	printf "    Install Docker:\n" && \
	printf "    ▪ macOS:   https://docs.docker.com/desktop/install/mac-install/\n" && \
	printf "    ▪ Linux:   https://docs.docker.com/engine/install/\n" && \
	printf "    ▪ Windows: https://docs.docker.com/desktop/install/windows-install/\n\n" && \
	exit 1)
	@docker info > /dev/null 2>&1 || ( \
		printf "\n[!] Docker is not running\n\n"; \
		if [ "$$(uname -s)" = "Darwin" ]; then \
			printf "    Starting Docker Desktop...\n"; \
			open -a Docker && sleep 5 && \
			(docker info > /dev/null 2>&1 && printf "    [✓] Docker started successfully\n\n" || \
			(printf "    [!] Failed to start Docker Desktop\n" && \
			printf "    Please start it manually from Applications\n\n" && exit 1)); \
		else \
			printf "    Linux: sudo systemctl start docker\n"; \
			printf "    Windows: Start Docker Desktop\n\n"; \
			exit 1; \
		fi \
	)

build: check-docker
	@printf "[*] Building all platforms via Docker multi-stage build...\n"
	@docker build -f docker/Dockerfile --target artifacts -t gdt-all-artifacts .
	@printf "[*] Extracting binaries...\n"
	@docker create --name gdt-all-extract gdt-all-artifacts
	@mkdir -p release
	@docker cp gdt-all-extract:/gdt64-linux-x64.so release/
	@docker cp gdt-all-extract:/gdt64-linux-arm64.so release/
	@docker cp gdt-all-extract:/gdt64-macos-arm64.dylib release/
	@docker cp gdt-all-extract:/gdt64-macos-x64.dylib release/
	@docker rm gdt-all-extract
	@docker rmi gdt-all-artifacts
	@printf "\n[*] ========================================\n"
	@printf "[+] All platforms built successfully!\n"
	@printf "\n"
	@printf "    Linux x64:   release/gdt64-linux-x64.so\n"
	@printf "    Linux ARM64: release/gdt64-linux-arm64.so\n"
	@printf "    macOS ARM64: release/gdt64-macos-arm64.dylib\n"
	@printf "    macOS x64:   release/gdt64-macos-x64.dylib\n"
	@printf "\n"
	@printf "    Note: For Windows, use ida-win-build with Clang MSVC ABI\n"
	@printf "\n"

build-windows:
ifeq ($(PLATFORM),Windows)
	@printf "[*] Building Windows x64 (native build)...\n"
	@printf "[!] Native Windows build not yet implemented\n"
	@printf "    Use MSVC or Clang-cl manually, or build from macOS/Linux\n"
	@exit 1
else
	@printf "[*] Building Windows x64 (cross-compile from $(PLATFORM))...\n"
	@if [ ! -d "$(LLVM_DIR)" ]; then \
		printf "\n[!] LLVM not found at $(LLVM_DIR)\n"; \
		printf "    macOS: brew install llvm\n"; \
		printf "    Linux: apt install clang lld\n\n"; \
		exit 1; \
	fi
	@if [ ! -d "$(XWIN_DIR)" ]; then \
		printf "\n[!] xwin not found at $(XWIN_DIR)\n"; \
		printf "    Install: cargo install xwin\n"; \
		printf "    Setup:   xwin --accept-license splat --output ~/.xwin\n\n"; \
		exit 1; \
	fi
	@mkdir -p obj release
	@printf "    Compiling source files...\n"
	@for src in src/*.cpp; do \
		obj_name="obj/$$(basename $${src%.*}).obj"; \
		printf "      $$src\n"; \
		$(LLVM_DIR)/bin/clang-cl \
			--target=x86_64-pc-windows-msvc \
			/EHsc /O2 /std:c++17 \
			-Isdk/src/include -Iinclude \
			-D__NT__ -D__EA64__ -DUSE_STANDARD_FILE_FUNCTIONS -D_CRT_SECURE_NO_WARNINGS \
			-Wno-microsoft-include \
			-Wno-unused-command-line-argument \
			-Wno-nontrivial-memcall \
			-Wno-nullability-completeness \
			-Wno-varargs \
			"/Fo$$obj_name" \
			-c "$$src" \
			-imsvc "$(XWIN_DIR)/crt/include" \
			-imsvc "$(XWIN_DIR)/sdk/include/ucrt" \
			-imsvc "$(XWIN_DIR)/sdk/include/um" \
			-imsvc "$(XWIN_DIR)/sdk/include/shared" \
			2>&1 | grep -v "^clang-cl: warning:" || true; \
	done
	@printf "    Linking: gdt64-windows-x64.dll\n"
	@$(LLD_LINK) \
		/DLL \
		/NOIMPLIB \
		/OUT:release/gdt64-windows-x64.dll \
		/LIBPATH:sdk/src/lib/x64_win_vc_64 \
		/LIBPATH:$(XWIN_DIR)/crt/lib/x86_64 \
		/LIBPATH:$(XWIN_DIR)/sdk/lib/um/x86_64 \
		/LIBPATH:$(XWIN_DIR)/sdk/lib/ucrt/x86_64 \
		obj/*.obj \
		ida.lib \
		/NOLOGO
	@printf "[+] Windows x64: release/gdt64-windows-x64.dll\n"
endif

build-all: clean build build-windows
	@printf "\n[*] ========================================\n"
	@printf "[+] ALL PLATFORMS BUILT SUCCESSFULLY!\n"
	@printf "\n"
	@printf "    Linux x64:    release/gdt64-linux-x64.so\n"
	@printf "    Linux ARM64:  release/gdt64-linux-arm64.so\n"
	@printf "    macOS ARM64:  release/gdt64-macos-arm64.dylib\n"
	@printf "    macOS x64:    release/gdt64-macos-x64.dylib\n"
	@printf "    Windows x64:  release/gdt64-windows-x64.dll\n"
	@printf "\n"
	@printf "    Total: 5 platforms, ready for release!\n"
	@printf "\n"

clean:
	@printf "[*] Cleaning build artifacts...\n"
	@rm -rf release/* obj/*
	@printf "[+] Cleaned: release/ and obj/\n"

build-clean:
	@printf "[*] Cleaning Docker artifacts...\n"
	@docker rm -f gdt-all-extract 2>/dev/null || true
	@docker rmi gdt-all-artifacts 2>/dev/null || true
	@printf "[*] Docker cleanup complete\n"

# ===================================================
# LOCAL macOS ARM64 BUILD (FAST, NO DOCKER)
# Usage: make local
# ===================================================
local:
	@printf "\n[*] Building GameDataTracker for macOS ARM64...\n"
	@mkdir -p release
	@clang++ -std=c++17 -O2 -fPIC -shared \
		-Wno-nullability-completeness \
		-Wno-varargs \
		-I./sdk/src/include \
		-I./include \
		-DUSE_STANDARD_FILE_FUNCTIONS \
		-D__MAC__ \
		-D__EA64__ \
		-L./sdk/src/lib/arm64_mac_clang_64 \
		-lida -lidalib \
		-o release/gdt64-macos-arm64.dylib \
		src/gamedata_tracker.cpp 2>&1 | grep -E "(error:|ld:)" || true
	@printf "[✓] Compiled: release/gdt64-macos-arm64.dylib\n"
	@cp -f release/gdt64-macos-arm64.dylib "/Applications/IDA Professional 9.2.app/Contents/MacOS/plugins/gdt64-macos-arm64.dylib"
	@printf "[✓] Installed: /Applications/IDA Professional 9.2.app/.../plugins/gdt64-macos-arm64.dylib\n"
	@printf "\n✅ Done! Restart IDA to load the new build.\n\n"
