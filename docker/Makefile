# Internal Makefile for Docker builds

# Platform detection (via env vars in Docker, uname for native)
PLATFORM ?= $(shell uname -s)

# C++17 required for IDA SDK
USE_COMPILER   := g++
COMPILER_FLAGS := -O2 -std=c++17 -Wreturn-type
LINKER_FLAGS   :=

OBJ_DIR        := obj/
CPP_FILES      := $(wildcard ./src/*.cpp)

# Platform-specific settings
ifeq ($(PLATFORM),Linux)
    # Linux - GCC
    USE_COMPILER   := g++
    COMPILER_FLAGS += -Wno-varargs
    COMPILER_FLAGS += -Isdk/src/include -Iinclude
    COMPILER_FLAGS += -fPIC
    COMPILER_FLAGS += -D__LINUX__ -D__EA64__ -DUSE_STANDARD_FILE_FUNCTIONS
    LINKER_FLAGS   := -shared
    RELEASE_NAME   := gdt64.so

else ifeq ($(PLATFORM),Darwin)
    # macOS - Clang via osxcross
    ARCH           ?= arm64
    ifeq ($(ARCH),x86_64)
        USE_COMPILER   := o64-clang++
        COMPILER_FLAGS += -Wno-nullability-completeness -Wno-varargs
        COMPILER_FLAGS += -Isdk/src/include -Iinclude
        COMPILER_FLAGS += -D__MAC__ -D__EA64__ -DUSE_STANDARD_FILE_FUNCTIONS
        COMPILER_FLAGS += -mmacosx-version-min=12.0
        COMPILER_FLAGS += -Lsdk/src/lib/x64_mac_clang_64
        RELEASE_NAME   := gdt64-macos-x64.dylib
    else
        USE_COMPILER   := oa64-clang++
        COMPILER_FLAGS += -Wno-nullability-completeness -Wno-varargs
        COMPILER_FLAGS += -Isdk/src/include -Iinclude
        COMPILER_FLAGS += -D__MAC__ -D__EA64__ -DUSE_STANDARD_FILE_FUNCTIONS
        COMPILER_FLAGS += -mmacosx-version-min=12.0
        COMPILER_FLAGS += -Lsdk/src/lib/arm64_mac_clang_64
        RELEASE_NAME   := gdt64-macos-arm64.dylib
    endif
    LINKER_FLAGS   := -dynamiclib -undefined dynamic_lookup -lida

else ifeq ($(PLATFORM),Windows)
    # Windows - Clang with MSVC ABI via xwin
    USE_COMPILER   := clang-cl
    COMPILER_FLAGS := /O2 /std:c++17 /EHsc /W3
    COMPILER_FLAGS += /Isdk/src/include /Iinclude
    COMPILER_FLAGS += /D__NT__ /D__EA64__ /D_WIN64 /DUSE_STANDARD_FILE_FUNCTIONS /D_CRT_SECURE_NO_WARNINGS
    LINKER_FLAGS   := /link /DLL /LIBPATH:sdk/src/lib/x64_win_vc_64 ida.lib
    RELEASE_NAME   := gdt64.dll

else
    $(error Unknown platform: $(PLATFORM))
endif

.PHONY: all clean

all:
	@mkdir -p $(OBJ_DIR)
	@echo "Building for $(PLATFORM) with $(USE_COMPILER)..."
	@count=0; \
	obj_files=""; \
	for file in $(CPP_FILES); do \
	  echo "  Compiling: $$file"; \
	  $(USE_COMPILER) $$file -c -o $(OBJ_DIR)$$count.o $(COMPILER_FLAGS); \
	  obj_files="$$obj_files $(OBJ_DIR)$$count.o"; \
	  count=$$((count + 1)); \
	done; \
	mkdir -p release; \
	echo "  Linking: $(RELEASE_NAME)"; \
	$(USE_COMPILER) -o release/$(RELEASE_NAME) $(COMPILER_FLAGS) $$obj_files $(LINKER_FLAGS)
	@echo "Done: release/$(RELEASE_NAME)"

clean:
	@rm -rf $(OBJ_DIR) release/
