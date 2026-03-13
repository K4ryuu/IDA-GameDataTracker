# Multi-platform build - all targets in one container
FROM --platform=linux/amd64 ubuntu:24.04 AS base

RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    clang \
    cmake \
    git \
    make \
    wget \
    libssl-dev \
    lzma-dev \
    libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY src/ ./src/
COPY sdk/ ./sdk/
COPY include/ ./include/
COPY docker/Makefile ./Makefile

# ============================================
# Linux x64 build
# ============================================
FROM base AS linux-build
ENV PLATFORM=Linux
RUN make && \
    mkdir -p /output && \
    cp release/*.so /output/gdt64-linux-x64.so

# ============================================
# Linux ARM64 build
# ============================================
FROM --platform=linux/arm64 ubuntu:24.04 AS linux-arm64-build

RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY src/ ./src/
COPY sdk/ ./sdk/
COPY include/ ./include/
COPY docker/Makefile ./Makefile

ENV PLATFORM=Linux
RUN make && \
    mkdir -p /output && \
    cp release/*.so /output/gdt64-linux-arm64.so

# ============================================
# macOS osxcross - use pre-built image
# ============================================
FROM --platform=linux/amd64 crazymax/osxcross:latest-ubuntu AS osxcross

# ============================================
# macOS ARM64 build
# ============================================
FROM base AS macos-arm64-build
ENV PATH="/osxcross/bin:$PATH"
ENV LD_LIBRARY_PATH="/osxcross/lib"
ENV PLATFORM=Darwin
ENV ARCH=arm64
WORKDIR /build
COPY src/ ./src/
COPY sdk/ ./sdk/
COPY include/ ./include/
COPY docker/Makefile ./Makefile
RUN --mount=type=bind,from=osxcross,source=/osxcross,target=/osxcross \
    make && \
    mkdir -p /output && \
    cp release/*.dylib /output/gdt64-macos-arm64.dylib

# ============================================
# macOS Intel x64 build
# ============================================
FROM base AS macos-x64-build
ENV PATH="/osxcross/bin:$PATH"
ENV LD_LIBRARY_PATH="/osxcross/lib"
ENV PLATFORM=Darwin
ENV ARCH=x86_64
WORKDIR /build
COPY src/ ./src/
COPY sdk/ ./sdk/
COPY include/ ./include/
COPY docker/Makefile ./Makefile
RUN --mount=type=bind,from=osxcross,source=/osxcross,target=/osxcross \
    make && \
    mkdir -p /output && \
    cp release/*.dylib /output/gdt64-macos-x64.dylib

# ============================================
# Final stage - collect all artifacts
# ============================================
FROM alpine:latest AS artifacts
COPY --from=linux-build /output/gdt64-linux-x64.so /
COPY --from=linux-arm64-build /output/gdt64-linux-arm64.so /
COPY --from=macos-arm64-build /output/gdt64-macos-arm64.dylib /
COPY --from=macos-x64-build /output/gdt64-macos-x64.dylib /
CMD ["/bin/sh"]
