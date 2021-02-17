#!/usr/bin/env sh

set -e

LIBBPF_DIR=$1
OUTPUT_DIR=$2

if test -z "$LIBBPF_DIR"; then
    echo "error: no libbpf dir provided"
    exit 1
fi

if test -z "$OUTPUT_DIR"; then
    echo "error: no output dir provided"
    exit 1
fi

BPF_TYPES="\
    bpf_cmd \
    bpf_insn \
    bpf_attr \
    bpf_map_type \
    bpf_prog_type \
    bpf_attach_type
    "

BPF_VARS="\
    BPF_PSEUDO_.*
    BPF_ALU \
    BPF_ALU64 \
    BPF_LDX \
    BPF_ST \
    BPF_STX \
    BPF_LD \
    BPF_K \
    BPF_DW \
    BPF_W \
    BPF_H \
    BPF_B \
    SO_ATTACH_BPF \
    SO_DETACH_BPF
    "

BTF_TYPES="\
    btf_header \
    btf_ext_header \
    btf_ext_info \
    btf_ext_info_sec \
    bpf_core_relo \
    bpf_core_relo_kind \
    btf_type \
    btf_enum \
    btf_array \
    btf_member \
    btf_param \
    btf_var \
    btf_var_secinfo
    "

BTF_VARS="\
    BTF_KIND_.*
    BTF_INT_.*
    "

PERF_TYPES="\
    perf_event_attr \
    perf_sw_ids \
    perf_event_sample_format \
    perf_event_mmap_page \
    perf_event_header \
    perf_type_id \
    perf_event_type
    "

PERF_VARS="\
    PERF_FLAG_.* \
    PERF_EVENT_.*
    "

NETLINK_TYPES="\
    ifinfomsg
    "

NETLINK_VARS="\
    NLMSG_ALIGNTO \
    IFLA_XDP_FD \
    XDP_FLAGS_.*
    "

LINUX_TYPES="$BPF_TYPES $BTF_TYPES $PERF_TYPES $NETLINK_TYPES"
LINUX_VARS="$BPF_VARS $BTF_VARS $PERF_VARS $NETLINK_VARS"

bindgen $LIBBPF_DIR/src/libbpf_internal.h \
    --no-layout-tests \
    --default-enum-style moduleconsts \
    $(for ty in $BTF_TYPES; do
        echo --whitelist-type "$ty"
    done) \
    $(for var in $BTF_VARS; do
        echo --whitelist-var "$var"
    done) \
    > $OUTPUT_DIR/btf_internal_bindings.rs

KVER=5.10.0-051000

bindgen aya/include/linux_wrapper.h \
    --no-layout-tests \
    --default-enum-style moduleconsts \
    $(for ty in $LINUX_TYPES; do
        echo --whitelist-type "$ty"
    done) \
    $(for var in $LINUX_VARS; do
        echo --whitelist-var "$var"
    done) \
    -- \
    -target x86_64 \
    -I $LIBBPF_DIR/include/uapi \
    -I $LIBBPF_DIR/include/ \
    -I /usr/include/x86_64-linux-gnu \
    > $OUTPUT_DIR/linux_bindings_x86_64.rs

# requires libc6-dev-arm64-cross
bindgen aya/include/linux_wrapper.h \
    --no-layout-tests \
    --default-enum-style moduleconsts \
    $(for ty in $LINUX_TYPES; do
        echo --whitelist-type "$ty"
    done) \
    $(for var in $LINUX_VARS; do
        echo --whitelist-var "$var"
    done) \
    -- \
    -target arm64 \
    -I $LIBBPF_DIR/include/uapi \
    -I $LIBBPF_DIR/include/ \
    -I /usr/aarch64-linux-gnu/include \
    > $OUTPUT_DIR/linux_bindings_aarch64.rs