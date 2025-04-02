#ifndef _HELPERS_NETWORK_RAW_H_
#define _HELPERS_NETWORK_RAW_H_

#include "maps.h"

__attribute__((always_inline)) struct raw_packet_event_t *get_raw_packet_event() {
    u32 key = 0;
    union union_heap_t* uh = bpf_map_lookup_elem(&union_heap, &key);
    return &uh->raw_packet_event;
}

#endif
