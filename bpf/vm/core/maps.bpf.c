/* The VM's shared state, as its own compile unit: this is the one place that
 * DEFINES the maps and counter globals (PFW_MAPS_DEFINE). Every program unit
 * (entry/, decode/) references them `extern` via core/maps.h, and the BPF static
 * linker resolves the references against the definitions here.
 *
 * It must be linked before the units that reference the externs — `bpftool gen
 * object` only back-patches extern map/global symbols when their definition is
 * seen first. It is: build/bpf.mk sorts the unit list and `core/` sorts ahead of
 * `decode/` and `entry/`, so this object is always first. A data-only unit (no
 * programs) is fine; the license lives with the entry program.
 */
#define PFW_MAPS_DEFINE
#include "core/common.h"
#include "core/maps.h"
