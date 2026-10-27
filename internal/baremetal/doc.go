// Package baremetal infers what a headerless flash dump does not state: ISA
// and endianness (by scoring SLEIGH decodes, as cpu_rec does), base address
// (by pointer and string alignment), Cortex-M vector tables, and peripheral
// names from CMSIS-SVD files.
package baremetal
