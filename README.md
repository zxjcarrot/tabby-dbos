# Tabby

Code for DB-OS co-designed buffer manager described in "Practical DB-OS Co-Design with Privileged DB Process".
The code is based on [vmcache](https://github.com/viktorleis/vmcache).

## Environment Variables

* BLOCK: storage file (e.g. /mnt/nvme0n1/datafile); default=/tmp/bm
* VIRTGB: virtual memory allocation in GB (e.g., 1024), should be at least device size; default=16
* PHYSGB: physical memory allocation in GB = buffer pool size, should be less than available RAM; default=4
* BATCH: batch size for eviction in pages; default=64
* RUNFOR: benchmark run duration in seconds; default=30
* RNDREAD: if non-negative, run random read benchmark, otherwise TPC-C; default=0
* THREADS: number of threads; default=1
* DATASIZE: number of warehouses for TPC-C, number of tuples for random read benchmark; default=10

## Example Command Lines

* TPC-C, 4 threads, 2 warehouses: `BLOCK=/mnt/nvme0n1/datafile THREADS=4 DATASIZE=2 ./tabby`
* random read, 10 threads, 1 million tuples: `BLOCK=/mnt/nvme0n1/datafile THREADS=10 DATASIZE=1e6 ./tabby`

## Dependencies and Configuration

* libaio: We need the libaio library. On Ubuntu: `sudo apt install libaio-dev`. On CentOS: `sudo yum install -y libaio-devel.x86_64`
You will probably also need to set `vm.overcommit_memory = 1` in `/etc/sysctl.conf`. Otherwise larger values of VIRTGB will not work.
* libdbos/libdune: We need the libdbos and dune kernel module library. See [README](../../README.md) of libdbos/libdune for instructions.

## Low-Hanging Fruit (TODO)

* use C++ wait/notify to handle lock contention instead of spinning
* implement free space management for storage
