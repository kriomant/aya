//! An array of available CPUs.

use std::os::fd::AsRawFd;

use aya_obj::generated::{bpf_cpumap_val, bpf_cpumap_val__bindgen_ty_1};

use crate::{
    maps::{check_bounds, check_kv_size, IterableMap, MapData, MapError},
    programs::ProgramFd,
    sys::{bpf_map_lookup_elem, bpf_map_update_elem},
    Pod,
};

/// An array of available CPUs.
///
/// XDP programs can use this map to redirect packets to a target
/// CPU for processing.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.15.
///
/// # Examples
/// ```no_run
/// # let elf_bytes = &[];
/// use aya::maps::xdp::CpuMap;
///
/// let mut bpf = aya::BpfLoader::new()
///     .set_max_entries("CPUS", aya::util::nr_cpus().unwrap() as u32)
///     .load(elf_bytes)
///     .unwrap();
/// let mut cpumap = CpuMap::try_from(bpf.map_mut("CPUS").unwrap())?;
/// let flags = 0;
/// let queue_size = 2048;
/// for i in 0u32..8u32 {
///     cpumap.set(i, queue_size, None, flags);
/// }
///
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_CPUMAP")]
pub struct CpuMap<T> {
    inner: T,
}

impl<T: AsRef<MapData>> CpuMap<T> {
    pub(crate) fn new(map: T) -> Result<CpuMap<T>, MapError> {
        let data = map.as_ref();
        check_kv_size::<u32, bpf_cpumap_val>(data)?;

        let _fd = data.fd_or_err()?;

        Ok(CpuMap { inner: map })
    }

    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.inner.as_ref().obj.max_entries()
    }

    /// Returns the queue size and possible program for a given CPU index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `cpu_index` is out of bounds,
    /// [`MapError::SyscallError`] if `bpf_map_lookup_elem` fails.
    pub fn get(&self, cpu_index: u32, flags: u64) -> Result<CpuMapValue, MapError> {
        let data = self.inner.as_ref();
        check_bounds(data, cpu_index)?;
        let fd = data.fd_or_err()?;

        let value = bpf_map_lookup_elem(fd, &cpu_index, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                io_error,
            }
        })?;
        let value: bpf_cpumap_val = value.ok_or(MapError::KeyNotFound)?;

        // SAFETY: map writes use fd, map reads use id.
        // https://elixir.bootlin.com/linux/v6.2/source/include/uapi/linux/bpf.h#L6149
        Ok(CpuMapValue {
            qsize: value.qsize,
            prog_id: unsafe { value.bpf_prog.id },
        })
    }

    /// An iterator over the elements of the map. The iterator item type is `Result<u32,
    /// MapError>`.
    pub fn iter(&self) -> impl Iterator<Item = Result<CpuMapValue, MapError>> + '_ {
        (0..self.len()).map(move |i| self.get(i, 0))
    }
}

impl<T: AsMut<MapData>> CpuMap<T> {
    /// Sets the queue size at the given CPU index, and optionally a chained program.
    ///
    /// When sending the packet to the CPU at the given index, the kernel will queue up to
    /// `queue_size` packets before dropping them.
    ///
    /// Another XDP program can be passed in that will be run on the target CPU, instead of the CPU
    /// that receives the packets. This allows to perform minimal computations on CPUs that
    /// directly handle packets from a NIC's RX queues, and perform possibly heavier ones in other,
    /// less busy CPUs.
    ///
    /// Note that only XDP programs with the `map = "cpumap"` argument can be passed. See the
    /// kernel-space `aya_bpf::xdp` for more information.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set(
        &mut self,
        cpu_index: u32,
        queue_size: u32,
        program: Option<ProgramFd>,
        flags: u64,
    ) -> Result<(), MapError> {
        let data = self.inner.as_mut();
        check_bounds(data, cpu_index)?;
        let fd = data.fd_or_err()?;

        let value = bpf_cpumap_val {
            qsize: queue_size,
            bpf_prog: bpf_cpumap_val__bindgen_ty_1 {
                fd: program.map(|prog| prog.as_raw_fd()).unwrap_or_default(),
            },
        };
        bpf_map_update_elem(fd, Some(&cpu_index), &value, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                io_error,
            }
        })?;
        Ok(())
    }
}

impl<T: AsRef<MapData>> IterableMap<u32, CpuMapValue> for CpuMap<T> {
    fn map(&self) -> &MapData {
        self.inner.as_ref()
    }

    fn get(&self, key: &u32) -> Result<CpuMapValue, MapError> {
        self.get(*key, 0)
    }
}

unsafe impl Pod for bpf_cpumap_val {}

#[derive(Clone, Copy, Debug)]
pub struct CpuMapValue {
    pub qsize: u32,
    pub prog_id: u32,
}