#![feature(local_key_cell_methods)]
use std::cell::Cell;
use std::io::{self, BufReader, Read};
use std::net::TcpStream;
use std::time::Duration;

const RP_ADDR: &str = "192.168.188.20:8900";

const LINE_SAMPLE_COUNT: usize = 813;

const NEWLINE_BLANK_SAMPLE_COUNT: usize = LINE_SAMPLE_COUNT * 2 / 3;

const PIXELS: (u32, u32) = (384, 288);
const BLANK_COUNTS: (u32, u32) = (0, 15);

const VBLANK_AVG: u8 = 0xc4;
const VBLANK_TOLERANCE: u8 = 20;

const HI_VOLTAGE: u8 = 0x7f;
const HI_TOLERANCE: u8 = 10;

const LO_VOLTAGE: u8 = 0x08;
const LO_TOLERANCE: u8 = 20;

struct RPReader<R> {
    rdr: R,
    left: usize,
}

impl<R> RPReader<R> {
    fn new(rdr: R) -> Self {
        Self { rdr, left: 0 }
    }
}

impl<R: std::io::Read> std::io::Read for RPReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.left == 0 {
            let mut header = [0u32; 15];
            self.rdr.read_exact(bytemuck::bytes_of_mut(&mut header))?;
            debug_assert_eq!(bytemuck::bytes_of(&header[0]), b"STRE");
            debug_assert_eq!(bytemuck::bytes_of(&header[1]), b"AMpa");
            debug_assert_eq!(bytemuck::bytes_of(&header[2]), b"ckID");
            debug_assert_eq!(bytemuck::bytes_of(&header[3]), b"v1.0");
            let id = u32::from_le_bytes(header[4].to_ne_bytes());
            // dbg!(id);
            let idk0 = u32::from_le_bytes(header[5].to_ne_bytes());
            // dbg!(idk0);
            let idk1 = u32::from_le_bytes(header[6].to_ne_bytes());
            let idk2 = u32::from_le_bytes(header[7].to_ne_bytes());
            // dbg!(idk2);
            // bit depth?
            let bitdepth = header[8];
            // dbg!(bitdepth);
            let packet_size = header[9];
            // dbg!(packet_size);
            let size = header[10];
            // dbg!(size);
            // adc mode?
            let adc_mode = header[12];
            // dbg!(adc_mode);
            let channel = header[13];
            // dbg!(channel);

            if idk1 != 0 {
                // dbg!(idk1);
                // eprint!("a");

                let line_idx = LINE_IDX.get();
                let line_idx = ((line_idx + idk1 as usize / LINE_SAMPLE_COUNT)
                    % (PIXELS.1 + BLANK_COUNTS.1) as usize)
                    + 1;
                LINE_IDX.set(if line_idx > PIXELS.1 as usize {
                    0
                } else {
                    line_idx
                });
                WAIT_FOR_NEXT.set(true);
            }

            self.left = u32::from_le_bytes(header[10].to_ne_bytes()) as usize;
            // eprintln!("frame with {} bytes", self.left);
        }

        let len = if self.left <= buf.len() {
            self.left
        } else {
            buf.len()
        };

        let read = self.rdr.read(&mut buf[..len])?;
        self.left -= read;
        Ok(read)
    }
}

thread_local! {
    static LINE_IDX: Cell<usize> = Cell::new(0);
    static WAIT_FOR_NEXT: Cell<bool> = Cell::new(true);
}

fn main() {
    let framebuffers = linuxfb::Framebuffer::list().expect("couldn't read framebuffer list");
    let mut fb = linuxfb::Framebuffer::new(framebuffers.get(0).expect("no framebuffers found"))
        .expect("failed to open framebuffer (try running as sudo?)");
    let (w, h) = fb.get_size();
    let (w, h) = (w.max(PIXELS.0), h.max(PIXELS.1));
    fb.set_virtual_size(w, h)
        .expect("failed to change virtual fb size");
    let bytes_per_pixel = fb.get_bytes_per_pixel() as usize;
    eprintln!("using fb size {:?}", (w, h));
    eprintln!("rendering to  {:?}", (w, PIXELS.1));

    let mut fb_map = fb.map().expect("failed to mmap the framebuffer");

    let mut sock = RPReader::new(BufReader::new(TcpStream::connect(RP_ADDR).unwrap()));

    eprintln!("connected to stream");

    const LINE_DURATION: Duration =
        Duration::from_nanos(1_000_000_000u64 / (PIXELS.1 as u64 + 24) / 50);

    let mut time = std::time::Instant::now();
    while moving_average_then_spike::<23, 3>(&mut sock, &mut fb_map, w, PIXELS.1, bytes_per_pixel)
        .is_ok()
    {
        let now = std::time::Instant::now();
        if let Some(extra_delay) = LINE_DURATION.checked_sub(now.duration_since(time)) {
            std::thread::sleep(extra_delay);
        }
        time = now;
    }
}

fn moving_average_then_spike<const N: usize, const NB: usize>(
    rdr: &mut impl Read,
    fb_map: &mut memmap::MmapMut,
    w: u32,
    h: u32,
    bytes_per_pixel: usize,
) -> io::Result<()> {
    MovingAverage::<N, NB>::new(rdr)?.read_until(rdr, fb_map, w, h, bytes_per_pixel)
}

struct MovingAverage<const N: usize, const NONBLANK: usize> {
    ringbuf: [u8; N],
    avg: u32,
    avg_nb: u32,
    index: usize,
}

impl<const N: usize, const NB: usize> MovingAverage<N, NB> {
    fn new(rdr: &mut impl Read) -> io::Result<Self> {
        let mut ringbuf = [0; N];
        rdr.read_exact(&mut ringbuf).unwrap();
        let avg = ringbuf[..N - NB].iter().map(|a| *a as u32).sum();
        let avg_nb = ringbuf[N - NB..N].iter().map(|a| *a as u32).sum();
        debug_assert!(N > NB);
        Ok(Self {
            ringbuf,
            avg,
            avg_nb,
            index: N - NB,
        })
    }
    fn read_until(
        mut self,
        rdr: &mut impl Read,
        fb_map: &mut memmap::MmapMut,
        w: u32,
        h: u32,
        bytes_per_pixel: usize,
    ) -> io::Result<()> {
        while !(self
            .avg
            .abs_diff((N as u32 - NB as u32) * (VBLANK_AVG as u32))
            < (N as u32 - NB as u32) * VBLANK_TOLERANCE as u32
            && (self.avg_nb.abs_diff((NB as u32) * (LO_VOLTAGE as u32)))
                < NB as u32 * LO_TOLERANCE as u32)
            && { check_not_cutoff::<N, NB>(&self.ringbuf, self.index) }
        {
            let idx = (self.index + NB) % N;
            self.avg -= self.ringbuf[idx] as u32;
            let idx_nb = self.index % N;
            self.avg += self.ringbuf[idx_nb] as u32;
            self.avg_nb -= self.ringbuf[idx_nb] as u32;
            rdr.read_exact(&mut self.ringbuf[idx..=idx])?;
            self.avg_nb += self.ringbuf[idx] as u32;
            self.index += 1;
            // eprintln!("{:?}", (self.index, self.avg, self.avg_nb, self.ringbuf));
        }
        // eprintln!("{}", self.index);
        let mut line_buf = [0; LINE_SAMPLE_COUNT];
        assert!(LINE_SAMPLE_COUNT >= NB);
        #[allow(clippy::needless_range_loop)]
        for i in 0..NB {
            line_buf[i] = self.ringbuf[(self.index + i) % N];
        }
        rdr.read_exact(&mut line_buf[NB..])?;

        let line_idx = if self.index >= NEWLINE_BLANK_SAMPLE_COUNT {
            if WAIT_FOR_NEXT.get() {
                WAIT_FOR_NEXT.set(false);
            }
            0
        } else {
            if WAIT_FOR_NEXT.get() {
                return Ok(());
            }
            LINE_IDX.get() + 1
        };
        LINE_IDX.set(line_idx);

        if line_idx >= h as usize {
            return Ok(());
        }
        let offset = line_idx * w as usize * bytes_per_pixel;

        #[allow(clippy::bool_to_int_with_if)]
        const MIDDLE_OFFSET: usize = {
            let samples_per_pixel = PIXELS.0 as f32 / LINE_SAMPLE_COUNT as f32;
            samples_per_pixel as usize
                + (samples_per_pixel - samples_per_pixel as usize as f32 > 0.8) as usize
        };

        for i in 0..PIXELS.0 as usize {
            let value = line_buf[(MIDDLE_OFFSET + LINE_SAMPLE_COUNT * i) / PIXELS.0 as usize];
            let val = if (HI_VOLTAGE - value) < HI_TOLERANCE {
                0xff
            } else {
                0x00
            };
            for bo in 0..bytes_per_pixel {
                fb_map[offset + i * bytes_per_pixel + bo] = val;
            }
        }
        Ok(())
    }
}

fn check_not_cutoff<const N: usize, const NB: usize>(ringbuf: &[u8; N], idx: usize) -> bool {
    assert!(N > NB);
    let mut diff = 0;
    for i in 0..N - NB {
        if ringbuf[(idx + i + NB) % N].abs_diff(VBLANK_AVG) >= VBLANK_TOLERANCE {
            diff += 1;
        }
    }
    diff < N / 2
}
