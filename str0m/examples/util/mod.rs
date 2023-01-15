use std::net::IpAddr;
use systemstat::{Platform, System};

pub fn select_host_address() -> IpAddr {
    let system = System::new();
    let networks = system.networks().unwrap();

    for net in networks.values() {
        for n in &net.addrs {
            match n.addr {
                systemstat::IpAddr::V4(v) => {
                    if !v.is_loopback() && !v.is_link_local() && !v.is_broadcast() {
                        return IpAddr::V4(v);
                    }
                }
                _ => {} // we could use ipv6 too
            }
        }
    }

    panic!("Found no usable network interface");
}
