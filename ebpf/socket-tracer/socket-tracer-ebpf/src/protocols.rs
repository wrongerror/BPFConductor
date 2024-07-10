use aya_ebpf::helpers::bpf_probe_read_user_buf;

use socket_tracer_common::{MessageType, ProtocolMessage, TrafficProtocol};

fn infer_http_message(buf: &[u8], count: usize) -> MessageType {
    if count < 16 {
        return MessageType::Unknown;
    }

    if &buf[0..4] == b"HTTP" {
        return MessageType::Response;
    }
    if &buf[0..3] == b"GET" || &buf[0..4] == b"HEAD" || &buf[0..4] == b"POST" {
        return MessageType::Request;
    }
    if &buf[0..3] == b"PUT" || &buf[0..6] == b"DELETE" {
        return MessageType::Request;
    }

    MessageType::Unknown
}

pub fn infer_protocol(buf: *const u8, count: usize) -> ProtocolMessage {
    let mut inferred_message = ProtocolMessage {
        protocol: TrafficProtocol::Unknown,
        msg_type: MessageType::Unknown,
    };

    if buf.is_null() || count == 0 {
        return inferred_message;
    }

    let mut kernel_buf = [0u8; 16];
    let read_len = count.min(kernel_buf.len());

    if unsafe { bpf_probe_read_user_buf(buf, &mut kernel_buf[..read_len]) }.is_err() {
        return inferred_message;
    }

    let buf = &kernel_buf[..read_len];
    match infer_http_message(buf, count) {
        MessageType::Unknown => {}
        msg_type => {
            inferred_message.msg_type = msg_type;
            inferred_message.protocol = TrafficProtocol::HTTP;
        }
    }

    inferred_message
}
