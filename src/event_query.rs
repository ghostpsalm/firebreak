//! Pull 5156/5157 events from the Security channel since a checkpoint, via
//! the modern EvtQuery API, rendered as XML and parsed with quick-xml.

#[cfg(not(windows))]
use anyhow::bail;
#[cfg(windows)]
use anyhow::Context;
use anyhow::Result;

use crate::model::EventRecord;

/// XPath filter for the Security channel. `since_iso` must be ISO8601 UTC
/// with milliseconds, e.g. 2026-07-15T00:00:00.000Z.
pub fn build_query(since_iso: Option<&str>) -> String {
    match since_iso {
        Some(ts) => format!(
            "*[System[(EventID=5156 or EventID=5157) and TimeCreated[@SystemTime>='{}']]]",
            ts
        ),
        None => "*[System[(EventID=5156 or EventID=5157)]]".to_string(),
    }
}

#[cfg(windows)]
pub fn query_events(since_iso: Option<&str>, mut on_event: impl FnMut(EventRecord)) -> Result<u64> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
    use windows::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtRender, EvtQueryChannelPath, EvtQueryForwardDirection,
        EvtRenderEventXml, EVT_HANDLE,
    };

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let channel = to_wide("Security");
    let query = to_wide(&build_query(since_iso));

    unsafe {
        let result_set: EVT_HANDLE = EvtQuery(
            None,
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            (EvtQueryChannelPath.0 | EvtQueryForwardDirection.0) as u32,
        )
        .context("EvtQuery on Security channel failed (needs elevation / Event Log Readers)")?;

        let mut total: u64 = 0;
        let mut render_buf: Vec<u16> = Vec::new();

        loop {
            // EvtNext hands back raw isize event handles in this binding
            let mut handles = [0isize; 64];
            let mut returned: u32 = 0;
            let next = EvtNext(result_set, &mut handles, 0, 0, &mut returned);
            if let Err(e) = next {
                let _ = EvtClose(result_set);
                if e.code() == windows::core::HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0) {
                    return Ok(total);
                }
                return Err(e).context("EvtNext failed");
            }
            for h in handles.iter().take(returned as usize) {
                let h = EVT_HANDLE(*h);
                let mut used: u32 = 0;
                let mut props: u32 = 0;
                // first call sizes the buffer
                let _ = EvtRender(
                    None,
                    h,
                    EvtRenderEventXml.0 as u32,
                    0,
                    None,
                    &mut used,
                    &mut props,
                );
                if used > 0 {
                    render_buf.resize((used as usize + 1) / 2 + 1, 0);
                    let cap_bytes = (render_buf.len() * 2) as u32;
                    if EvtRender(
                        None,
                        h,
                        EvtRenderEventXml.0 as u32,
                        cap_bytes,
                        Some(render_buf.as_mut_ptr() as *mut _),
                        &mut used,
                        &mut props,
                    )
                    .is_ok()
                    {
                        let xml = String::from_utf16_lossy(
                            &render_buf[..(used as usize / 2).saturating_sub(1)],
                        );
                        if let Some(ev) = parse_event_xml(&xml) {
                            total += 1;
                            on_event(ev);
                        }
                    }
                }
                let _ = EvtClose(h);
            }
        }
    }
}

#[cfg(not(windows))]
pub fn query_events(_since_iso: Option<&str>, _on_event: impl FnMut(EventRecord)) -> Result<u64> {
    bail!("event log query is only available on Windows")
}

/// Timestamp of the oldest surviving 5156/5157 event, for rollover
/// detection. None if the log holds no such events.
#[cfg(windows)]
pub fn first_event_time() -> Result<Option<String>> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
    use windows::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtRender, EvtQueryChannelPath, EvtQueryForwardDirection,
        EvtRenderEventXml, EVT_HANDLE,
    };

    let channel: Vec<u16> = "Security".encode_utf16().chain(std::iter::once(0)).collect();
    let query: Vec<u16> = build_query(None)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let result_set: EVT_HANDLE = EvtQuery(
            None,
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            (EvtQueryChannelPath.0 | EvtQueryForwardDirection.0) as u32,
        )
        .context("EvtQuery failed")?;

        let mut handles = [0isize; 1];
        let mut returned: u32 = 0;
        let next = EvtNext(result_set, &mut handles, 0, 0, &mut returned);
        if let Err(e) = next {
            let _ = EvtClose(result_set);
            if e.code() == windows::core::HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0) {
                return Ok(None);
            }
            return Err(e).context("EvtNext failed");
        }
        let mut out = None;
        if returned > 0 {
            let h = EVT_HANDLE(handles[0]);
            let mut used: u32 = 0;
            let mut props: u32 = 0;
            let _ = EvtRender(None, h, EvtRenderEventXml.0 as u32, 0, None, &mut used, &mut props);
            if used > 0 {
                let mut buf: Vec<u16> = vec![0; (used as usize + 1) / 2 + 1];
                let cap = (buf.len() * 2) as u32;
                if EvtRender(
                    None,
                    h,
                    EvtRenderEventXml.0 as u32,
                    cap,
                    Some(buf.as_mut_ptr() as *mut _),
                    &mut used,
                    &mut props,
                )
                .is_ok()
                {
                    let xml = String::from_utf16_lossy(&buf[..(used as usize / 2).saturating_sub(1)]);
                    out = parse_event_xml(&xml).map(|ev| ev.time_created);
                }
            }
            let _ = EvtClose(h);
        }
        let _ = EvtClose(result_set);
        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn first_event_time() -> Result<Option<String>> {
    bail!("event log query is only available on Windows")
}

/// Direction tokens in 5156/5157 EventData. VERIFY on a real box: expected
/// %%14592 = Inbound, %%14593 = Outbound.
fn decode_direction(raw: &str) -> String {
    match raw {
        "%%14592" => "Inbound".to_string(),
        "%%14593" => "Outbound".to_string(),
        other => other.to_string(),
    }
}

/// Parse one rendered event XML into an EventRecord. Returns None for
/// events that don't carry the fields we need.
pub fn parse_event_xml(xml: &str) -> Option<EventRecord> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut event_id: u32 = 0;
    let mut time_created = String::new();
    let mut current_data_name: Option<String> = None;
    let mut in_event_id = false;

    let mut filter_rtid: Option<u64> = None;
    let mut application = String::new();
    let mut direction = String::new();
    let mut protocol: u32 = 0;
    let mut dest_address = String::new();
    let mut dest_port = String::new();
    let mut source_address = String::new();
    let mut source_port = String::new();

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local = e.local_name();
                let tag = std::str::from_utf8(local.as_ref()).unwrap_or("");
                match tag {
                    "EventID" => in_event_id = true,
                    "TimeCreated" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"SystemTime" {
                                time_created =
                                    String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                    "Data" => {
                        current_data_name = None;
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"Name" {
                                current_data_name =
                                    Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(t)) => {
                let text = t.unescape().unwrap_or_default().to_string();
                if in_event_id {
                    event_id = text.parse().unwrap_or(0);
                } else if let Some(name) = &current_data_name {
                    match name.as_str() {
                        "FilterRTID" => filter_rtid = text.parse().ok(),
                        "Application" => application = text,
                        "Direction" => direction = decode_direction(&text),
                        "Protocol" => protocol = text.parse().unwrap_or(0),
                        "DestAddress" => dest_address = text,
                        "DestPort" => dest_port = text,
                        "SourceAddress" => source_address = text,
                        "SourcePort" => source_port = text,
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local = e.local_name();
                let tag = std::str::from_utf8(local.as_ref()).unwrap_or("");
                if tag == "EventID" {
                    in_event_id = false;
                } else if tag == "Data" {
                    current_data_name = None;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }

    let filter_rtid = filter_rtid?;
    if event_id != 5156 && event_id != 5157 {
        return None;
    }
    Some(EventRecord {
        event_id,
        time_created,
        filter_rtid,
        application,
        direction,
        protocol,
        dest_address,
        dest_port,
        source_address,
        source_port,
    })
}

#[allow(dead_code)]
pub fn protocol_name(proto: u32) -> &'static str {
    match proto {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
<EventID>5156</EventID><Version>1</Version><Level>0</Level><Task>12810</Task><Opcode>0</Opcode>
<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-07-15T10:11:12.123456700Z'/>
<EventRecordID>12345</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='88'/>
<Channel>Security</Channel><Computer>HOST</Computer><Security/></System>
<EventData><Data Name='ProcessID'>1234</Data>
<Data Name='Application'>\device\harddiskvolume3\windows\system32\svchost.exe</Data>
<Data Name='Direction'>%%14593</Data>
<Data Name='SourceAddress'>192.168.1.10</Data><Data Name='SourcePort'>53211</Data>
<Data Name='DestAddress'>142.250.66.46</Data><Data Name='DestPort'>443</Data>
<Data Name='Protocol'>6</Data>
<Data Name='FilterRTID'>67321</Data>
<Data Name='LayerName'>%%14611</Data><Data Name='LayerRTID'>48</Data>
<Data Name='RemoteUserID'>S-1-0-0</Data><Data Name='RemoteMachineID'>S-1-0-0</Data></EventData></Event>"#;

    #[test]
    fn parses_5156() {
        let ev = parse_event_xml(SAMPLE).expect("should parse");
        assert_eq!(ev.event_id, 5156);
        assert_eq!(ev.filter_rtid, 67321);
        assert_eq!(ev.direction, "Outbound");
        assert_eq!(ev.protocol, 6);
        assert_eq!(ev.dest_port, "443");
        assert!(ev.application.ends_with("svchost.exe"));
        assert!(ev.is_allow());
    }
}
