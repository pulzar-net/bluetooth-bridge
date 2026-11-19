//! Errors.

use std::io;

/// What went wrong.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The transport failed (unplugged, socket closed, serial error).
    #[error("transport: {0}")]
    Io(#[from] io::Error),
    /// The controller refused a command.
    #[error("controller returned {status_name} ({status:#04x}) for command {opcode:#06x}")]
    Hci {
        /// The command's opcode.
        opcode: u16,
        /// The HCI status code (Core Vol 1, Part F).
        status: u8,
        /// Its name.
        status_name: String,
    },
    /// The controller does not support what was asked (it lacks the
    /// feature bit or the command).
    #[error("not supported by this controller: {0}")]
    Unsupported(&'static str),
    /// No answer in time.
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    /// The connection is gone.
    #[error("disconnected")]
    Disconnected,
    /// The peer's ATT server answered with an error.
    #[error("ATT error {code:#04x} ({}) on handle {handle:#06x} for request {request:#04x}", crate::att::error_name(*code))]
    Att {
        /// The request opcode.
        request: u8,
        /// The attribute handle.
        handle: u16,
        /// The ATT error code.
        code: u8,
    },
    /// Pairing failed.
    #[error("pairing failed: {0}")]
    Pairing(String),
    /// The peer broke the protocol.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// A parameter is out of range.
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
    /// The host has stopped (the transport closed or the controller failed).
    #[error("the host has stopped")]
    Stopped,
}

/// A result with this crate's error.
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub(crate) fn hci(opcode: u16, status: u8) -> Self {
        Error::Hci {
            opcode,
            status,
            status_name: status_name(status).to_string(),
        }
    }
}

/// The name of an HCI status (error) code, Core Vol 1, Part F, 1.3.
pub fn status_name(code: u8) -> &'static str {
    match code {
        0x00 => "Success",
        0x01 => "Unknown HCI Command",
        0x02 => "Unknown Connection Identifier",
        0x03 => "Hardware Failure",
        0x04 => "Page Timeout",
        0x05 => "Authentication Failure",
        0x06 => "PIN or Key Missing",
        0x07 => "Memory Capacity Exceeded",
        0x08 => "Connection Timeout",
        0x09 => "Connection Limit Exceeded",
        0x0a => "Synchronous Connection Limit To A Device Exceeded",
        0x0b => "Connection Already Exists",
        0x0c => "Command Disallowed",
        0x0d => "Connection Rejected due to Limited Resources",
        0x0e => "Connection Rejected Due To Security Reasons",
        0x0f => "Connection Rejected due to Unacceptable BD_ADDR",
        0x10 => "Connection Accept Timeout Exceeded",
        0x11 => "Unsupported Feature or Parameter Value",
        0x12 => "Invalid HCI Command Parameters",
        0x13 => "Remote User Terminated Connection",
        0x14 => "Remote Device Terminated Connection due to Low Resources",
        0x15 => "Remote Device Terminated Connection due to Power Off",
        0x16 => "Connection Terminated By Local Host",
        0x17 => "Repeated Attempts",
        0x18 => "Pairing Not Allowed",
        0x19 => "Unknown LMP PDU",
        0x1a => "Unsupported Remote Feature",
        0x1b => "SCO Offset Rejected",
        0x1c => "SCO Interval Rejected",
        0x1d => "SCO Air Mode Rejected",
        0x1e => "Invalid LMP Parameters / Invalid LL Parameters",
        0x1f => "Unspecified Error",
        0x20 => "Unsupported LMP Parameter Value / Unsupported LL Parameter Value",
        0x21 => "Role Change Not Allowed",
        0x22 => "LMP Response Timeout / LL Response Timeout",
        0x23 => "LMP Error Transaction Collision / LL Procedure Collision",
        0x24 => "LMP PDU Not Allowed",
        0x25 => "Encryption Mode Not Acceptable",
        0x26 => "Link Key cannot be Changed",
        0x27 => "Requested QoS Not Supported",
        0x28 => "Instant Passed",
        0x29 => "Pairing With Unit Key Not Supported",
        0x2a => "Different Transaction Collision",
        0x2c => "QoS Unacceptable Parameter",
        0x2d => "QoS Rejected",
        0x2e => "Channel Classification Not Supported",
        0x2f => "Insufficient Security",
        0x30 => "Parameter Out Of Mandatory Range",
        0x32 => "Role Switch Pending",
        0x34 => "Reserved Slot Violation",
        0x35 => "Role Switch Failed",
        0x36 => "Extended Inquiry Response Too Large",
        0x37 => "Secure Simple Pairing Not Supported By Host",
        0x38 => "Host Busy - Pairing",
        0x39 => "Connection Rejected due to No Suitable Channel Found",
        0x3a => "Controller Busy",
        0x3b => "Unacceptable Connection Parameters",
        0x3c => "Advertising Timeout",
        0x3d => "Connection Terminated due to MIC Failure",
        0x3e => "Connection Failed to be Established / Synchronization Timeout",
        0x40 => "Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging",
        0x41 => "Type0 Submap Not Defined",
        0x42 => "Unknown Advertising Identifier",
        0x43 => "Limit Reached",
        0x44 => "Operation Cancelled by Host",
        0x45 => "Packet Too Long",
        0x46 => "Too Late",
        0x47 => "Too Early",
        0x48 => "Insufficient Channels",
        _ => "Reserved",
    }
}
