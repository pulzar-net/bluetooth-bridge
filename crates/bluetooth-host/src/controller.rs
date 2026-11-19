//! What the controller can do, read once at start, so every feature can
//! check before it asks and degrade cleanly on an old chip (a Pi 3's
//! Bluetooth 4.1 controller has no extended advertising, no 2M or coded PHY
//! and no data length extension).

use bt_hci::param::CmdMask;
use serde::Serialize;

/// LE feature bits, Core Vol 6, Part B, 4.6.
pub mod le_feature {
    /// LE Encryption.
    pub const ENCRYPTION: u32 = 0;
    /// Connection Parameters Request procedure.
    pub const CONN_PARAMS_REQUEST: u32 = 1;
    /// LE Ping.
    pub const PING: u32 = 4;
    /// LE Data Packet Length Extension.
    pub const DATA_LENGTH_EXTENSION: u32 = 5;
    /// LL Privacy.
    pub const LL_PRIVACY: u32 = 6;
    /// Extended Scanner Filter Policies.
    pub const EXT_SCANNER_FILTER_POLICIES: u32 = 7;
    /// LE 2M PHY.
    pub const PHY_2M: u32 = 8;
    /// LE Coded PHY.
    pub const PHY_CODED: u32 = 11;
    /// LE Extended Advertising.
    pub const EXTENDED_ADVERTISING: u32 = 12;
    /// LE Periodic Advertising.
    pub const PERIODIC_ADVERTISING: u32 = 13;
    /// Channel Selection Algorithm #2.
    pub const CSA2: u32 = 14;
    /// Connection CTE Request.
    pub const CONN_CTE_REQUEST: u32 = 17;
    /// Connection CTE Response.
    pub const CONN_CTE_RESPONSE: u32 = 18;
    /// Connectionless CTE Transmitter.
    pub const CONNLESS_CTE_TX: u32 = 19;
    /// Connectionless CTE Receiver.
    pub const CONNLESS_CTE_RX: u32 = 20;
    /// Antenna switching during CTE transmission (AoD).
    pub const AOD: u32 = 21;
    /// Antenna switching during CTE reception (AoA).
    pub const AOA: u32 = 22;
    /// Receiving Constant Tone Extensions.
    pub const CTE_RX: u32 = 23;
    /// Periodic Advertising Sync Transfer, recipient.
    pub const PAST_RECIPIENT: u32 = 25;
    /// Isochronous Broadcaster.
    pub const ISO_BROADCASTER: u32 = 30;
    /// Synchronized Receiver.
    pub const SYNC_RECEIVER: u32 = 31;
    /// LE Power Control Request.
    pub const POWER_CONTROL: u32 = 33;
    /// Connection Subrating.
    pub const SUBRATING: u32 = 37;
    /// Channel Sounding.
    pub const CHANNEL_SOUNDING: u32 = 46;

    /// Every named bit, for reports.
    pub const NAMES: &[(u32, &str)] = &[
        (0, "le_encryption"),
        (1, "connection_parameters_request"),
        (2, "extended_reject_indication"),
        (3, "peripheral_initiated_features_exchange"),
        (4, "le_ping"),
        (5, "data_length_extension"),
        (6, "ll_privacy"),
        (7, "extended_scanner_filter_policies"),
        (8, "le_2m_phy"),
        (9, "stable_modulation_index_tx"),
        (10, "stable_modulation_index_rx"),
        (11, "le_coded_phy"),
        (12, "extended_advertising"),
        (13, "periodic_advertising"),
        (14, "channel_selection_algorithm_2"),
        (15, "power_class_1"),
        (16, "minimum_number_of_used_channels"),
        (17, "connection_cte_request"),
        (18, "connection_cte_response"),
        (19, "connectionless_cte_transmitter"),
        (20, "connectionless_cte_receiver"),
        (21, "antenna_switching_aod"),
        (22, "antenna_switching_aoa"),
        (23, "receiving_cte"),
        (24, "periodic_advertising_sync_transfer_sender"),
        (25, "periodic_advertising_sync_transfer_recipient"),
        (26, "sleep_clock_accuracy_updates"),
        (27, "remote_public_key_validation"),
        (28, "cis_central"),
        (29, "cis_peripheral"),
        (30, "isochronous_broadcaster"),
        (31, "synchronized_receiver"),
        (32, "cis_host_support"),
        (33, "power_control_request"),
        (34, "power_control_request_2"),
        (35, "path_loss_monitoring"),
        (36, "periodic_advertising_adi"),
        (37, "connection_subrating"),
        (38, "connection_subrating_host_support"),
        (39, "channel_classification"),
        (40, "advertising_coding_selection"),
        (41, "advertising_coding_selection_host_support"),
        (43, "periodic_advertising_with_responses_advertiser"),
        (44, "periodic_advertising_with_responses_scanner"),
        (46, "channel_sounding"),
        (47, "channel_sounding_host_support"),
    ];
}

/// The controller's identity and capabilities.
#[derive(Debug, Clone, Serialize)]
pub struct Capabilities {
    /// The public address, least significant byte first; all zeros when the
    /// controller has none.
    #[serde(serialize_with = "ser_addr")]
    pub public_address: [u8; 6],
    /// HCI version (a Core Specification version number).
    pub hci_version: u8,
    /// HCI subversion.
    pub hci_subversion: u16,
    /// LMP/LL version.
    pub lmp_version: u8,
    /// LMP/LL subversion.
    pub lmp_subversion: u16,
    /// Manufacturer (a company identifier).
    pub manufacturer: u16,
    /// Supported commands, the 64-octet mask.
    #[serde(skip)]
    pub commands: [u8; 64],
    /// LMP features, page 0.
    pub lmp_features: u64,
    /// LE features.
    pub le_features: u64,
    /// LE supported states.
    pub le_states: u64,
    /// Maximum LE ACL data length per packet, and how many the controller buffers.
    pub le_acl: (u16, u16),
    /// Maximum ISO data length and buffer count (0 when ISO is not supported).
    pub iso: (u16, u8),
    /// Maximum extended advertising data length (31 for legacy only).
    pub max_adv_data: u16,
    /// Number of advertising sets (1 for legacy only).
    pub adv_sets: u8,
    /// Filter Accept List size.
    pub filter_accept_list_size: u8,
    /// Resolving List size (0 without LL privacy).
    pub resolving_list_size: u8,
    /// Maximum data length: (tx octets, tx time, rx octets, rx time).
    pub max_data_length: (u16, u16, u16, u16),
}

fn ser_addr<S: serde::Serializer>(a: &[u8; 6], s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&crate::Address::public(*a))
}

impl Capabilities {
    /// The supported-commands mask, with a getter per command.
    pub fn cmds(&self) -> CmdMask {
        // CmdMask is a transparent 64-byte bit field; rebuild it from the bytes.
        use bt_hci::FromHciBytes;
        <&CmdMask>::from_hci_bytes(&self.commands)
            .map(|(m, _)| *m)
            .unwrap_or_default()
    }

    /// Whether an LE feature bit is set.
    pub fn le(&self, bit: u32) -> bool {
        bit < 64 && self.le_features & (1 << bit) != 0
    }

    /// Extended advertising, scanning and connecting (Bluetooth 5). The
    /// feature bit makes those commands mandatory (Core Vol 4, Part E, 3),
    /// so it alone decides: some controllers leave them out of their
    /// supported-commands mask.
    pub fn extended_advertising(&self) -> bool {
        self.le(le_feature::EXTENDED_ADVERTISING)
    }

    /// Extended scanning commands (the same feature bit).
    pub fn extended_scanning(&self) -> bool {
        self.extended_advertising()
    }

    /// Periodic advertising.
    pub fn periodic_advertising(&self) -> bool {
        self.le(le_feature::PERIODIC_ADVERTISING)
    }

    /// The coded PHY (long range).
    pub fn coded_phy(&self) -> bool {
        self.le(le_feature::PHY_CODED)
    }

    /// The 2M PHY.
    pub fn phy_2m(&self) -> bool {
        self.le(le_feature::PHY_2M)
    }

    /// Data length extension.
    pub fn data_length_extension(&self) -> bool {
        self.le(le_feature::DATA_LENGTH_EXTENSION) && self.cmds().le_set_data_length()
    }

    /// Changing PHY on a connection.
    pub fn phy_update(&self) -> bool {
        (self.phy_2m() || self.coded_phy()) && self.cmds().le_set_phy()
    }

    /// Names of the LE features the controller has.
    pub fn le_feature_names(&self) -> Vec<&'static str> {
        le_feature::NAMES
            .iter()
            .filter(|(b, _)| self.le(*b))
            .map(|(_, n)| *n)
            .collect()
    }

    /// The manufacturer's name, from the assigned numbers.
    pub fn manufacturer_name(&self) -> Option<&'static str> {
        bluetooth_numbers::company(self.manufacturer)
    }

    /// The Core Specification version the controller implements.
    pub fn version_name(&self) -> Option<&'static str> {
        bluetooth_numbers::core_version(self.hci_version)
    }
}
