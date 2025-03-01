use crate::errors::Error;
use crate::misc::BlockNumber;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::fork_spec::HeightOrTimestamp as RawHeightOrTimestamp;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::ForkSpec as RawForkSpec;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum HeightOrTimestamp {
    Height(u64),
    Time(u64),
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ForkSpec {
    pub height_or_timestamp: HeightOrTimestamp,
    /// Items count after parent_beacon_root
    pub additional_header_item_count: u64,
}

impl TryFrom<RawForkSpec> for ForkSpec {
    type Error = Error;

    fn try_from(value: RawForkSpec) -> Result<Self, Self::Error> {
        let height_or_timestamp = value
            .height_or_timestamp
            .ok_or(Error::MissingTimestampOrHeightInForkSpec)?;

        Ok(Self {
            height_or_timestamp: match height_or_timestamp {
                RawHeightOrTimestamp::Height(height) => HeightOrTimestamp::Height(height),
                RawHeightOrTimestamp::Timestamp(timestamp) => HeightOrTimestamp::Time(timestamp),
            },
            additional_header_item_count: value.additional_header_item_count,
        })
    }
}

impl From<ForkSpec> for RawForkSpec {
    fn from(value: ForkSpec) -> Self {
        Self {
            height_or_timestamp: match value.height_or_timestamp {
                HeightOrTimestamp::Height(height) => Some(RawHeightOrTimestamp::Height(height)),
                HeightOrTimestamp::Time(timestamp) => {
                    Some(RawHeightOrTimestamp::Timestamp(timestamp))
                }
            },
            additional_header_item_count: value.additional_header_item_count,
        }
    }
}

pub fn find_target_fork_spec(
    fork_specs: &[ForkSpec],
    current_height: BlockNumber,
    current_timestamp: u64,
) -> Result<&ForkSpec, Error> {
    // find from last to first
    fork_specs
        .iter()
        .rev()
        .find(|spec| match spec.height_or_timestamp {
            HeightOrTimestamp::Height(height) => height <= current_height,
            HeightOrTimestamp::Time(timestamp) => timestamp <= current_timestamp,
        })
        .ok_or(Error::MissingForkSpec(current_height, current_timestamp))
}

pub fn validate_sorted_asc(fork_specs: &[ForkSpec]) -> Result<(), Error> {
    let mut last_height: Option<u64> = None;
    let mut last_timestamp: Option<u64> = None;
    for spec in fork_specs {
        match &spec.height_or_timestamp {
            HeightOrTimestamp::Height(height) => {
                if let Some(last_height) = &last_height {
                    if height <= last_height {
                        return Err(Error::UnexpectedForkSpecHeightOrder(*height, *last_height));
                    }
                }
                last_height = Some(*height);
            }
            HeightOrTimestamp::Time(timestamp) => {
                if let Some(last_timestamp) = &last_timestamp {
                    if timestamp <= last_timestamp {
                        return Err(Error::UnexpectedForkSpecTimestampOrder(
                            *timestamp,
                            *last_timestamp,
                        ));
                    }
                }
                last_timestamp = Some(*timestamp);
            }
        }
    }
    Ok(())
}
