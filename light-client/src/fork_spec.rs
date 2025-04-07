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

/// HEIGHT should be sorted by HEIGHT and TIMESTAMP should be sorted by TIMESTAMP.
/// As an operational constraint, ForkSpec should be submitted in HF order
pub fn verify_sorted_asc(fork_specs: &[ForkSpec]) -> Result<(), Error> {
    let mut last_height: Option<u64> = None;
    let mut last_timestamp: Option<u64> = None;
    for spec in fork_specs {
        match &spec.height_or_timestamp {
            HeightOrTimestamp::Height(height) => {
                if let Some(last_height) = &last_height {
                    if height <= last_height {
                        return Err(Error::UnexpectedForkSpecHeightOrder(*last_height, *height));
                    }
                }
                last_height = Some(*height);
            }
            HeightOrTimestamp::Time(timestamp) => {
                if let Some(last_timestamp) = &last_timestamp {
                    if timestamp <= last_timestamp {
                        return Err(Error::UnexpectedForkSpecTimestampOrder(
                            *last_timestamp,
                            *timestamp,
                        ));
                    }
                }
                last_timestamp = Some(*timestamp);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::errors::Error;
    use crate::fork_spec::ForkSpec;
    use crate::fork_spec::{find_target_fork_spec, verify_sorted_asc, HeightOrTimestamp};

    #[test]
    fn test_success_find_target_spec_height_only() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 1,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(20),
                additional_header_item_count: 2,
            },
        ];
        let v = find_target_fork_spec(specs, 10, 0).unwrap();
        assert_eq!(v.height_or_timestamp, HeightOrTimestamp::Height(10));
        let v = find_target_fork_spec(specs, 11, 0).unwrap();
        assert_eq!(v.height_or_timestamp, HeightOrTimestamp::Height(10));
        let v = find_target_fork_spec(specs, 19, 0).unwrap();
        assert_eq!(v.height_or_timestamp, HeightOrTimestamp::Height(10));
        let v = find_target_fork_spec(specs, 20, 0).unwrap();
        assert_eq!(v.height_or_timestamp, HeightOrTimestamp::Height(20));
    }

    #[test]
    fn test_success_find_target_spec_timestamp_only() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 1,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(20),
                additional_header_item_count: 2,
            },
        ];
        let v = find_target_fork_spec(specs, 0, 10).unwrap();
        assert_eq!(v.height_or_timestamp, HeightOrTimestamp::Time(10));
        let v = find_target_fork_spec(specs, 0, 11).unwrap();
        assert_eq!(v.height_or_timestamp, HeightOrTimestamp::Time(10));
        let v = find_target_fork_spec(specs, 0, 19).unwrap();
        assert_eq!(v.height_or_timestamp, HeightOrTimestamp::Time(10));
        let v = find_target_fork_spec(specs, 0, 20).unwrap();
        assert_eq!(v.height_or_timestamp, HeightOrTimestamp::Time(20));
    }

    #[test]
    fn test_success_find_target_spec_timestamp_and_height() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 1,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 20,
            },
        ];
        // After value is primary
        let v = find_target_fork_spec(specs, 10, 10).unwrap();
        assert_eq!(v.height_or_timestamp, HeightOrTimestamp::Time(10));
        let v = find_target_fork_spec(specs, 11, 11).unwrap();
        assert_eq!(v.height_or_timestamp, HeightOrTimestamp::Time(10));
        let v = find_target_fork_spec(specs, 10, 19).unwrap();
        assert_eq!(v.height_or_timestamp, HeightOrTimestamp::Time(10));
        let v = find_target_fork_spec(specs, 20, 20).unwrap();
        assert_eq!(v.height_or_timestamp, HeightOrTimestamp::Time(10));
    }

    #[test]
    fn test_error_find_target_spec_height_only() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 1,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(20),
                additional_header_item_count: 2,
            },
        ];
        let v = find_target_fork_spec(specs, 9, 0).unwrap_err();
        match v {
            Error::MissingForkSpec(e1, e0) => {
                assert_eq!(e1, 9);
                assert_eq!(e0, 0);
            }
            _ => unreachable!("unexpected error"),
        }
    }

    #[test]
    fn test_error_find_target_spec_timestamp_only() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 1,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(20),
                additional_header_item_count: 2,
            },
        ];
        let v = find_target_fork_spec(specs, 0, 9).unwrap_err();
        match v {
            Error::MissingForkSpec(e1, e0) => {
                assert_eq!(e1, 0);
                assert_eq!(e0, 9);
            }
            _ => unreachable!("unexpected error"),
        }
    }

    #[test]
    fn test_error_find_target_spec_timestamp_and_height() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 1,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 2,
            },
        ];
        let v = find_target_fork_spec(specs, 9, 9).unwrap_err();
        match v {
            Error::MissingForkSpec(e1, e0) => {
                assert_eq!(e1, 9);
                assert_eq!(e0, 9);
            }
            _ => unreachable!("unexpected error"),
        }
    }

    #[test]
    fn test_success_verify_sorted_asc_height() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 1,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(11),
                additional_header_item_count: 2,
            },
        ];
        verify_sorted_asc(specs).unwrap();
    }

    #[test]
    fn test_success_verify_sorted_asc_time() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 1,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(11),
                additional_header_item_count: 2,
            },
        ];
        verify_sorted_asc(specs).unwrap();
    }

    #[test]
    fn test_error_verify_sorted_asc_height() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 1,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 2,
            },
        ];
        let v = verify_sorted_asc(specs).unwrap_err();
        match v {
            Error::UnexpectedForkSpecHeightOrder(e1, e0) => {
                assert_eq!(e1, 10);
                assert_eq!(e0, 10);
            }
            _ => unreachable!("unexpected error"),
        }

        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(11),
                additional_header_item_count: 1,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 2,
            },
        ];
        let v = verify_sorted_asc(specs).unwrap_err();
        match v {
            Error::UnexpectedForkSpecHeightOrder(e1, e0) => {
                assert_eq!(e1, 11);
                assert_eq!(e0, 10);
            }
            _ => unreachable!("unexpected error"),
        }
    }

    #[test]
    fn test_error_verify_sorted_asc_time() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 1,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 2,
            },
        ];
        let v = verify_sorted_asc(specs).unwrap_err();
        match v {
            Error::UnexpectedForkSpecTimestampOrder(e1, e0) => {
                assert_eq!(e1, 10);
                assert_eq!(e0, 10);
            }
            _ => unreachable!("unexpected error"),
        }

        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(11),
                additional_header_item_count: 1,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 2,
            },
        ];
        let v = verify_sorted_asc(specs).unwrap_err();
        match v {
            Error::UnexpectedForkSpecTimestampOrder(e1, e0) => {
                assert_eq!(e1, 11);
                assert_eq!(e0, 10);
            }
            _ => unreachable!("unexpected error"),
        }
    }
}
