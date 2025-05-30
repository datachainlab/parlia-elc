use crate::errors::Error;
use crate::misc::BlockNumber;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::fork_spec::HeightOrTimestamp as RawHeightOrTimestamp;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::ForkSpec as RawForkSpec;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum HeightOrTimestamp {
    Height(u64),
    Time(u64),
}

/// ForkSpec defines different parameters for each HF.
/// The ForkSpec of the supporting HF must be registered at CreateClient
/// This is a data structure that does not exist in the BSC node and is designed uniquely for the light client.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ForkSpec {
    /// The timestamp or height at which the HF will occur.
    /// If you set the timestamp, you need to use the value described in bsc's ChainConfig.
    /// https://github.com/bnb-chain/bsc/blob/5735d8a56540e8f2fb26d5585de0fa3959bb17b4/params/config.go#L192C3-L192C14
    pub height_or_timestamp: HeightOrTimestamp,
    /// Items count after parent_beacon_root
    /// The number of headers prior to Pascal HF is set to 0.
    /// For example, the number of headers after Pascal HF is set to 1 because of the addition of the requestsHash.
    pub additional_header_item_count: u64,
    /// Block count in epoch
    pub epoch_length: u64,
    /// Max turn length
    pub max_turn_length: u64,
    /// true: header has msec in mix_digest
    pub enable_header_msec: bool,
    /// Gas Limit bound diriver
    pub gas_limit_bound_divider: u64,
}

impl ForkSpec {
    /// Boundary epochs are block heights that indicate the epochs before and after the HF.
    ///
    /// Calculates the boundary epochs based on the current and previous fork specifications.
    /// This function determines the boundary epochs by comparing the current fork specification
    /// with the previous fork specification. It calculates the previous last epoch, the current
    /// first epoch, and any intermediate epochs between them.
    ///
    /// previous_last: refers to the previous epoch of the height
    /// current_first refers to the first epoch of the height divisible by the current fork epoch length.
    /// intermediates: refers to the epochs between the previous last and current first.
    ///
    /// eg) height = 1501
    /// previous_last = 1400
    /// intermediates = [1600, 1800]
    /// current_first = 2000
    ///
    /// in Lorentz HF
    /// eg) height = 1600
    /// previous_last = 1600
    /// intermediates = [1800]
    /// current_first = 2000
    ///
    /// eg) height = 1601
    /// previous_last = 1600
    /// intermediates = [1800]
    /// current_first = 2000
    ///
    /// eg) height = 1800
    /// previous_last = 1800
    /// intermediates = []
    /// current_first = 2000
    ///
    /// eg) height = 2000
    /// previous_last = 2000
    /// intermediates = []
    /// current_first = 2000
    pub fn boundary_epochs(&self, prev_fork_specs: &[ForkSpec]) -> Result<BoundaryEpochs, Error> {
        let prev_fork_spec = prev_fork_specs
            .first()
            .ok_or(Error::EmptyPreviousForkSpecs)?;
        if let HeightOrTimestamp::Height(height) = self.height_or_timestamp {
            if self.epoch_length == 0 || prev_fork_spec.epoch_length == 0 {
                return Err(Error::UnexpectedEpochLength(
                    self.epoch_length,
                    prev_fork_spec.epoch_length,
                ));
            }
            let previous_last = height - (height % prev_fork_spec.epoch_length);

            let current_first = if height % self.epoch_length == 0 {
                height
            } else {
                height + (self.epoch_length - height % self.epoch_length)
            };
            let mut intermediates = vec![];

            // Only for localnet.
            // intermediates are [200, 400, 500, ...]
            // The decrease in epoch length probably does not occur and is therefore not supported.
            if previous_last == 0 {
                let mut epoch_length_list: alloc::vec::Vec<u64> = prev_fork_specs
                    .iter()
                    .rev()
                    .map(|spec| spec.epoch_length)
                    .collect();
                // ex) [200, 500, 500, 1000, 1000, 2000...] -> [200, 500, 1000, 2000...]
                epoch_length_list.dedup();

                epoch_length_list.windows(2).for_each(|pair| {
                    let (start, end) = (pair[0], pair[1]);
                    let mut value = start;
                    while value < end {
                        intermediates.push(value);
                        value += start;
                    }
                });
            }
            let mut mid = previous_last + prev_fork_spec.epoch_length;
            while mid < current_first {
                intermediates.push(mid);
                mid += prev_fork_spec.epoch_length;
            }
            return Ok(BoundaryEpochs {
                previous_fork_spec: prev_fork_spec.clone(),
                current_fork_spec: self.clone(),
                previous_last,
                current_first,
                intermediates,
            });
        }
        Err(Error::MissingForkHeightInBoundaryCalculation(self.clone()))
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BoundaryEpochs {
    previous_fork_spec: ForkSpec,
    current_fork_spec: ForkSpec,
    previous_last: BlockNumber,
    current_first: BlockNumber,
    intermediates: alloc::vec::Vec<BlockNumber>,
}

impl BoundaryEpochs {
    pub fn current_fork_spec(&self) -> &ForkSpec {
        &self.current_fork_spec
    }

    /// Calculates the current epoch block number based on the given block number.
    ///
    /// This function determines the current epoch block number by considering the given block number
    /// and the intermediate epochs. It handles various cases such as the first epoch, intermediate epochs,
    /// and epochs after the hard fork.
    ///
    pub fn current_epoch_block_number(&self, number: BlockNumber) -> BlockNumber {
        if number >= self.current_first {
            return number - (number % self.current_fork_spec.epoch_length);
        }
        for mid in self.intermediates.iter().rev() {
            if number >= *mid {
                return *mid;
            }
        }
        number - (number % self.previous_fork_spec.epoch_length)
    }

    /// Calculates the previous epoch block number based on the current epoch block number.
    ///
    /// This function determines the previous epoch block number by considering the current epoch block number
    /// and the intermediate epochs. It handles various cases such as the first epoch, intermediate epochs,
    /// and epochs after the hard fork.
    pub fn previous_epoch_block_number(
        &self,
        current_epoch_block_number: BlockNumber,
    ) -> BlockNumber {
        if current_epoch_block_number == 0 {
            return 0;
        }
        // Before HF
        if current_epoch_block_number <= self.previous_last {
            return current_epoch_block_number - self.previous_fork_spec.epoch_length;
        }

        for (i, mid) in self.intermediates.iter().enumerate() {
            if current_epoch_block_number == *mid {
                if i == 0 {
                    return self.previous_last;
                } else {
                    return self.intermediates[i - 1];
                }
            }
        }

        if current_epoch_block_number == self.current_first {
            if self.intermediates.is_empty() {
                return self.previous_last;
            }
            return *self.intermediates.last().unwrap();
        }

        // After HF
        current_epoch_block_number - self.current_fork_spec.epoch_length
    }
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
            epoch_length: value.epoch_length,
            max_turn_length: value.max_turn_length,
            enable_header_msec: value.enable_header_msec,
            gas_limit_bound_divider: value.gas_limit_bound_divider,
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
            epoch_length: value.epoch_length,
            max_turn_length: value.max_turn_length,
            enable_header_msec: value.enable_header_msec,
            gas_limit_bound_divider: value.gas_limit_bound_divider,
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

/// Retrieves the boundary epochs for the given `ForkSpec`.
///
/// This function finds the boundary epochs for the specified `current_spec` by comparing it
/// with the previous fork specifications in the provided list. It returns the boundary epochs
/// if the `current_spec` is found in the list.
pub fn get_boundary_epochs(
    current_spec: &ForkSpec,
    fork_specs: &[ForkSpec],
) -> Result<BoundaryEpochs, Error> {
    for (i, spec) in fork_specs.iter().enumerate() {
        if spec == current_spec {
            if i == 0 {
                return spec.boundary_epochs(fork_specs);
            }
            return spec.boundary_epochs(&fork_specs[i - 1..]);
        }
    }
    Err(Error::MissingPreviousForkSpec(current_spec.clone()))
}

/// Verifies that the given list of `ForkSpec` is sorted in ascending order.
///
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
    use crate::fixture::{
        fork_spec_after_lorentz, fork_spec_after_maxwell, fork_spec_after_pascal,
        fork_spec_after_post_maxwell_1, fork_spec_after_post_maxwell_2,
    };
    use crate::fork_spec::{
        find_target_fork_spec, get_boundary_epochs, verify_sorted_asc, ForkSpec, HeightOrTimestamp,
    };

    #[test]
    fn test_success_find_target_spec_height_only() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 1,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(20),
                additional_header_item_count: 2,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: true,
                gas_limit_bound_divider: 256,
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
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(20),
                additional_header_item_count: 2,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
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
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 20,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
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
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(20),
                additional_header_item_count: 2,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
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
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(20),
                additional_header_item_count: 2,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
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
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 2,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
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
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(11),
                additional_header_item_count: 2,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
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
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(11),
                additional_header_item_count: 2,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
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
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 2,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
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
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 2,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
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
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 2,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
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
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 2,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
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

    #[test]
    fn test_error_boundary_epochs_lorentz_pascal() {
        let current = ForkSpec {
            height_or_timestamp: HeightOrTimestamp::Time(0),
            additional_header_item_count: 1,
            epoch_length: 500,
            max_turn_length: 64,
            enable_header_msec: true,
            gas_limit_bound_divider: 256,
        };
        match current
            .boundary_epochs(&[fork_spec_after_pascal()])
            .unwrap_err()
        {
            Error::MissingForkHeightInBoundaryCalculation(e1) => {
                assert_eq!(current, e1);
            }
            _ => unreachable!("unexpected error"),
        }
    }

    #[test]
    fn test_error_boundary_epochs_current_epoch_length_zero() {
        let current = ForkSpec {
            height_or_timestamp: HeightOrTimestamp::Height(0),
            additional_header_item_count: 1,
            epoch_length: 0,
            max_turn_length: 64,
            enable_header_msec: false,
            gas_limit_bound_divider: 256,
        };
        match current
            .boundary_epochs(&[fork_spec_after_pascal()])
            .unwrap_err()
        {
            Error::UnexpectedEpochLength(e1, e2) => {
                assert_eq!(current.epoch_length, e1);
                assert_ne!(current.epoch_length, e2);
            }
            _ => unreachable!("unexpected error"),
        }
    }

    #[test]
    fn test_error_boundary_epochs_previous_epoch_length_zero() {
        let previous = ForkSpec {
            height_or_timestamp: HeightOrTimestamp::Height(0),
            additional_header_item_count: 1,
            epoch_length: 0,
            max_turn_length: 64,
            enable_header_msec: false,
            gas_limit_bound_divider: 256,
        };
        match fork_spec_after_pascal()
            .boundary_epochs(&[previous.clone()])
            .unwrap_err()
        {
            Error::UnexpectedEpochLength(e1, e2) => {
                assert_ne!(previous.epoch_length, e1);
                assert_eq!(previous.epoch_length, e2);
            }
            _ => unreachable!("unexpected error"),
        }
    }

    #[test]
    fn test_success_boundary_epochs() {
        // Lorentz HF
        let mut f1 = fork_spec_after_lorentz().clone();
        f1.height_or_timestamp = HeightOrTimestamp::Height(1501);
        let be = f1.boundary_epochs(&[fork_spec_after_pascal()]).unwrap();
        assert_eq!(be.previous_last, 1400);
        assert_eq!(be.intermediates, vec![1600, 1800]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(1600);
        let be = f1.boundary_epochs(&[fork_spec_after_pascal()]).unwrap();
        assert_eq!(be.previous_last, 1600);
        assert_eq!(be.intermediates, vec![1800]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(1601);
        let be = f1.boundary_epochs(&[fork_spec_after_pascal()]).unwrap();
        assert_eq!(be.previous_last, 1600);
        assert_eq!(be.intermediates, vec![1800]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(1800);
        let be = f1.boundary_epochs(&[fork_spec_after_pascal()]).unwrap();
        assert_eq!(be.previous_last, 1800);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(2000);
        let be = f1.boundary_epochs(&[fork_spec_after_pascal()]).unwrap();
        assert_eq!(be.previous_last, 2000);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 2000);

        // Maxwell HF
        let mut f1 = fork_spec_after_maxwell().clone();
        f1.height_or_timestamp = HeightOrTimestamp::Height(1501);
        let be = f1
            .boundary_epochs(&[fork_spec_after_lorentz(), fork_spec_after_pascal()])
            .unwrap();
        assert_eq!(be.previous_last, 1500);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(2000);
        let be = f1
            .boundary_epochs(&[fork_spec_after_lorentz(), fork_spec_after_pascal()])
            .unwrap();
        assert_eq!(be.previous_last, 2000);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(2001);
        let be = f1
            .boundary_epochs(&[fork_spec_after_lorentz(), fork_spec_after_pascal()])
            .unwrap();
        assert_eq!(be.previous_last, 2000);
        assert_eq!(be.intermediates, vec![2500]);
        assert_eq!(be.current_first, 3000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(2500);
        let be = f1
            .boundary_epochs(&[fork_spec_after_lorentz(), fork_spec_after_pascal()])
            .unwrap();
        assert_eq!(be.previous_last, 2500);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 3000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(3000);
        let be = f1
            .boundary_epochs(&[fork_spec_after_lorentz(), fork_spec_after_pascal()])
            .unwrap();
        assert_eq!(be.previous_last, 3000);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 3000);

        // Post maxwell 1 HF
        let mut f1 = fork_spec_after_post_maxwell_1().clone();
        f1.height_or_timestamp = HeightOrTimestamp::Height(1501);
        let be = f1
            .boundary_epochs(&[
                fork_spec_after_maxwell(),
                fork_spec_after_lorentz(),
                fork_spec_after_pascal(),
            ])
            .unwrap();
        assert_eq!(be.previous_last, 1000);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(2000);
        let be = f1
            .boundary_epochs(&[
                fork_spec_after_maxwell(),
                fork_spec_after_lorentz(),
                fork_spec_after_pascal(),
            ])
            .unwrap();
        assert_eq!(be.previous_last, 2000);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(2001);
        let be = f1
            .boundary_epochs(&[
                fork_spec_after_maxwell(),
                fork_spec_after_lorentz(),
                fork_spec_after_pascal(),
            ])
            .unwrap();
        assert_eq!(be.previous_last, 2000);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 3000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(2500);
        let be = f1
            .boundary_epochs(&[
                fork_spec_after_maxwell(),
                fork_spec_after_lorentz(),
                fork_spec_after_pascal(),
            ])
            .unwrap();
        assert_eq!(be.previous_last, 2000);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 3000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(3000);
        let be = f1
            .boundary_epochs(&[
                fork_spec_after_maxwell(),
                fork_spec_after_lorentz(),
                fork_spec_after_pascal(),
            ])
            .unwrap();
        assert_eq!(be.previous_last, 3000);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 3000);

        // Post maxwell 2 HF
        let mut f1 = fork_spec_after_post_maxwell_2().clone();
        f1.height_or_timestamp = HeightOrTimestamp::Height(1501);
        let be = f1
            .boundary_epochs(&[
                fork_spec_after_post_maxwell_1(),
                fork_spec_after_maxwell(),
                fork_spec_after_lorentz(),
                fork_spec_after_pascal(),
            ])
            .unwrap();
        assert_eq!(be.previous_last, 1000);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(2000);
        let be = f1
            .boundary_epochs(&[
                fork_spec_after_post_maxwell_1(),
                fork_spec_after_maxwell(),
                fork_spec_after_lorentz(),
                fork_spec_after_pascal(),
            ])
            .unwrap();
        assert_eq!(be.previous_last, 2000);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(2001);
        let be = f1
            .boundary_epochs(&[
                fork_spec_after_post_maxwell_1(),
                fork_spec_after_maxwell(),
                fork_spec_after_lorentz(),
                fork_spec_after_pascal(),
            ])
            .unwrap();
        assert_eq!(be.previous_last, 2000);
        assert_eq!(be.intermediates, vec![3000]);
        assert_eq!(be.current_first, 4000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(3000);
        let be = f1
            .boundary_epochs(&[
                fork_spec_after_post_maxwell_1(),
                fork_spec_after_maxwell(),
                fork_spec_after_lorentz(),
                fork_spec_after_pascal(),
            ])
            .unwrap();
        assert_eq!(be.previous_last, 3000);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 4000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(4000);
        let be = f1
            .boundary_epochs(&[
                fork_spec_after_post_maxwell_1(),
                fork_spec_after_maxwell(),
                fork_spec_after_lorentz(),
                fork_spec_after_pascal(),
            ])
            .unwrap();
        assert_eq!(be.previous_last, 4000);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 4000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(4001);
        let be = f1
            .boundary_epochs(&[
                fork_spec_after_post_maxwell_1(),
                fork_spec_after_maxwell(),
                fork_spec_after_lorentz(),
                fork_spec_after_pascal(),
            ])
            .unwrap();
        assert_eq!(be.previous_last, 4000);
        assert_eq!(be.intermediates, vec![5000]);
        assert_eq!(be.current_first, 6000);
    }

    #[test]
    fn test_success_boundary_epochs_lorentz_pascal() {
        let be = fork_spec_after_lorentz()
            .boundary_epochs(&[fork_spec_after_pascal()])
            .unwrap();
        assert_eq!(be.previous_last, 0);
        assert_eq!(be.intermediates, vec![200, 400]);
        assert_eq!(be.current_first, 500);
        assert_eq!(be.current_epoch_block_number(199), 0);
        assert_eq!(be.current_epoch_block_number(200), 200);
        assert_eq!(be.current_epoch_block_number(399), 200);
        assert_eq!(be.current_epoch_block_number(400), 400);
        assert_eq!(be.current_epoch_block_number(499), 400);
        assert_eq!(be.current_epoch_block_number(500), 500);
        assert_eq!(be.current_epoch_block_number(501), 500);
        assert_eq!(be.current_epoch_block_number(999), 500);
        assert_eq!(be.current_epoch_block_number(1000), 1000);
        assert_eq!(be.current_epoch_block_number(1001), 1000);
        assert_eq!(be.current_epoch_block_number(1499), 1000);
        assert_eq!(be.current_epoch_block_number(1500), 1500);
        assert_eq!(be.current_epoch_block_number(1501), 1500);

        assert_eq!(be.previous_epoch_block_number(0), 0);
        assert_eq!(be.previous_epoch_block_number(200), 0);
        assert_eq!(be.previous_epoch_block_number(400), 200);
        assert_eq!(be.previous_epoch_block_number(500), 400);
        assert_eq!(be.previous_epoch_block_number(1000), 500);
        assert_eq!(be.previous_epoch_block_number(1500), 1000);
    }

    #[test]
    fn test_success_boundary_epochs_maxwell_lorentz() {
        let be = fork_spec_after_maxwell()
            .boundary_epochs(&[fork_spec_after_lorentz(), fork_spec_after_pascal()])
            .unwrap();
        assert_eq!(be.previous_last, 0);
        assert_eq!(be.intermediates, vec![200, 400, 500]);
        assert_eq!(be.current_first, 1000);
        assert_eq!(be.current_epoch_block_number(199), 0);
        assert_eq!(be.current_epoch_block_number(200), 200);
        assert_eq!(be.current_epoch_block_number(399), 200);
        assert_eq!(be.current_epoch_block_number(400), 400);
        assert_eq!(be.current_epoch_block_number(499), 400);
        assert_eq!(be.current_epoch_block_number(500), 500);
        assert_eq!(be.current_epoch_block_number(501), 500);
        assert_eq!(be.current_epoch_block_number(999), 500);
        assert_eq!(be.current_epoch_block_number(1000), 1000);
        assert_eq!(be.current_epoch_block_number(1001), 1000);
        assert_eq!(be.current_epoch_block_number(1499), 1000);
        assert_eq!(be.current_epoch_block_number(1500), 1000);
        assert_eq!(be.current_epoch_block_number(1501), 1000);
        assert_eq!(be.current_epoch_block_number(1999), 1000);
        assert_eq!(be.current_epoch_block_number(2000), 2000);
        assert_eq!(be.current_epoch_block_number(2001), 2000);
        assert_eq!(be.current_epoch_block_number(2999), 2000);
        assert_eq!(be.current_epoch_block_number(3000), 3000);

        assert_eq!(be.previous_epoch_block_number(0), 0);
        assert_eq!(be.previous_epoch_block_number(200), 0);
        assert_eq!(be.previous_epoch_block_number(400), 200);
        assert_eq!(be.previous_epoch_block_number(500), 400);
        assert_eq!(be.previous_epoch_block_number(1000), 500);
        assert_eq!(be.previous_epoch_block_number(2000), 1000);
        assert_eq!(be.previous_epoch_block_number(3000), 2000);
    }

    #[test]
    fn test_success_boundary_epochs_after_maxwell_1() {
        let be = fork_spec_after_post_maxwell_1()
            .boundary_epochs(&[
                fork_spec_after_maxwell(),
                fork_spec_after_lorentz(),
                fork_spec_after_pascal(),
            ])
            .unwrap();
        assert_eq!(be.previous_last, 0);
        assert_eq!(be.intermediates, vec![200, 400, 500]);
        // Same as maxwell
        assert_eq!(be.current_first, 1000);
        assert_eq!(be.current_epoch_block_number(199), 0);
        assert_eq!(be.current_epoch_block_number(200), 200);
        assert_eq!(be.current_epoch_block_number(399), 200);
        assert_eq!(be.current_epoch_block_number(400), 400);
        assert_eq!(be.current_epoch_block_number(499), 400);
        assert_eq!(be.current_epoch_block_number(500), 500);
        assert_eq!(be.current_epoch_block_number(501), 500);
        assert_eq!(be.current_epoch_block_number(999), 500);
        assert_eq!(be.current_epoch_block_number(1000), 1000);
        assert_eq!(be.current_epoch_block_number(1001), 1000);
        assert_eq!(be.current_epoch_block_number(1499), 1000);
        assert_eq!(be.current_epoch_block_number(1500), 1000);
        assert_eq!(be.current_epoch_block_number(1501), 1000);
        assert_eq!(be.current_epoch_block_number(1999), 1000);
        assert_eq!(be.current_epoch_block_number(2000), 2000);
        assert_eq!(be.current_epoch_block_number(2001), 2000);
        assert_eq!(be.current_epoch_block_number(2999), 2000);
        assert_eq!(be.current_epoch_block_number(3000), 3000);

        assert_eq!(be.previous_epoch_block_number(0), 0);
        assert_eq!(be.previous_epoch_block_number(200), 0);
        assert_eq!(be.previous_epoch_block_number(400), 200);
        assert_eq!(be.previous_epoch_block_number(500), 400);
        assert_eq!(be.previous_epoch_block_number(1000), 500);
        assert_eq!(be.previous_epoch_block_number(2000), 1000);
        assert_eq!(be.previous_epoch_block_number(3000), 2000);
    }

    #[test]
    fn test_success_boundary_epochs_after_maxwell_2() {
        let be = fork_spec_after_post_maxwell_2()
            .boundary_epochs(&[
                fork_spec_after_post_maxwell_1(),
                fork_spec_after_maxwell(),
                fork_spec_after_lorentz(),
                fork_spec_after_pascal(),
            ])
            .unwrap();
        assert_eq!(be.previous_last, 0);
        assert_eq!(be.intermediates, vec![200, 400, 500, 1000]);
        assert_eq!(be.current_first, 2000);
        assert_eq!(be.current_epoch_block_number(199), 0);
        assert_eq!(be.current_epoch_block_number(200), 200);
        assert_eq!(be.current_epoch_block_number(399), 200);
        assert_eq!(be.current_epoch_block_number(400), 400);
        assert_eq!(be.current_epoch_block_number(499), 400);
        assert_eq!(be.current_epoch_block_number(500), 500);
        assert_eq!(be.current_epoch_block_number(501), 500);
        assert_eq!(be.current_epoch_block_number(999), 500);
        assert_eq!(be.current_epoch_block_number(1000), 1000);
        assert_eq!(be.current_epoch_block_number(1001), 1000);
        assert_eq!(be.current_epoch_block_number(1499), 1000);
        assert_eq!(be.current_epoch_block_number(1500), 1000);
        assert_eq!(be.current_epoch_block_number(1501), 1000);
        assert_eq!(be.current_epoch_block_number(1999), 1000);
        assert_eq!(be.current_epoch_block_number(2000), 2000);
        assert_eq!(be.current_epoch_block_number(2001), 2000);
        assert_eq!(be.current_epoch_block_number(2999), 2000);
        assert_eq!(be.current_epoch_block_number(3000), 2000);

        assert_eq!(be.previous_epoch_block_number(0), 0);
        assert_eq!(be.previous_epoch_block_number(200), 0);
        assert_eq!(be.previous_epoch_block_number(400), 200);
        assert_eq!(be.previous_epoch_block_number(500), 400);
        assert_eq!(be.previous_epoch_block_number(1000), 500);
        assert_eq!(be.previous_epoch_block_number(2000), 1000);
        assert_eq!(be.previous_epoch_block_number(3000), 1000);
    }

    #[test]
    fn test_error_get_boundary_epochs() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 1,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(20),
                additional_header_item_count: 2,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
        ];
        let v = get_boundary_epochs(&fork_spec_after_pascal(), specs).unwrap_err();
        match v {
            Error::MissingPreviousForkSpec(f) => {
                assert_eq!(f, fork_spec_after_pascal());
            }
            _ => unreachable!("unexpected error {}", v),
        }
    }

    #[test]
    fn test_success_get_boundary_epochs() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 1,
                epoch_length: 200,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(20),
                additional_header_item_count: 2,
                epoch_length: 500,
                max_turn_length: 9,
                enable_header_msec: false,
                gas_limit_bound_divider: 256,
            },
        ];
        let v = get_boundary_epochs(&specs[1], specs).unwrap();
        assert_eq!(v.current_fork_spec, specs[1]);
        assert_eq!(v.previous_fork_spec, specs[0]);

        let v = get_boundary_epochs(&specs[0], specs).unwrap();
        assert_eq!(v.current_fork_spec, specs[0]);
        assert_eq!(v.previous_fork_spec, specs[0]);
    }
}
