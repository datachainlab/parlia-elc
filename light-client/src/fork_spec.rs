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
    /// Block count in epoch
    pub epoch_length: u64,
}

impl ForkSpec {
    /// first = previous last epoch
    /// last = current first epoch
    ///
    /// eg) height = 1501
    /// first = 1400
    /// mid = [1600, 1800]
    /// last = 2000
    ///
    /// in Lorentz HF
    /// eg) height = 1600
    /// first = 1600
    /// mid = [1800]
    /// last = 2000
    ///
    /// eg) height = 1601
    /// first = 1600
    /// mid = [1800]
    /// last = 2000
    ///
    /// eg) height = 1800
    /// first = 1800
    /// mid = []
    /// last = 2000
    ///
    /// eg) height = 2000
    /// first = 2000
    /// mid = []
    /// last = 2000
    pub fn boundary_epochs(&self, prev_fork_spec: &ForkSpec) -> Result<BoundaryEpochs, Error> {
        if let HeightOrTimestamp::Height(height) = self.height_or_timestamp {
            let prev_last = height - (height % prev_fork_spec.epoch_length);
            let current_first = (height..).find(|&h| h % self.epoch_length == 0).unwrap();
            let mut intermediates = vec![];

            // starts 0, 200, 400...epoch_length
            if prev_last == 0 {
                const DEFAULT_EPOCH_LENGTH: u64 = 200;
                let mut mid = prev_last + DEFAULT_EPOCH_LENGTH;
                while mid < prev_fork_spec.epoch_length {
                    intermediates.push(mid);
                    mid += DEFAULT_EPOCH_LENGTH;
                }
            }
            let mut mid = prev_last + prev_fork_spec.epoch_length;
            while mid < current_first {
                intermediates.push(mid);
                mid += prev_fork_spec.epoch_length;
            }
            return Ok(BoundaryEpochs {
                previous_fork_spec: prev_fork_spec.clone(),
                current_fork_spec: self.clone(),
                current_first,
                prev_last,
                intermediates,
            });
        }
        Err(Error::MissingForkHeightIntBoundaryCalculation(self.clone()))
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BoundaryEpochs {
    previous_fork_spec: ForkSpec,
    current_fork_spec: ForkSpec,
    prev_last: BlockNumber,
    current_first: BlockNumber,
    intermediates: alloc::vec::Vec<BlockNumber>,
}

impl BoundaryEpochs {
    pub fn current_fork_spec(&self) -> &ForkSpec {
        &self.current_fork_spec
    }

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

    pub fn previous_epoch_block_number(
        &self,
        current_epoch_block_number: BlockNumber,
    ) -> BlockNumber {
        if current_epoch_block_number == 0 {
            return 0;
        }
        // first or under
        if current_epoch_block_number <= self.prev_last {
            return current_epoch_block_number - self.previous_fork_spec.epoch_length;
        }

        // Hit mids eppchs
        for (i, mid) in self.intermediates.iter().enumerate() {
            if current_epoch_block_number == *mid {
                if i == 0 {
                    return self.prev_last;
                } else {
                    return self.intermediates[i - 1];
                }
            }
        }

        // is just current HF first
        if current_epoch_block_number == self.current_first {
            if self.intermediates.is_empty() {
                return self.prev_last;
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

pub fn get_boundary_epochs(
    current_spec: &ForkSpec,
    fork_specs: &[ForkSpec],
) -> Result<BoundaryEpochs, Error> {
    // find from last to first
    for (i, spec) in fork_specs.iter().enumerate() {
        if spec == current_spec {
            if i == 0 {
                return spec.boundary_epochs(spec);
            }
            return spec.boundary_epochs(&fork_specs[i - 1]);
        }
    }
    Err(Error::MissingPreviousForkSpec(current_spec.clone()))
}

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
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(20),
                additional_header_item_count: 2,
                epoch_length: 200,
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
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(20),
                additional_header_item_count: 2,
                epoch_length: 200,
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
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 20,
                epoch_length: 200,
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
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(20),
                additional_header_item_count: 2,
                epoch_length: 200,
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
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(20),
                additional_header_item_count: 2,
                epoch_length: 200,
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
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 2,
                epoch_length: 200,
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
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(11),
                additional_header_item_count: 2,
                epoch_length: 200,
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
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(11),
                additional_header_item_count: 2,
                epoch_length: 200,
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
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 2,
                epoch_length: 200,
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
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 2,
                epoch_length: 200,
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
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 2,
                epoch_length: 200,
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
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Time(10),
                additional_header_item_count: 2,
                epoch_length: 200,
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
        };
        match current
            .boundary_epochs(&fork_spec_after_pascal())
            .unwrap_err()
        {
            Error::MissingForkHeightIntBoundaryCalculation(e1) => {
                assert_eq!(current, e1);
            }
            _ => unreachable!("unexpected error"),
        }
    }

    #[test]
    fn test_success_boundary_epochs() {
        let mut f1 = fork_spec_after_lorentz().clone();
        f1.height_or_timestamp = HeightOrTimestamp::Height(1501);
        let be = f1.boundary_epochs(&fork_spec_after_pascal()).unwrap();
        assert_eq!(be.prev_last, 1400);
        assert_eq!(be.intermediates, vec![1600, 1800]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(1600);
        let be = f1.boundary_epochs(&fork_spec_after_pascal()).unwrap();
        assert_eq!(be.prev_last, 1600);
        assert_eq!(be.intermediates, vec![1800]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(1601);
        let be = f1.boundary_epochs(&fork_spec_after_pascal()).unwrap();
        assert_eq!(be.prev_last, 1600);
        assert_eq!(be.intermediates, vec![1800]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(1800);
        let be = f1.boundary_epochs(&fork_spec_after_pascal()).unwrap();
        assert_eq!(be.prev_last, 1800);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 2000);

        f1.height_or_timestamp = HeightOrTimestamp::Height(2000);
        let be = f1.boundary_epochs(&fork_spec_after_pascal()).unwrap();
        assert_eq!(be.prev_last, 2000);
        assert_eq!(be.intermediates, vec![]);
        assert_eq!(be.current_first, 2000);
    }

    #[test]
    fn test_success_boundary_epochs_lorentz_pascal() {
        let be = fork_spec_after_lorentz()
            .boundary_epochs(&fork_spec_after_pascal())
            .unwrap();
        assert_eq!(be.prev_last, 0);
        assert_eq!(be.intermediates[0], 200);
        assert_eq!(be.intermediates[1], 400);
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
            .boundary_epochs(&fork_spec_after_lorentz())
            .unwrap();
        assert_eq!(be.prev_last, 0);
        assert_eq!(be.intermediates[0], 200);
        assert_eq!(be.intermediates[1], 400);
        assert_eq!(be.intermediates[2], 500);
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
    fn test_error_get_boundary_epochs() {
        let specs = &[
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(10),
                additional_header_item_count: 1,
                epoch_length: 200,
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(20),
                additional_header_item_count: 2,
                epoch_length: 200,
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
            },
            ForkSpec {
                height_or_timestamp: HeightOrTimestamp::Height(20),
                additional_header_item_count: 2,
                epoch_length: 500,
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
