//! C3.2: bounded retry of the REAL guest include preprocessor. No host parser.
//! This does not migrate the isolated preprocessor machine to the shared heap.
use super::*;
use crate::anka64::compiler_adapter::resources::growth::workspace::DIRECTORY_SOURCE_LIMIT;

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct PreprocessGrowthPolicy {
    initial: u64,
    maximum: u64,
    attempts: u32,
    work: u64,
}
impl PreprocessGrowthPolicy {
    pub fn new(initial:u64,maximum:u64,attempts:u32,work:u64) -> Result<Self,AnkaPreprocessError> {
        if initial==0 || initial%4096!=0 || maximum%4096!=0 || initial>maximum
            || maximum>1024*1024 || attempts==0 || attempts>16 || work==0
            || work>(ANKAPP_MAX_ROUNDS as u64)*(ANKAPP_QUANTUM as u64) {
            return Err(AnkaPreprocessError::GrowthPolicy);
        }
        Ok(Self {initial,maximum,attempts,work})
    }
    pub(crate) fn maximum_capacity(self)->u64 {self.maximum}
    fn next(self,current:u64,attempts:u32,remaining:u64) -> Result<u64,AnkaPreprocessError> {
        if remaining==0 {return Err(AnkaPreprocessError::WorkExhausted);}
        if attempts>=self.attempts || current>=self.maximum {
            return Err(AnkaPreprocessError::GrowthExhausted);
        }
        // Construction bounds current and maximum to 1 MiB; no doubling wrap.
        Ok((current*2).min(self.maximum))
    }
}

#[derive(Debug,PartialEq,Eq)]
pub struct PreprocessGrowthResult {
    pub source: PreprocessedSource,
    pub attempts: u32,
    /// Conservative dispatched instruction budget, NOT elapsed time or a
    /// hardware performance counter. Charged before each quantum, across retries.
    pub dispatched_budget: u64,
    pub output_capacity: u64,
}

pub(super) fn take_quantum(remaining:&mut u64) -> Result<usize,AnkaPreprocessError> {
    if *remaining==0 {return Err(AnkaPreprocessError::WorkExhausted);}
    let n=(*remaining).min(ANKAPP_QUANTUM as u64);
    *remaining-=n;
    Ok(n as usize)
}

pub(super) fn capacity_reply(ordinary:bool,exit:u64,status:u64,used:u64,capacity:u64) -> bool {
    ordinary && exit==7 && status==7 && used==capacity
}

/// Policy controls output growth only. Existing member/layout/include-depth
/// bounds remain hard failures. The returned source is caller-owned until the
/// Kernel's charged directory-source ingress admits its exact bytes.
pub fn run_ankapp_growing(image:&[u8],bundle:&SourceBundle,policy:PreprocessGrowthPolicy)
    -> Result<PreprocessGrowthResult,AnkaPreprocessError>
{
    run_growing_profile(image,bundle,policy,false)
}
pub(crate) fn run_ankapp_growing_accounted(image:&[u8],bundle:&SourceBundle,policy:PreprocessGrowthPolicy)
    -> Result<PreprocessGrowthResult,AnkaPreprocessError> {
    storage::charge(image,bundle,policy)?;
    run_growing_profile(image,bundle,policy,true)
}
fn run_growing_profile(image:&[u8],bundle:&SourceBundle,policy:PreprocessGrowthPolicy,bounded:bool)
    -> Result<PreprocessGrowthResult,AnkaPreprocessError> {
    let mut capacity=policy.initial;
    let mut remaining=policy.work;
    for attempts in 1..=policy.attempts {
        let mut retryable=false;
        // The attempt's isolated machine is dropped before this call returns.
        let result=run_ankapp_attempt_profile(image,bundle,capacity,&mut remaining,&mut retryable,bounded);
        match result {
            Ok(source)=> {
                if source.bytes.len()>DIRECTORY_SOURCE_LIMIT {return Err(AnkaPreprocessError::GrowthExhausted);}
                return Ok(PreprocessGrowthResult {source,attempts,
                    dispatched_budget:policy.work-remaining,output_capacity:capacity});
            }
            Err(AnkaPreprocessError::PreprocessorRejected(7)) if retryable => {
                capacity=policy.next(capacity,attempts,remaining)?;
            }
            Err(error)=>return Err(error),
        }
    }
    Err(AnkaPreprocessError::GrowthExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn c32_preprocess_policy_bounds_alignment_attempts_and_cumulative_work() {
        for (a,b,n,w) in [(0,4096,1,1),(4095,4096,1,1),(8192,4096,1,1),
            (4096,4097,1,1),(4096,2097152,1,1),(4096,4096,0,1),
            (4096,4096,17,1),(4096,4096,1,0),(4096,4096,1,1000000001)] {
            assert_eq!(PreprocessGrowthPolicy::new(a,b,n,w),Err(AnkaPreprocessError::GrowthPolicy));
        }
        assert!(PreprocessGrowthPolicy::new(4096,1048576,16,1000000000).is_ok());
    }
    #[test]
    fn c32_preprocess_growth_is_strict_finite_and_cannot_reset_work() {
        let p=PreprocessGrowthPolicy::new(4096,12288,3,100017).unwrap();
        let mut work=p.work;assert_eq!(take_quantum(&mut work),Ok(100000));
        assert_eq!(p.next(4096,1,work),Ok(8192));
        assert_eq!(take_quantum(&mut work),Ok(17));
        assert_eq!(take_quantum(&mut work),Err(AnkaPreprocessError::WorkExhausted));
        assert_eq!(p.next(8192,2,work),Err(AnkaPreprocessError::WorkExhausted));
        assert_eq!(p.next(8192,2,1),Ok(12288));
        assert_eq!(p.next(12288,2,1),Err(AnkaPreprocessError::GrowthExhausted));
        assert_eq!(p.next(4096,3,1),Err(AnkaPreprocessError::GrowthExhausted));
    }
    #[test]
    fn c32_preprocess_only_matching_ordinary_full_capacity_reply_retries() {
        assert!(capacity_reply(true,7,7,4096,4096));
        for (ordinary,exit,status,used) in [(false,7,7,4096),(true,0,7,4096),
            (true,7,0,4096),(true,8,8,4096),(true,7,7,4095),(true,7,7,4097)] {
            assert!(!capacity_reply(ordinary,exit,status,used,4096));
        }
    }
    // Hand-written ISA transport probes exercise the actual isolated runner;
    // they are not substitutes for the ignored real ankapp/CC2 acceptance.
    fn probe(exit:i32,full:bool,fault:bool) -> Vec<u8> {
        use crate::anka64::isa::Asm64;
        let mut a=Asm64::new();
        // 0x20000 is one past MOVI's signed 18-bit maximum. Construct the
        // manifest address without widening the ISA immediate contract.
        a.movi(4,(ANKAPP_MANIFEST_VADDR / 2) as i32);
        a.add(4,4,4);
        a.ld(5,4,MAN_RESULT_VADDR as i32);
        a.movi(6,7);a.st(6,5,0);
        if full {a.ld(6,4,MAN_OUTPUT_CAPACITY as i32);} else {a.movi(6,1);}
        a.st(6,5,8);
        if fault {
            // User HALT is an ordinary exit (R0), not a protection fault.
            // The manifest is sealed and granted READ only: this store must
            // fault even after the guest has forged a full capacity reply.
            a.st(6,4,0);
            a.halt(); // unreachable if manifest protection is enforced
        } else {a.movi(0,0);a.movi(1,exit);a.trap(0);}
        a.to_bytes()
    }
    fn bundle() -> SourceBundle {
        SourceBundle::new("main.c",[SourceBundleMember::new("main.c",b"x".to_vec()).unwrap()]).unwrap()
    }
    #[test]
    fn c32_preprocess_real_transport_rejects_capacity_impostors_and_faults() {
        let p=PreprocessGrowthPolicy::new(4096,8192,2,200000).unwrap();
        for (exit,full) in [(0,true),(7,false)] {
            assert_eq!(run_ankapp_growing(&probe(exit,full,false),&bundle(),p),
                Err(AnkaPreprocessError::PreprocessorRejected(7)));
        }
        assert_eq!(run_ankapp_growing(&probe(7,true,true),&bundle(),p),
            Err(AnkaPreprocessError::PreprocessorDidNotExit));
    }
    #[test]
    fn c32_preprocess_real_capacity_retries_spend_one_shared_budget() {
        let image=probe(7,true,false);
        assert_eq!(run_ankapp_growing(&image,&bundle(),
            PreprocessGrowthPolicy::new(4096,16384,3,200000).unwrap()),
            Err(AnkaPreprocessError::WorkExhausted));
        assert_eq!(run_ankapp_growing(&image,&bundle(),
            PreprocessGrowthPolicy::new(4096,8192,2,300000).unwrap()),
            Err(AnkaPreprocessError::GrowthExhausted));
    }

}
