//! Independent BIT-v1.2 integer experiment. No keys, transactions, or production storage.
use anyhow::{ensure, Result};
use ethnum::U256;
use serde::{Deserialize, Serialize};
pub const MAX: u128 = 10_240_000_000_000_000_000;
pub const GENESIS: u128 = 10_000_000_000_000_000;

pub fn scheduled(budget: u128, interval: u64, completed: u64) -> Result<u128> {
    ensure!(budget <= MAX && interval > 0, "invalid policy");
    let k = completed / interval;
    let r = completed % interval;
    let remaining = if k >= 128 { 0 } else { budget >> k };
    let era = remaining - remaining / 2;
    Ok(budget - remaining + era.checked_mul(r as u128).ok_or_else(||anyhow::anyhow!("overflow"))? / interval as u128)
}
pub fn quota(budget: u128, interval: u64, epoch: u64) -> Result<u128> {
    Ok(scheduled(budget,interval,epoch.checked_add(1).ok_or_else(||anyhow::anyhow!("epoch overflow"))?)? - scheduled(budget,interval,epoch)?)
}
pub fn proportional(a:u128,b:u128,d:u128)->Result<u128>{
    ensure!(d>0,"zero denominator");
    Ok(u128::try_from(U256::from(a)*U256::from(b)/U256::from(d))?)
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq)]
pub struct Supply {
    #[serde(with="decimal")] pub genesis:u128,
    #[serde(with="decimal")] pub minted:u128,
    #[serde(with="decimal")] pub burned:u128,
    #[serde(with="decimal")] pub forfeited:u128,
    pub completed:u64,
    pub interval:u64,
}
impl Supply {
    pub fn new(genesis:u128,interval:u64)->Result<Self>{
        ensure!(genesis>0 && genesis<MAX && interval>0,"invalid genesis/policy");
        Ok(Self{genesis,minted:0,burned:0,forfeited:0,completed:0,interval})
    }
    pub fn issued(&self)->u128{self.genesis+self.minted}
    pub fn total(&self)->u128{self.issued()-self.burned}
    pub fn check(&self)->Result<()>{
        ensure!(self.genesis>0 && self.genesis<MAX,"genesis bounds");
        let issued=self.genesis.checked_add(self.minted).ok_or_else(||anyhow::anyhow!("overflow"))?;
        ensure!(issued<=MAX && self.burned<=issued,"cap/burn bounds");
        ensure!(self.minted.checked_add(self.forfeited)==Some(scheduled(MAX-self.genesis,self.interval,self.completed)?),"scheduled accounting");
        Ok(())
    }
    pub fn settle(&mut self,expected_epoch:u64,eligible:bool)->Result<u128>{
        self.check()?;
        ensure!(expected_epoch==self.completed,"duplicate/out-of-order settlement");
        let q=quota(MAX-self.genesis,self.interval,self.completed)?;
        let mut next=self.clone();
        if eligible {ensure!(q<=MAX-self.issued(),"cap mismatch");next.minted+=q;} else {next.forfeited+=q;}
        next.completed=next.completed.checked_add(1).ok_or_else(||anyhow::anyhow!("epoch overflow"))?;
        next.check()?;*self=next;Ok(if eligible{q}else{0})
    }
    pub fn burn(&mut self,amount:u128)->Result<()>{
        self.check()?;ensure!(amount<=self.total(),"insufficient assets");self.burned+=amount;self.check()
    }
}
mod decimal {
    use serde::{Deserialize,Deserializer,Serializer};
    pub fn serialize<S:Serializer>(v:&u128,s:S)->Result<S::Ok,S::Error>{s.serialize_str(&v.to_string())}
    pub fn deserialize<'de,D:Deserializer<'de>>(d:D)->Result<u128,D::Error>{
        let s=String::deserialize(d)?;
        if s.is_empty() || !s.bytes().all(|c|c.is_ascii_digit()) || (s.len()>1 && s.starts_with('0')) {return Err(serde::de::Error::custom("canonical decimal required"));}
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)] mod tests {
use super::*;
#[test]fn fixed_cap_and_signed_range(){assert_eq!(MAX,102_400_000_000*100_000_000u128);assert!(MAX>i64::MAX as u128);assert!(MAX/100_000_000<((1u128<<60)-1));}
#[test]fn small_schedule(){let q:Vec<_>=(0..10).map(|i|quota(15,2,i).unwrap()).collect();assert_eq!(q,vec![4,4,2,2,1,1,0,1,0,0]);}
#[test]fn golden_points(){for(e,u,q)in[(0,0,145976027397260),(35039,5114854023972602739,145976027397261),(35040,5115000000000000000,72988013698630),(70080,7672500000000000000,36494006849315),(2242559,10229999999999999999,1),(2242560,10230000000000000000,0)]{assert_eq!(scheduled(MAX-GENESIS,35040,e).unwrap(),u);assert_eq!(quota(MAX-GENESIS,35040,e).unwrap(),q);}}
#[test]fn exhaustive_small_budgets(){for b in 1..150{for h in 1..9{let mut sum=0;for e in 0..h*130{let q=quota(b,h,e).unwrap();sum+=q;assert_eq!(sum,scheduled(b,h,e+1).unwrap());assert!(sum<=b);}assert_eq!(sum,b);}}}
#[test]fn burn_does_not_reopen(){let mut s=Supply::new(GENESIS,1).unwrap();for e in 0..64{s.settle(e,true).unwrap();}assert_eq!(s.issued(),MAX);s.burn(1_000_000).unwrap();assert_eq!(s.settle(64,true).unwrap(),0);assert_eq!(s.issued(),MAX);}
#[test]fn forfeited_does_not_catch_up(){let mut s=Supply::new(GENESIS,1).unwrap();s.settle(0,false).unwrap();let k=s.forfeited;for e in 1..65{s.settle(e,true).unwrap();}assert_eq!(s.issued()+k,MAX);assert!(k>0);}
#[test]fn duplicate_is_atomic(){let mut s=Supply::new(GENESIS,2).unwrap();s.settle(0,true).unwrap();let before=s.clone();assert!(s.settle(0,true).is_err());assert_eq!(s,before);assert!(s.settle(2,true).is_err());assert_eq!(s,before);}
#[test]fn bad_state_rejected(){let mut s=Supply::new(GENESIS,2).unwrap();s.minted=1;assert!(s.settle(0,true).is_err());}
#[test]fn bad_genesis_rejected(){for g in [0,MAX,MAX+1]{assert!(Supply::new(g,2).is_err());}assert!(Supply::new(GENESIS,0).is_err());}
#[test]fn zero_quota_not_finished(){assert_eq!(quota(15,2,6).unwrap(),0);assert!(scheduled(15,2,6).unwrap()<15);assert_eq!(quota(15,2,7).unwrap(),1);}
#[test]fn large_shift_and_horizon(){assert_eq!(scheduled(15,1,128).unwrap(),15);assert!(quota(15,1,u64::MAX).is_err());assert!(scheduled(15,0,1).is_err());}
#[test]fn serialization_big_integer(){let mut s=Supply::new(GENESIS,1).unwrap();s.settle(0,true).unwrap();let text=serde_json::to_string(&s).unwrap();assert!(text.contains("\"minted\":\""));assert_eq!(s,serde_json::from_str(&text).unwrap());}
#[test]fn invalid_numeric_json_rejected(){let mut text=serde_json::to_value(Supply::new(GENESIS,1).unwrap()).unwrap();text["genesis"]=serde_json::json!(1e16);assert!(serde_json::from_value::<Supply>(text).is_err());}
#[test]fn share_u256_intermediate(){let big=(1u128<<119)-1;assert_eq!(proportional(big,big,big).unwrap(),big);assert!(proportional(1,1,0).is_err());}
#[test]fn share_rounding_and_last_exit(){assert_eq!(proportional(2,2,3).unwrap(),1);let p=107;let s=100;let first=proportional(p,33,s).unwrap();let remaining=p-first;assert_eq!(first+remaining,p);}
#[test]fn no_wall_clock_input(){let s=Supply::new(GENESIS,2).unwrap();let recovered:Supply=serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();assert_eq!(s,recovered);assert_eq!(s.completed,0);}
}
