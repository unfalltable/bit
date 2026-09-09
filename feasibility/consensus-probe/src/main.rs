//! Real ABCI 2.0 plumbing and deterministic emission experiment.
//! No user transactions, shielded ledger, staking authorization, or production database.
mod economics;
use anyhow::{ensure,Result};
use economics::{Supply,GENESIS};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{self,File,OpenOptions},io::Write,path::{Path,PathBuf},sync::{Arc,Mutex}};
use tendermint_abci::{Application,ServerBuilder};
use tendermint_proto::v0_38::{abci::*,crypto::{public_key,PublicKey}};

#[derive(Clone,Debug,Serialize,Deserialize)]
struct State { height:i64, supply:Supply, first_validator:Vec<u8> }
impl State {
    fn initial()->Self{Self{height:0,supply:Supply::new(GENESIS,2).unwrap(),first_validator:vec![]}}
    fn bytes(&self)->Vec<u8>{serde_json::to_vec(self).unwrap()}
    fn hash(&self)->Vec<u8>{Sha256::digest(self.bytes()).to_vec()}
    fn advance(&self,height:i64)->Result<Self>{
        ensure!(height==self.height+1,"unexpected height");
        let mut next=self.clone();next.height=height;
        if height>1 && (height-1)%10==0 {let e=next.supply.completed;next.supply.settle(e,true)?;}
        ensure!(next.supply.completed==((height-1)/10)as u64,"epoch mismatch");
        next.supply.check()?;Ok(next)
    }
}
struct Inner{committed:State,pending:Option<State>,directory:PathBuf,crash_height:i64,crash_phase:String}
#[derive(Clone)]struct App(Arc<Mutex<Inner>>);

fn persist(directory:&Path,state:&State)->Result<()>{
    let temp=directory.join("state.pending");
    let mut file=File::create(&temp)?;file.write_all(&state.bytes())?;file.sync_all()?;
    fs::rename(temp,directory.join("state.json"))?;
    // Per-height copies allow the harness to compare independent nodes at the same height.
    let mut history=File::create(directory.join(format!("state-{}.json",state.height)))?;
    history.write_all(&state.bytes())?;history.sync_all()?;Ok(())
}
fn crash_once(inner:&Inner,height:i64,phase:&str){
    if inner.crash_height==height && inner.crash_phase==phase {
        let marker=inner.directory.join("fault-injected.marker");
        if let Ok(mut f)=OpenOptions::new().write(true).create_new(true).open(marker){
            writeln!(f,"height={height}, phase={phase}").unwrap();f.sync_all().unwrap();
            std::process::exit(86);
        }
    }
}
impl Application for App {
    fn info(&self,_:RequestInfo)->ResponseInfo{
        let i=self.0.lock().unwrap();
        ResponseInfo{data:"BIT_FEASIBILITY_ONLY_NO_USER_TX".into(),version:"0.1.0".into(),app_version:1,last_block_height:i.committed.height,last_block_app_hash:if i.committed.height==0{vec![].into()}else{i.committed.hash().into()}}
    }
    fn init_chain(&self,request:RequestInitChain)->ResponseInitChain{
        assert!(request.chain_id.starts_with("bit-feasibility-"),"experimental chain only");
        assert_eq!(request.validators.len(),4,"four validators required");
        let mut keys:Vec<Vec<u8>>=request.validators.iter().map(|v|match &v.pub_key.as_ref().unwrap().sum{Some(public_key::Sum::Ed25519(k))=>k.clone(),_=>panic!("ed25519 fixture required")}).collect();keys.sort();
        let mut i=self.0.lock().unwrap();i.committed.first_validator=keys.remove(0);persist(&i.directory,&i.committed).unwrap();
        ResponseInitChain{validators:request.validators,app_hash:i.committed.hash().into(),..Default::default()}
    }
    fn query(&self,_:RequestQuery)->ResponseQuery{
        let i=self.0.lock().unwrap();ResponseQuery{code:0,value:i.committed.bytes().into(),height:i.committed.height,log:"unproved experiment state; not a BIT wallet API".into(),..Default::default()}
    }
    fn check_tx(&self,_:RequestCheckTx)->ResponseCheckTx{ResponseCheckTx{code:1,log:"no user transactions in this experiment".into(),..Default::default()}}
    fn prepare_proposal(&self,_:RequestPrepareProposal)->ResponsePrepareProposal{ResponsePrepareProposal{txs:vec![]}}
    fn process_proposal(&self,r:RequestProcessProposal)->ResponseProcessProposal{
        let i=self.0.lock().unwrap();let ok=r.txs.is_empty()&&i.committed.advance(r.height).is_ok();
        ResponseProcessProposal{status:if ok{response_process_proposal::ProposalStatus::Accept}else{response_process_proposal::ProposalStatus::Reject}as i32}
    }
    fn finalize_block(&self,r:RequestFinalizeBlock)->ResponseFinalizeBlock{
        assert!(r.txs.is_empty(),"fixture rejects nonempty proposals");
        let mut i=self.0.lock().unwrap();
        let next=i.committed.advance(r.height).expect("deterministic state failure");
        let updates=if r.height==5{vec![ValidatorUpdate{pub_key:Some(PublicKey{sum:Some(public_key::Sum::Ed25519(next.first_validator.clone()))}),power:11}]}else{vec![]};
        let hash=next.hash();i.pending=Some(next);
        crash_once(&i,r.height,"after-finalize");
        ResponseFinalizeBlock{validator_updates:updates,app_hash:hash.into(),..Default::default()}
    }
    fn commit(&self)->ResponseCommit{
        let mut i=self.0.lock().unwrap();let next=i.pending.take().expect("commit requires finalized state");
        persist(&i.directory,&next).expect("durable state write");i.committed=next;
        crash_once(&i,i.committed.height,"after-commit");
        ResponseCommit{retain_height:0}
    }
}
fn main()->Result<()>{
    let args:Vec<_>=std::env::args().collect();
    ensure!(args.len()>=3,"usage: bit-consensus-probe LISTEN DIRECTORY [CRASH_HEIGHT CRASH_PHASE]");
    let directory=PathBuf::from(&args[2]);fs::create_dir_all(&directory)?;
    let state=directory.join("state.json");
    let committed:State=if state.exists(){serde_json::from_slice(&fs::read(state)?)?}else{State::initial()};committed.supply.check()?;
    let app=App(Arc::new(Mutex::new(Inner{committed,pending:None,directory,crash_height:args.get(3).map(|s|s.parse()).transpose()?.unwrap_or(-1),crash_phase:args.get(4).cloned().unwrap_or_default()})));
    eprintln!("BIT feasibility ABCI only; no real value; listening {}",args[1]);
    ServerBuilder::new(1024*1024).bind(&args[1],app)?.listen()?;Ok(())
}

#[cfg(test)]mod tests{
use super::*;
#[test]fn first_settlement_and_replay(){let mut s=State::initial();for h in 1..11{s=s.advance(h).unwrap();assert_eq!(s.supply.completed,0);}let next=s.advance(11).unwrap();assert_eq!(next.supply.completed,1);assert_eq!(next.hash(),s.advance(11).unwrap().hash());assert!(next.advance(11).is_err());}
#[test]fn serialization_root_stable(){let mut s=State::initial();for h in 1..30{s=s.advance(h).unwrap();}let roundtrip:State=serde_json::from_slice(&s.bytes()).unwrap();assert_eq!(s.hash(),roundtrip.hash());}
}
