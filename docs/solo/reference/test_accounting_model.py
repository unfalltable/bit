"""Only tests the reference oracle. No actual chain or ZK testing is claimed."""
import random
import unittest
from copy import deepcopy
from accounting_model import Ledger, ModelError, amount, share_quote, redeem_quote, emission, MAX_AMOUNT

class AccountingTests(unittest.TestCase):
    def funded(self, value=10**8):
        x=Ledger(value); x.claim_genesis(); return x

    def test_genesis_single_claim(self):
        x=Ledger(1000); self.assertEqual(x.claim_genesis(fee=3),997)
        with self.assertRaises(ModelError): x.claim_genesis()
        self.assertEqual(x.total,1000)

    def test_amount_boundaries(self):
        self.assertEqual(amount(MAX_AMOUNT-1),MAX_AMOUNT-1)
        for bad in [-1,MAX_AMOUNT,True,1.0,"2"]:
            with self.assertRaises(ModelError):amount(bad)

    def test_deposit_floor_and_last_redemption(self):
        self.assertEqual(share_quote(3,2,2),1)
        self.assertEqual(redeem_quote(7,3,1),2)
        self.assertEqual(redeem_quote(7,3,3),7)
        with self.assertRaises(ModelError):share_quote(100,1,1)

    def test_pending_no_reward(self):
        x=self.funded(); x.delegate('a',10000)
        self.assertEqual(x.reward(300),0); self.assertEqual(x.pending['a'],10000)
        x.activate('a'); x.reward(300,0); self.assertEqual(x.p,10300)

    def test_reward_commission_total(self):
        x=self.funded();x.delegate('a',10000,10);x.activate('a')
        x.reward(990,500)
        self.assertEqual((x.p,x.commission,x.fees),(10950,50,0))
        self.assertEqual(x.total,x.genesis+990)

    def test_cap_clipping(self):
        x=Ledger(1000,1005);x.claim_genesis();x.delegate('a',500);x.activate('a')
        self.assertEqual(x.reward(100),5);self.assertEqual(x.reward(100),0)
        self.assertEqual(x.total,1005)

    def test_no_eligible_no_mint(self):
        x=self.funded();x.delegate('a',10000,3);x.activate('a')
        self.assertEqual(x.reward(100,eligible=False),0)
        self.assertEqual(x.fees,3)

    def test_failed_action_atomic(self):
        x=self.funded();x.delegate('a',100)
        before=deepcopy(x.__dict__)
        with self.assertRaises(ModelError):x.activate('a',101)
        self.assertEqual(x.__dict__,before)

    def test_cancel_pending_fee_release(self):
        x=self.funded();x.delegate('a',1000);x.cancel_pending('a',7)
        self.assertEqual(x.q,x.genesis-7);self.assertEqual(x.fees,7)

    def test_all_funds_staked_can_exit(self):
        x=self.funded(10000);x.delegate('a',10000);x.activate('a')
        self.assertEqual(x.q,0)
        x.unbond('a',10000,'t',1,722,3610,fee=10)
        self.assertEqual(x.cohorts[1].assets,9990)
        net=x.claim_exit('t',722+241921,3610+1209601,fee=10)
        self.assertEqual(net,9980);self.assertEqual(x.q,9980)
        self.assertEqual(x.fees,20)

    def test_maturity_requires_both_strict_bounds(self):
        x=self.funded();x.delegate('a',1000);x.activate('a')
        x.unbond('a',1000,'t',1,722,3610)
        for h,t in [(722+241920,3610+1209601),(722+241921,3610+1209600)]:
            with self.assertRaises(ModelError):x.claim_exit('t',h,t)
        with self.assertRaises(ModelError):x.claim_exit('t',10**9,10**9,slash_pending=True)
        x.claim_exit('t',722+241921,3610+1209601)

    def test_repeat_exit_claim_rejected(self):
        x=self.funded();x.delegate('a',1000);x.activate('a')
        x.unbond('a',1000,'t',1,722,3610);x.claim_exit('t',10**9,10**9)
        with self.assertRaises(ModelError):x.claim_exit('t',10**9,10**9)

    def test_penalty_active_exit_not_pending(self):
        x=self.funded();x.delegate('a',10000);x.activate('a');x.delegate('b',2000)
        x.unbond('a',4000,'t',1,722,3610)
        self.assertEqual(x.slash('e',721,500),500)
        self.assertEqual(x.pending['b'],2000)
        self.assertEqual((x.p,x.cohorts[1].assets),(5700,3800))
        self.assertEqual(x.slash('e',721),0)
        self.assertEqual(x.slash('different-evidence',722),0)
        x.claim_exit('t',10**9,10**9)

    def test_cohort_outside_exposure_not_slashed(self):
        x=self.funded();x.delegate('a',10000);x.activate('a')
        x.unbond('a',4000,'t',1,722,3610)
        self.assertEqual(x.slash('e',723,500),300)
        self.assertEqual(x.cohorts[1].assets,4000)

    def test_shielded_fee_source(self):
        x=self.funded();x.delegate('a',10000);x.activate('a');q=x.q
        x.unbond('a',10000,'t',1,722,3610,fee=10,released=False)
        self.assertEqual(x.q,q-10);self.assertEqual(x.cohorts[1].assets,10000)
        x.claim_exit('t',10**9,10**9,fee=10,released=False)
        self.assertEqual(x.q,x.genesis-20)

    def test_commission_claim(self):
        x=self.funded();x.delegate('a',10000);x.activate('a');x.reward(1000,1000)
        self.assertEqual(x.claim_commission(100,fee=1),99)
        self.assertEqual(x.commission,0)
        with self.assertRaises(ModelError):x.claim_commission(1)

    def test_last_pool_and_cohort_no_dust(self):
        x=self.funded();x.delegate('a',300);x.activate('a');x.reward(7,0)
        x.unbond('a',100,'t1',1,722,3610);x.unbond('a',200,'t2',1,722,3610)
        self.assertEqual((x.p,x.s),(0,0))
        x.claim_exit('t1',10**9,10**9);x.claim_exit('t2',10**9,10**9)
        self.assertEqual((x.cohorts[1].assets,x.cohorts[1].shares),(0,0))

    def test_fractional_emission_carry(self):
        supply=123456789;carry=0;minted=0;n=500
        for _ in range(n):
            m,carry=emission(supply,carry);minted+=m
        self.assertEqual(minted,supply*200*720*n//(10000*6307200))

    def test_insolvent_generation_rejects_deposit(self):
        with self.assertRaises(ModelError):share_quote(0,100,100)

    def test_seeded_random_accounting_sequences(self):
        # 40 seeds × 80 operations: accounting invariant checked on each success/failure.
        for seed in range(40):
            r=random.Random(seed);x=self.funded(10**10);counter=0
            for i in range(80):
                action=r.randrange(5)
                before=deepcopy(x.__dict__)
                try:
                    if action==0:
                        p=f'p{counter}';counter+=1
                        x.delegate(p,r.randrange(1000,100000),r.randrange(0,20));x.activate(p)
                    elif action==1:x.reward(r.randrange(0,10000),r.randrange(0,2001))
                    elif action==2:
                        live=[p for p,s in x.positions.items() if s>0]
                        if live:
                            p=r.choice(live);u=r.randint(1,x.positions[p])
                            x.unbond(p,u,f't{seed}-{i}',i,720*i+2,3600*i+10,fee=0)
                    elif action==3:
                        live=[t for t,v in x.tickets.items() if not v.claimed]
                        if live:x.claim_exit(r.choice(live),10**9,10**12,fee=0)
                    else:x.pay_fee(r.randrange(0,20))
                except ModelError:
                    # A delegate followed by activation comprises two transactions,
                    # so a failure may legitimately leave pending. Each is atomic.
                    pass
                x.check()
            x.slash(f'e-{seed}',0,500);x.check()

if __name__ == '__main__':
    unittest.main(verbosity=2)
