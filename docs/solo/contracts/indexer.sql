-- PostgreSQL 17 schema contract. Public read model, never authoritative funds.
-- Execute through migrations with dedicated roles; secrets/privacy data prohibited.
BEGIN;
CREATE DOMAIN hash32 AS BYTEA CHECK (octet_length(VALUE)=32);
CREATE DOMAIN amount120 AS NUMERIC(37,0)
 CHECK (VALUE>=0 AND VALUE<1329227995784915872903807060280344576);
CREATE DOMAIN uint64n AS NUMERIC(20,0)
 CHECK (VALUE>=0 AND VALUE<=18446744073709551615);
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,applied_at TIMESTAMPTZ NOT NULL);
CREATE TABLE blocks(chain_context hash32 NOT NULL,height uint64n NOT NULL,block_hash hash32 NOT NULL,app_hash hash32 NOT NULL,chain_time TIMESTAMPTZ NOT NULL,tx_count INTEGER NOT NULL CHECK(tx_count>=0),compact_hash hash32 NOT NULL,PRIMARY KEY(chain_context,height),UNIQUE(chain_context,block_hash));
CREATE TABLE transactions_public(chain_context hash32 NOT NULL,tx_id hash32 NOT NULL,height uint64n NOT NULL,tx_index INTEGER NOT NULL CHECK(tx_index>=0),action_type TEXT NOT NULL,fee amount120 NOT NULL,execution_code TEXT NOT NULL,envelope_hash hash32 NOT NULL,position_id hash32,PRIMARY KEY(chain_context,tx_id),UNIQUE(chain_context,height,tx_index),FOREIGN KEY(chain_context,height) REFERENCES blocks(chain_context,height));
-- Intentionally no from_address, to_address, private_amount, IP or device identifiers.
CREATE TABLE validators(chain_context hash32 NOT NULL,validator_id hash32 NOT NULL,operator_pubkey hash32 NOT NULL,consensus_pubkey hash32 NOT NULL,display_name TEXT NOT NULL,status TEXT NOT NULL,pool_assets amount120 NOT NULL,pool_shares amount120 NOT NULL,commission_bps INTEGER NOT NULL CHECK(commission_bps BETWEEN 0 AND 2000),sequence uint64n NOT NULL,state_height uint64n NOT NULL,PRIMARY KEY(chain_context,validator_id));
CREATE TABLE validator_changes(chain_context hash32 NOT NULL,height uint64n NOT NULL,event_index INTEGER NOT NULL,validator_id hash32 NOT NULL,change_type TEXT NOT NULL,public_payload JSONB NOT NULL,PRIMARY KEY(chain_context,height,event_index));
CREATE TABLE stake_positions_public(chain_context hash32 NOT NULL,position_id hash32 NOT NULL,owner_pubkey hash32 NOT NULL,validator_id hash32 NOT NULL,generation uint64n NOT NULL,shares amount120 NOT NULL,pending_amount amount120 NOT NULL,sequence uint64n NOT NULL,status TEXT NOT NULL,state_height uint64n NOT NULL,PRIMARY KEY(chain_context,position_id));
CREATE TABLE exit_cohorts(chain_context hash32 NOT NULL,cohort_id hash32 NOT NULL,validator_id hash32 NOT NULL,exit_epoch uint64n NOT NULL,assets amount120 NOT NULL,units amount120 NOT NULL,exposure_end_height uint64n NOT NULL,exposure_end_time TIMESTAMPTZ,maturity_height uint64n NOT NULL,maturity_time TIMESTAMPTZ,status TEXT NOT NULL,state_height uint64n NOT NULL,PRIMARY KEY(chain_context,cohort_id));
CREATE TABLE exit_tickets_public(chain_context hash32 NOT NULL,ticket_id hash32 NOT NULL,position_id hash32 NOT NULL,cohort_id hash32 NOT NULL,units amount120 NOT NULL,sequence uint64n NOT NULL,claimed BOOLEAN NOT NULL,state_height uint64n NOT NULL,PRIMARY KEY(chain_context,ticket_id));
CREATE TABLE supply_snapshots(chain_context hash32 NOT NULL,height uint64n NOT NULL,total amount120 NOT NULL,genesis amount120 NOT NULL,minted amount120 NOT NULL,burned amount120 NOT NULL,shielded amount120 NOT NULL,stake amount120 NOT NULL,pending amount120 NOT NULL,exits amount120 NOT NULL,commission amount120 NOT NULL,fees amount120 NOT NULL,genesis_unclaimed amount120 NOT NULL,PRIMARY KEY(chain_context,height),CHECK(total=genesis+minted-burned),CHECK(total=shielded+stake+pending+exits+commission+fees+genesis_unclaimed));
CREATE TABLE evidence_events(chain_context hash32 NOT NULL,evidence_hash hash32 NOT NULL,validator_id hash32 NOT NULL,infraction_height uint64n NOT NULL,accepted_height uint64n NOT NULL,penalty_bps INTEGER NOT NULL,burned amount120 NOT NULL,status TEXT NOT NULL,PRIMARY KEY(chain_context,evidence_hash));
CREATE TABLE indexer_cursor(chain_context hash32 PRIMARY KEY,last_height uint64n NOT NULL,last_block_hash hash32 NOT NULL,verified_header_height uint64n NOT NULL);
CREATE INDEX tx_public_height ON transactions_public(chain_context,height,tx_index);
CREATE INDEX positions_validator ON stake_positions_public(chain_context,validator_id);
CREATE INDEX exits_validator ON exit_cohorts(chain_context,validator_id,exit_epoch);
COMMIT;
-- Deployment: create reader/writer roles with administrator-issued credentials;
-- grant only SELECT to reader. Never put passwords in this file.
