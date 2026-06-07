# TOPOS REGISTER/PUBLISH — Manual IMS Checklist

1. **Multi-Contact REGISTER (P-CSCF)**
   - Config: `enable_reg_pub=1`, `reg_pub_multi_contact=0`
   - Send REGISTER with 2+ Contact URIs
   - Expect: LM_NOTICE in logs; all bindings in registrar/usrloc

2. **rectime refresh**
   - Config: `methods_update_time=SUBSCRIBE,REGISTER`
   - Send re-REGISTER; query `topos_d.rectime` updates

3. **PUBLISH through presence server**
   - Config: `enable_reg_pub=1`, `mask_callid=1`
   - PUBLISH with Event/SIP-ETag; verify headers preserved after round-trip

4. **methods_noinitial opt-out**
   - Config: `enable_reg_pub=1`, `methods_noinitial=REGISTER`
   - Initial REGISTER skipped by TOPOS (Call-ID not masked)
