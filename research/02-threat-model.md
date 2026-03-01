# 02 - Threat Model

## Primary Threat Actors
1. Opportunistic drainers using leaked private keys.
2. Organized exploit teams chaining vulnerability + laundering routes.
3. Insiders abusing privileged roles or upgrade control.
4. Bots exploiting newly published vulnerabilities.

## Kill Chains
### A. Compromised Signer Drain
1. Key compromise.
2. Privileged transaction from known signer.
3. Rapid, abnormal outflows to fresh addresses.
4. Bridge transfers and fragmentation.

### B. Approval + TransferFrom Drain
1. Victim signs malicious permit/approval.
2. Attacker repeatedly executes `transferFrom`.
3. Funds fan out to staging wallets.
4. Mixed/bridged to exit chains.

### C. Smart Contract Exploit
1. Attack transaction triggers vulnerable logic.
2. TVL extraction from pools/treasury.
3. Flash movement to multiple recipients.
4. Cross-chain laundering.

## Attack Surface Taxonomy
- Wallet level: signer compromise, anomalous nonce behavior.
- Contract level: function misuse, role changes, sudden admin actions.
- Flow level: amount anomalies, burst anomalies, cluster anomalies.
- Ecosystem level: destination contamination (known malicious clusters).

## Detection Opportunities
- Burst velocity and entropy changes.
- New counterparties with high outflow concentration.
- Fast bridge sequence after exploit tx.
- Repeated transfer pattern templates.
- Abnormal privileged call sequence.
