# TokenShield - Decentralized Token Security Audit Platform

## Overview

TokenShield is a comprehensive smart contract security auditing system built on Stacks blockchain that protects users from malicious tokens, honeypots, and rug pulls through multi-layered risk analysis and community-driven intelligence.

## Features

### Core Capabilities
- **Real-time Token Risk Assessment**: Advanced scoring algorithms analyze multiple risk factors
- **Forensic Transaction Analysis**: Detect suspicious patterns and anomalies
- **Community-Driven Threat Intelligence**: Collaborative database of known threats
- **Professional Auditor System**: Reputation-based security analyst framework
- **Automated Detection**: Identify honeypots and potential rug pulls
- **Whitelist Management**: Maintain registry of verified safe tokens

### Key Components
- Multi-factor risk scoring (0-100 scale)
- Four-tier risk classification system
- Transaction pattern analysis
- Whale wallet concentration tracking
- Fee structure analysis (buy/sell/transfer)
- Contract control function detection
- Ownership and verification status tracking

## Architecture

### Data Structures

#### Token Audit Results
Stores comprehensive audit data for each analyzed token:
- Risk metrics (score, tier, malicious flag)
- Token economics (liquidity, holder count, whale concentration)
- Fee structure (buy, sell, transfer fees)
- Control functions (pause, blacklist, transaction limits)
- Contract metadata (verification, ownership, creation block)
- Audit metadata (auditor, timestamp, community feedback)

#### Threat Intelligence Registry
Maintains risk profiles for wallet addresses:
- Risk scoring and suspicious activity tracking
- Blacklist status and honeypot associations
- Activity timeline and report history

#### Safe Token Registry
Whitelist of verified safe tokens with endorsement tracking

#### Auditor Reputation System
Professional auditor performance metrics and certification status

### Risk Tiers
1. **SAFE** (1): Risk score 0-25
2. **CAUTION** (2): Risk score 26-50
3. **WARNING** (3): Risk score 51-75
4. **DANGER** (4): Risk score 76-100

## Installation

### Prerequisites
- Stacks blockchain node or access to Stacks API
- Clarinet CLI for local development and testing
- Basic understanding of Clarity smart contracts

### Deployment Steps

1. Clone the repository:
```bash
git clone repository
cd repository
```

2. Install Clarinet:
```bash
curl -L https://github.com/hirosystems/clarinet/releases/download/v1.0.0/clarinet-linux-x64.tar.gz | tar xz
sudo mv clarinet /usr/local/bin
```

3. Run tests:
```bash
clarinet test
```

4. Deploy to testnet:
```bash
clarinet deploy --testnet
```

## Usage

### For Users

#### Check Token Risk Score
```clarity
(contract-call? .tokenshield get-token-risk-score 'SP2TOKEN...)
```

#### Get Full Audit Report
```clarity
(contract-call? .tokenshield get-token-audit-report 'SP2TOKEN...)
```

#### Check if Token is Malicious
```clarity
(contract-call? .tokenshield is-token-malicious 'SP2TOKEN...)
```

#### Verify Safe Token Status
```clarity
(contract-call? .tokenshield is-token-verified-safe 'SP2TOKEN...)
```

### For Auditors

#### Execute Token Audit
```clarity
(contract-call? .tokenshield execute-token-audit
    'SP2TOKEN...     ;; token address
    u5000000         ;; liquidity in USD
    u250             ;; holder count
    u35              ;; top holder percentage
    u3               ;; buy fee %
    u3               ;; sell fee %
    u0               ;; transfer fee %
    false            ;; has pause function
    false            ;; has blacklist function
    false            ;; has transaction limit
    true             ;; ownership renounced
    true             ;; contract verified
)
```

#### Log Transaction Analysis
```clarity
(contract-call? .tokenshield log-transaction-analysis
    'SP2TOKEN...     ;; token address
    0x123...         ;; transaction hash
    'SP2SENDER...    ;; sender address
    'SP2RECEIVER...  ;; receiver address
    u1000000         ;; amount
    u5               ;; slippage %
    false            ;; transaction failed
    u50000           ;; gas used
)
```

### For Administrators

#### Add Safe Token
```clarity
(contract-call? .tokenshield add-safe-token 
    'SP2TOKEN... 
    "KYC verified by TokenShield team"
)
```

#### Blacklist Malicious Address
```clarity
(contract-call? .tokenshield blacklist-address 'SP2MALICIOUS...)
```

#### Certify Professional Auditor
```clarity
(contract-call? .tokenshield certify-auditor 
    'SP2AUDITOR... 
    "DeFi security specialist"
)
```

## API Reference

### Read Functions

| Function | Description | Parameters | Returns |
|----------|-------------|------------|---------|
| `get-token-audit-report` | Get complete audit data | token: principal | Full audit record or none |
| `get-token-risk-score` | Get risk score only | token: principal | uint (0-100) or error |
| `is-token-malicious` | Check malicious flag | token: principal | bool |
| `get-wallet-threat-data` | Get threat intelligence | wallet: principal | Threat record or none |
| `is-token-verified-safe` | Check safe registry | token: principal | bool |
| `get-auditor-reputation` | Get auditor metrics | auditor: principal | Reputation data |
| `calculate-risk-score` | Calculate risk score | Multiple factors | uint (0-100) |
| `get-platform-stats` | Get system statistics | None | Platform metrics |

### Write Functions

| Function | Description | Access |
|----------|-------------|--------|
| `execute-token-audit` | Perform security audit | Public |
| `log-transaction-analysis` | Record transaction data | Public |
| `add-threat-flag` | Flag suspicious address | Public |
| `batch-audit-tokens` | Audit multiple tokens | Public |
| `add-safe-token` | Whitelist token | Admin only |
| `remove-safe-token` | Remove from whitelist | Admin only |
| `blacklist-address` | Ban malicious address | Admin only |
| `transfer-admin` | Change admin | Admin only |
| `certify-auditor` | Certify professional | Admin only |
| `emergency-shutdown` | Disable system | Admin only |

## Risk Assessment

### Risk Score Calculation

The risk score (0-100) is calculated based on:

1. **Liquidity Risk** (0-25 points)
   - Triggered if liquidity < 1000 USD

2. **Holder Risk** (0-20 points)
   - Triggered if holders < 10

3. **Concentration Risk** (0-30 points)
   - Triggered if top holder owns > 10%

4. **Fee Risk** (0-40 points)
   - Buy fee > 25%: +15 points
   - Sell fee > 25%: +25 points

5. **Control Risk** (0-30 points)
   - Has pause function: +12 points
   - Has blacklist function: +18 points

6. **Trust Risk** (0-23 points)
   - Ownership not renounced: +15 points
   - Contract not verified: +8 points

### Automatic Malicious Classification

A token is automatically flagged as malicious if:
- Risk score ≥ 60
- Sell fee > 50% AND buy fee < 5% (honeypot pattern)
- Has blacklist function AND ownership not renounced

## Security Considerations

### Access Control
- Admin functions restricted to platform administrator
- Admin transfer requires current admin authorization
- Emergency shutdown capability for crisis management

### Input Validation
- Principal address validation (non-zero checks)
- Percentage bounds checking (0-100)
- String length validation (max 50 characters)
- Transaction hash length validation (32 bytes)

### Data Integrity
- Immutable audit records (updates create new entries)
- Block height timestamps for all operations
- Auditor accountability through address tracking

### Best Practices
- Always verify multiple audit sources
- Check both risk score and tier classification
- Monitor threat intelligence updates
- Report suspicious activities promptly