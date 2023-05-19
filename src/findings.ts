import {
    Finding,
    FindingSeverity,
    FindingType,
} from "forta-agent";

export const zero_delay_finding = (contractAddress: string, from_: string, tx_hash: string, old_delay: string) => {
    return Finding.fromObject({
        name: 'TimelockController Minimum Delay Was Set To Zero',
        description: `${from_} set TimelockController Minimum Delay to zero`,
        alertId: 'TIMELOCK-ZERO-DELAY',
        type: FindingType.Suspicious,
        severity: FindingSeverity.Info,
        metadata: {
            contractAddress,
            tx_hash,
            old_delay
        }
    });
};

export const main_exploit_finding = (contractAddress: string, from_: string, tx_hash: string, proposal_id: string) => {
    return Finding.fromObject({
        name: 'TimelockController Exploit Alert',
        description: `${from_} exploit TimelockController ${contractAddress}`,
        alertId: 'TIMELOCK-EXPLOIT',
        type: FindingType.Exploit,
        severity: FindingSeverity.Critical,
        metadata: {
            contractAddress,
            executor: from_,
            tx_hash,
            proposal_id
        }
    });
};

export const proposal_lifecycle_violation_finding = (contractAddress: string, from_: string, tx_hash: string, proposal_id: string) => {
    return Finding.fromObject({
        name: 'TimelockController Proposal Lifecycle Violation',
        description: `Proposal ${proposal_id} for contact ${contractAddress} was executed before scheduled`,
        alertId: 'TIMELOCK-PROPOSAL-LIFECYCLE-VIOLATION',
        type: FindingType.Suspicious,
        severity: FindingSeverity.Critical,
        metadata: {
            contractAddress,
            executor: from_,
            tx_hash,
            proposal_id
        }
    });
};

export const executor_got_proposer_role_finding = (contractAddress: string, accountAddress: string, from_: string, tx_hash: string) => {
    return Finding.fromObject({
        name: 'TimelockController Executor Got Proposer Role',
        description: `TimelockController ${contractAddress} executor ${accountAddress} get proposer role`,
        alertId: 'TIMELOCK-EXECUTOR-PROPOSER',
        type: FindingType.Suspicious,
        severity: FindingSeverity.Medium,
        metadata: {
            contractAddress,
            executor: accountAddress,
            initiator: from_,
            tx_hash
        }
    });
};

export const executor_got_admin_role_finding = (contractAddress: string, accountAddress: string, from_: string, tx_hash: string) => {
    return Finding.fromObject({
        name: 'TimelockController Executor Got Admin Role',
        description: `TimelockController ${contractAddress} executor ${accountAddress} get admin role`,
        alertId: 'TIMELOCK-EXECUTOR-ADMIN',
        type: FindingType.Suspicious,
        severity: FindingSeverity.Medium,
        metadata: {
            contractAddress,
            executor: accountAddress,
            initiator: from_,
            tx_hash
        }
    });
};

export const untrusted_executor_finding = (contractAddress: string, from_: string) => {
    return Finding.fromObject({
        name: 'TimelockController Untrusted Executor',
        description: `TimelockController executor ${from_} is untrusted`,
        alertId: 'TIMELOCK-UNTRUSTED-EXECUTOR',
        type: FindingType.Suspicious,
        severity: FindingSeverity.High,
        metadata: {
            contractAddress,
            executor: from_
        }
    });
};

export const contract_lost_selfadministration_finding = (contractAddress: string, sender: string, tx_hash: string) => {
    return Finding.fromObject({
        name: 'Contract Lost Its Admin Role',
        description: `Contract's ${contractAddress} role "ADMIN" was revoked`,
        alertId: 'TIMELOCK-ADMIN-REVOKED',
        type: FindingType.Suspicious,
        severity: FindingSeverity.High,
        metadata: {
            contractAddress,
            from: sender,
            tx_hash
        }
    });
};

export const role_renounced_finding = (contractAddress: string, sender: string, role: string, tx_hash: string) => {
    return Finding.fromObject({
        name: 'Address Renounced Its Role',
        description: `Address ${sender} renounced its own role ${role}`,
        alertId: 'TIMELOCK-ROLE-RENOUNCED',
        type: FindingType.Info,
        severity: FindingSeverity.Medium,
        metadata: {
            contractAddress,
            from: sender,
            role,
            tx_hash
        }
    });
};

export const role_revoked_finding = (contractAddress: string, accountAddress: string, sender: string, role: string, tx_hash: string) => {
    return Finding.fromObject({
        name: 'Role Revoked Event',
        description: `Address ${sender} revoked role ${role} of the address ${accountAddress}`,
        alertId: 'TIMELOCK-ADMIN-REVOKED',
        type: FindingType.Info,
        severity: FindingSeverity.Medium,
        metadata: {
            contractAddress,
            accountAddress,
            from: sender,
            role,
            tx_hash
        }
    });
};