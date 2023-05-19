import {
  Finding,
  HandleTransaction,
  TransactionEvent,
  LogDescription,
  ethers,
  getEthersProvider
} from "forta-agent";

import timelock_abi from './timelock_abi.json'
import { contract_lost_selfadministration_finding, executor_got_admin_role_finding, executor_got_proposer_role_finding, main_exploit_finding, proposal_lifecycle_violation_finding, role_renounced_finding, role_revoked_finding, untrusted_executor_finding, zero_delay_finding } from "./findings";


// function extract specified argument from the event
const extract_argument = async (event: LogDescription, argument: string) => {
  return event.args[argument];
}
// get and format all events from contrat
const iface = new ethers.utils.Interface(timelock_abi.filter((e:any) => e.type === 'event'));
const ifaceEvents = iface.format(ethers.utils.FormatTypes.full);
const timelockEvents = Object.fromEntries(Object.values(iface.events).map((e,i) =>[e.name,ifaceEvents[i]]))

const {MinDelayChange,CallExecuted,CallScheduled, RoleGranted, RoleRevoked} = timelockEvents;
const TIMELOCK_ADMIN_ROLE = ethers.utils.solidityKeccak256(['string'], ['TIMELOCK_ADMIN_ROLE']);
const PROPOSER_ROLE = ethers.utils.solidityKeccak256(['string'], ['PROPOSER_ROLE']);
const EXECUTOR_ROLE = ethers.utils.solidityKeccak256(['string'], ['EXECUTOR_ROLE']);
const CANCELLER_ROLE = ethers.utils.solidityKeccak256(['string'], ['CANCELLER_ROLE']);
const provider = getEthersProvider();



/*** detects TimelockController main vulnerability exploit ***/

const detectMainExploit = async (txEvent: TransactionEvent) => {
  const findings: Finding[] = [];
  const dangerProposalsId: string[] = [];

  // get "MinDelayChange(uint256,uint256)" events from the log
  const MinDelayEvents = txEvent.filterLog(MinDelayChange);

  // get get "CallScheduled(bytes32,uint256,address,uint256,bytes,bytes32,uint256)" and
  // "CallExecuted(bytes32,uint256,address,uint256,bytes)" events from the log
  const SheduledAndExecutedEvents = txEvent.filterLog([CallScheduled,CallExecuted]);

  for (let event of MinDelayEvents) {
    if (await extract_argument(event, "newDuration") == 0) {
      // alert if minDelay is zero
      findings.push(zero_delay_finding(event.address, txEvent.from, txEvent.transaction.hash, (await extract_argument(event, 'oldDuration'))._hex));
    }
  }

  for (let event of SheduledAndExecutedEvents) {
    //  get proposal id from the event
    const proposal_id: string = await extract_argument(event, 'id');
    console.log(event.name);
    
    if (event.name === 'CallExecuted') {
      // add proposal id to danger list if it was executed
      dangerProposalsId.push(proposal_id)
    } else if (event.name === 'CallSheduled') { 
      
      // check if proposal id is in the danger list, which means it was executed already
      if (dangerProposalsId.includes(proposal_id)) {
        // and now check if timelock delay was changed
        for (let finding of findings) {
          if (finding.alertId === 'TIMELOCK-ZERO-DELAY') {
            // alert main exploit
            findings.push(main_exploit_finding(event.address, txEvent.from, txEvent.hash, proposal_id));
          }
        }
      }
    } else {
      // alert proposal lifecycle violation
      findings.push(proposal_lifecycle_violation_finding(event.address, txEvent.from, txEvent.hash, proposal_id))
    }
  }

  return findings;
}

/*** 
 * detects `RoleGranted(bytes32,address,address)` event for the executor and creates 
 * alert when executor gets proposer or admin roles 
***/

const detectNewRoleForExecutor = async (txEvent: TransactionEvent) => {
  
  const findings: Finding[] = [];

   // get `RoleGranted(bytes32,address,address)` events from the log
  const RoleGrantedEvents = txEvent.filterLog(RoleGranted);

  for (let event of RoleGrantedEvents) {
    // get role signature which was granted and address that got the new role
    const role = await extract_argument(event, 'role');

    
    const account = await extract_argument(event, 'account');
    // return empty list if Executor role granted
    
    if (role === EXECUTOR_ROLE) return findings;
    
    const timelock = new ethers.Contract(event.address, timelock_abi, provider);
    // check if address has executor role
    if (timelock.hasRole(EXECUTOR_ROLE, account)) {

      // alert if the executor got proposer role
      if (role === PROPOSER_ROLE) { 
        findings.push(executor_got_proposer_role_finding(event.address, account, txEvent.from, txEvent.hash));
      } 
      // alert if the executor got admin role
      else if (role === TIMELOCK_ADMIN_ROLE) {
        findings.push(executor_got_admin_role_finding(event.address, account, txEvent.from, txEvent.hash));
      }
    }
  }

  return findings;
}

/*** 
 *  detects untrusted executors as described in
 *  https://forum.openzeppelin.com/t/timelockcontroller-vulnerability-post-mortem/14958
***/

const detectUntrustedExecutor = async (txEvent: TransactionEvent) => {
  const findings: Finding[] = [];
  //  get all timelock events from the log
  for (let event of txEvent.filterLog(Object.values(timelockEvents))) {
    const timelock = new ethers.Contract(event.address, timelock_abi, provider);

    // check does address have executor and proposer role
   const has_exec = await timelock.hasRole(EXECUTOR_ROLE, txEvent.from);

     // return empty list if address haven't executor role
     if (!has_exec) return findings;
    const has_prop = await timelock.hasRole(PROPOSER_ROLE, txEvent.from);
  
    // alert if executor hasn't proposer roleextract_argument
    if (has_exec && !has_prop) findings.push(untrusted_executor_finding(event.address, txEvent.from));
  }

  return findings;
}

/*** detects RevokeRole events ***/

const detectRevokeRole = async (txEvent: TransactionEvent) => {
  const findings: Finding[] = [];
  // get `RoleRevoked(bytes32,address,address)` events from the log
  const RoleRevokedEvents = txEvent.filterLog(RoleRevoked);

  for (let event of RoleRevokedEvents) {
    // get role signature which was revoked and address from revoke is happened
    const role = await extract_argument(event, 'role');
    const account = await extract_argument(event, 'account');

    if (txEvent.transaction.to === account && role === TIMELOCK_ADMIN_ROLE) {
      // alert if contract lost its Admin role
      findings.push(contract_lost_selfadministration_finding(account, txEvent.from, txEvent.hash))
    } else if (txEvent.from === account) {
      // alert if user removes his own role
      findings.push(role_renounced_finding(event.address, txEvent.from, role, txEvent.hash))
    } else {
      //  create info-alert if there is RoleRevoked event in the log
      findings.push(role_revoked_finding(event.address, account, txEvent.from, role, txEvent.hash))
    }
  }

  return findings;
}

const handleTransaction: HandleTransaction = async (
  txEvent: TransactionEvent
) => {
  const findings = await Promise.all([
    detectMainExploit(txEvent),
    detectNewRoleForExecutor(txEvent),
    detectUntrustedExecutor(txEvent),
    detectRevokeRole(txEvent)
  ]);

  return findings.flatMap((e) => e.flat());

};

export default {
  handleTransaction,
};
