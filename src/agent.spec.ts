import { createTransactionEvent, getEthersProvider } from "forta-agent"
import { ethers } from 'hardhat'
import timelock_abi from './timelock_abi.json'
import { loadFixture, time } from '@nomicfoundation/hardhat-network-helpers';
import agent from './agent'
import { Finding } from "forta-agent";
import { FindingSeverity } from "forta-agent";
import { FindingType } from "forta-agent";
import { contract_lost_selfadministration_finding, executor_got_admin_role_finding, executor_got_proposer_role_finding, main_exploit_finding, proposal_lifecycle_violation_finding, role_renounced_finding, role_revoked_finding, untrusted_executor_finding } from "./findings";
import { Contract, Transaction } from "ethers";
import { LogDescription } from "forta-agent";
export const ZERO_BYTES32 = '0x0000000000000000000000000000000000000000000000000000000000000000';

export const random_salt = '0x025e7b0be353a74631ad648c667493c0e1cd31caa4cc2d3520fdc171ea0cc726';

const iface = new ethers.utils.Interface(timelock_abi.filter((e: any) => e.type === 'event'));
const ifaceEvents = iface.format(ethers.utils.FormatTypes.full);
const timelockEvents = Object.fromEntries(Object.values(iface.events).map((e, i) => [e.name, ifaceEvents[i]]))

const { MinDelayChange, CallExecuted, CallScheduled, RoleGranted, RoleRevoked } = timelockEvents;
const { handleTransaction } = agent;

const genOperation = (target: string, value: string, data: string, predecessor: string, salt: string) => {

    const id = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode([
        'address',
        'uint256',
        'bytes',
        'uint256',
        'bytes32',
    ], [
        target,
        value,
        data,
        predecessor,
        salt,
    ]));
    return { id, target, value, data, predecessor, salt };
}


const extract_argument = async (event: LogDescription, argument: string) => {
    return event.args[argument];
}

const TIMELOCK_ADMIN_ROLE = ethers.utils.solidityKeccak256(['string'], ['TIMELOCK_ADMIN_ROLE']);
const PROPOSER_ROLE = ethers.utils.solidityKeccak256(['string'], ['PROPOSER_ROLE']);
const EXECUTOR_ROLE = ethers.utils.solidityKeccak256(['string'], ['EXECUTOR_ROLE']);
const CANCELLER_ROLE = ethers.utils.solidityKeccak256(['string'], ['CANCELLER_ROLE']);


const provider = getEthersProvider();
const createTxEvent = async (contract: Contract, tx: any) => {
    const receipt = await (tx).wait();

    return (
        createTransactionEvent({
            contractAddress: contract.address,
            transaction: tx,
            logs: receipt.logs,
            block: {
                hash: tx.blockHash,
                number: tx.blockNumber,
                timestamp: Date.now(),
            },
        })
    )
}


const deployTimelockFixture = async () => {



    const [admin, proposer, canceller, executor, other] = await ethers.getSigners()

    const TimeLock = await ethers.getContractFactory("TimelockController");

    const timelock = await TimeLock.deploy(100, [proposer.address], [executor.address], admin.address);

    await timelock.deployed()


    return { timelock, admin, proposer, canceller, executor, other };
}




describe("timelock-exploit agent", () => {
    describe("mainExploit", () => {
        it("return correct findings logs", async () => {
            const { timelock, proposer, executor } = await loadFixture(deployTimelockFixture);

            const { target, value, data, predecessor, salt } = genOperation(
                timelock.address,
                '0',
                timelock.interface.encodeFunctionData('updateDelay', ['0']),
                '0x0000000000000000000000000000000000000000000000000000000000000000',
                '0xf8e775b2c5f4d66fb5c7fa800f35ef518c262b6014b3c0aee6ea21bff157f108',
            )

            await timelock.connect(proposer).schedule(
                target,
                value,
                data,
                predecessor,
                salt,
                100,
            );


            await time.increase(100);

            const tx = await timelock.connect(executor).execute(
                target,
                value,
                data,
                predecessor,
                salt
            );

            const txEvent = await createTxEvent(timelock, tx);

            const findings = await handleTransaction(txEvent);

            expect(findings).toStrictEqual([
                Finding.fromObject({
                    name: "TimelockController Minimum Delay Was Set To Zero",
                    description: `${txEvent.from} set TimelockController Minimum Delay to zero`,
                    alertId: "TIMELOCK-ZERO-DELAY",
                    severity: FindingSeverity.Info,
                    type: FindingType.Suspicious,
                    metadata: {
                        contractAddress: timelock.address,
                        tx_hash: tx.hash,
                        old_delay: ethers.utils.hexlify(100)
                    },
                }),
            ]);


        })

        it('lifecycle violation', async () => {
            const { timelock, proposer, executor } = await loadFixture(deployTimelockFixture);

            const { target, value, data, predecessor, salt } = genOperation(
                '0x31754f590B97fD975Eb86938f18Cc304E264D2F2',
                '0',
                '0x3bf92ccc',
                '0x0000000000000000000000000000000000000000000000000000000000000000',
                '0xf8e775b2c5f4d66fb5c7fa800f35ef518c262b6014b3c0aee6ea21bff157f108',
            )

            const tx = await timelock.connect(proposer).schedule(
                target,
                value,
                data,
                predecessor,
                salt,
                100,
            );


            const txEvent = await createTxEvent(timelock, tx);


            const findings = await handleTransaction(txEvent);
            for (let event of txEvent.filterLog([CallScheduled, CallExecuted])) {
                const proposal_id: string = await extract_argument(event, 'id');


                const test_finding = proposal_lifecycle_violation_finding(timelock.address, proposer.address, tx.hash, proposal_id);

                expect(findings).toStrictEqual([test_finding]);

            }
        });
        it('main exploit', async () => {
            const { timelock, admin, proposer, executor, canceller } = await loadFixture(deployTimelockFixture);

            const { target, value, data, predecessor, salt } = genOperation(
                timelock.address,
                '0',
                timelock.interface.encodeFunctionData('updateDelay', ['0']),
                '0x0000000000000000000000000000000000000000000000000000000000000000',
                '0xf8e775b2c5f4d66fb5c7fa800f35ef518c262b6014b3c0aee6ea21bff157f108',
            )

            await timelock.connect(proposer).schedule(
                target,
                value,
                data,
                predecessor,
                salt,
                100,
            );


            await time.increase(100);

            await timelock.connect(executor).execute(
                target,
                value,
                data,
                predecessor,
                salt
            );

            const tx = await timelock.connect(admin).grantRole(CANCELLER_ROLE, canceller.address);


            const txEvent = await createTxEvent(timelock, tx)

            const findings = await handleTransaction(txEvent);

            for (let event of txEvent.filterLog([CallScheduled, CallExecuted])) {
                const proposal_id: string = await extract_argument(event, 'id');

                const test_finding = main_exploit_finding(timelock.address, proposer.address, tx.hash, proposal_id);

                expect(findings).toStrictEqual([test_finding]);

            }


        })
    })

    describe('newRoleForExecutor', () => {
        it('executor got admin role', async () => {
            const { timelock, admin, executor } = await loadFixture(deployTimelockFixture);

            const tx = await timelock.connect(admin).grantRole(TIMELOCK_ADMIN_ROLE, executor.address);


            const findings = await handleTransaction(await createTxEvent(timelock, tx));

            const test_finding = executor_got_admin_role_finding(timelock.address, executor.address, admin.address, tx.hash);

            expect(findings).toStrictEqual([test_finding]);
        });
        it('executor got proposer role', async () => {
            const { timelock, admin, executor } = await loadFixture(deployTimelockFixture);
            const tx = await timelock.connect(admin).grantRole(PROPOSER_ROLE, executor.address);


            const findings = await handleTransaction(await createTxEvent(timelock, tx));

            const test_finding = executor_got_proposer_role_finding(timelock.address, executor.address, admin.address, tx.hash);


            expect(findings).toStrictEqual([test_finding]);
        });
    });

    describe('revokeRole', () => {
        it('contract lost it admin role', async () => {
            const { timelock, admin } = await loadFixture(deployTimelockFixture);
            const tx = await timelock.connect(admin).revokeRole(TIMELOCK_ADMIN_ROLE, timelock.address);

            const findings = await handleTransaction(await createTxEvent(timelock, tx));

            const test_finding = contract_lost_selfadministration_finding(timelock.address, admin.address, tx.hash)

            expect(findings).toStrictEqual([test_finding]);
        });

        it('user removes his own role', async () => {
            const { timelock, admin, executor } = await loadFixture(deployTimelockFixture);
            const tx = await timelock.connect(admin).revokeRole(TIMELOCK_ADMIN_ROLE, admin.address);

            const findings = await handleTransaction(await createTxEvent(timelock, tx));

            const test_finding = role_renounced_finding(timelock.address, admin.address, TIMELOCK_ADMIN_ROLE, tx.hash)

            expect(findings).toStrictEqual([test_finding]);
        });

        it('RoleRevoked event in the log', async () => {
            const { timelock, admin, proposer } = await loadFixture(deployTimelockFixture);
            const tx = await timelock.connect(admin).revokeRole(CANCELLER_ROLE, proposer.address);

            const findings = await handleTransaction(await createTxEvent(timelock, tx));

            const test_finding = role_revoked_finding(timelock.address, proposer.address, admin.address, CANCELLER_ROLE, tx.hash)

            expect(findings).toStrictEqual([test_finding]);
        });
    });
});