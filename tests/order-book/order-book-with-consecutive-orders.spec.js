const fs = require('fs');
const { expect } = require('chai');
const path = require('path');
const {
    IndexerWrapper, getCKBSDK, resetBlocks, sendTransaction, commitTxs, BufferParser,
} = require('../../utils');

describe('order test data for order-book', () => {
    let indexer;
    let deps;
    let defaultLockScript;
    const occupiedCKBAmnt = 179n * 10n ** 8n; // occupied 178, plus 1 more
    const includFeeInPay = 1n + 3n/1000n; // the fee in Pay amount

    const ckb = getCKBSDK();
    const privateKey = '0x01829817e4dead9ec93822574313c74eab20e308e4c9af476f28515aea4f8a2f';
    const publicKey = ckb.utils.privateKeyToPublicKey(privateKey);
    const rootPublicKeyHash = `0x${ckb.utils.blake160(publicKey, 'hex')}`;

    const alicePrivateKey = '0x650f2b74920bc2a3e5e33e5909cac206e38fc5fe8cb8b1596bf631a60057ff0e';
    const alicePublicKey = ckb.utils.privateKeyToPublicKey(alicePrivateKey);
    const alicePublicKeyHash = `0x${ckb.utils.blake160(alicePublicKey, 'hex')}`;
    let aliceLockHash;

    const bobPrivateKey = '0x41f44f049b66b2d095d2c66a04b11b518feb6947b999e2b3d2fc2725e891e273';
    const bobPublicKey = ckb.utils.privateKeyToPublicKey(bobPrivateKey);
    const bobPublicKeyHash = `0x${ckb.utils.blake160(bobPublicKey, 'hex')}`;
    let bobLockHash;

    const dealmakerPrivateKey = '0x44c3c2baf6559ae80516486dc08ce023f6a3911152600c456093c0ad03001d32';
    const dealmakerPublicKey = ckb.utils.privateKeyToPublicKey(dealmakerPrivateKey);
    const dealmakerPublicKeyHash = `0x${ckb.utils.blake160(dealmakerPublicKey, 'hex')}`;

    const calculateTypeIdHash = (input) => {
        const typeIdHash = ckb.utils.blake2b(32, null, null, ckb.utils.PERSONAL);

        const outpointStruct = new Map([['txHash', input.txHash], ['index', ckb.utils.toUint32Le(input.index)]]);
        const serializedOutpoint = ckb.utils.serializeStruct(outpointStruct);
        const serializedSince = ckb.utils.toUint64Le('0x0', 8);
        const inputStruct = new Map([['since', serializedSince], ['previousOutput', serializedOutpoint]]);
        const inputSerialized = ckb.utils.serializeStruct(inputStruct);

        typeIdHash.update(ckb.utils.hexToBytes(inputSerialized));
        typeIdHash.update(ckb.utils.hexToBytes('0x0000000000000000'));
        const id = `0x${typeIdHash.digest('hex')}`;

        return id;
    };

    before(async () => {
        await resetBlocks();
        indexer = new IndexerWrapper();
        deps = await ckb.loadDeps();
        defaultLockScript = {
            hashType: 'type',
            codeHash: deps.secp256k1Dep.codeHash,
            args: rootPublicKeyHash,
        };

        const aliceLock = {
            codeHash: deps.secp256k1Dep.codeHash,
            hashType: 'type',
            args: alicePublicKeyHash,
        };
        aliceLockHash = ckb.utils.scriptToHash(aliceLock);

        const bobLock = {
            codeHash: deps.secp256k1Dep.codeHash,
            hashType: 'type',
            args: bobPublicKeyHash,
        };
        bobLockHash = ckb.utils.scriptToHash(bobLock);
        
    });

    describe('deploy sudt and order lock and create pending orders', () => {
        let typeIdScript;
        let udtScriptDataHex;
        let orderLockScriptDataHex;
        let orderLockCodeHash;
        // let secp256k1SignAllScriptDataHex;

        const sudtCellDep = {
            outPoint: {
                txHash: null,
                index: null,
            },
            depType: 'code',
        };
        const orderCellDep = {
            outPoint: {
                txHash: null,
                index: null,
            },
            depType: 'code',
        };

        const formatScript = (script) => (script ? {
            args: script.args,
            hashType: script.hashType || script.hash_type,
            codeHash: script.codeHash || script.code_hash,
        } : undefined);

        const formatCKB = (capacity) => BigInt(capacity) / (10n ** 8n);

        const generateRawTx = async (inputs, outputs, cellDeps = []) => {
            const tx = {
                version: '0x0',
                headerDeps: [],
                cellDeps: [
                    {
                        outPoint: {
                            txHash: '0x42334ded191bfc39e4f2bae1f6052458e3e4def9cd8d32dc94186c585287d4ff',
                            index: '0x0',
                        },
                        depType: 'depGroup',
                    },
                    ...cellDeps,
                ],
            };

            tx.inputs = inputs.map((input) => ({
                previousOutput: input.outPoint,
                since: '0x0',
            }));

            tx.outputs = outputs.map((output) => ({
                capacity: output.ckbAmount ? `0x${output.ckbAmount.toString(16)}` : `0x${(BigInt(output.ckb) * 10n ** 8n).toString(16)}`,
                lock: formatScript(output.lock),
                type: formatScript(output.type),
            }));

            tx.outputsData = outputs.map((output) => output.data || '0x');

            tx.witnesses = tx.inputs.map((_, i) => (i > 0 ? '0x' : {
                lock: '',
                inputType: '',
                outputType: '',
            }));

            return tx;
        };

        const formatOrderData = (currentAmount, orderAmount, price, isBid) => {
            const udtAmountHex = BufferParser.writeBigUInt128LE(currentAmount);
            if (isBid === undefined) {
                return udtAmountHex;
            }

            const orderAmountHex = BufferParser.writeBigUInt128LE(orderAmount).replace('0x', '');

            const priceBuf = Buffer.alloc(8);
            priceBuf.writeBigUInt64LE(price);
            const priceHex = `${priceBuf.toString('hex')}`;

            const bidOrAskBuf = Buffer.alloc(1);
            bidOrAskBuf.writeInt8(isBid ? 0 : 1);
            const isBidHex = `${bidOrAskBuf.toString('hex')}`;
            const dataHex = udtAmountHex + orderAmountHex + priceHex + isBidHex;
            return dataHex;
        };

        const parseOrderData = (hex) => {
            const sUDTAmount = BufferParser.parseAmountFromSUDTData(hex.slice(0, 34));
            const orderAmount = BufferParser.parseAmountFromSUDTData(hex.slice(34, 66));

            let price;
            try {
                const priceBuf = Buffer.from(hex.slice(66, 82), 'hex');
                price = priceBuf.readBigInt64LE();
            } catch (error) {
                price = null;
            }

            const isBid = hex.slice(82, 84) === '00';

            return {
                sUDTAmount,
                orderAmount,
                price,
                isBid,
            };
        };

        const collectOrderInputs = async (aliceTxHash, bobTxHash) => {
            const aliceOrderLock = {
                codeHash: orderLockCodeHash,
                hashType: 'data',
                args: aliceLockHash,
            };
            const bobOrderLock = {
                codeHash: orderLockCodeHash,
                hashType: 'data',
                args: bobLockHash,
            };
            const dealmakerDefaultLock = {
                ...defaultLockScript,
                args: dealmakerPublicKeyHash,
            };

            const aliceOrderCells = await indexer.collectCells({
                lock: aliceOrderLock,
            });
            const aliceOrderCell = await filterSpecCellByTxHash(aliceTxHash, aliceOrderCells);

            const bobOrderCells = await indexer.collectCells({
                lock: bobOrderLock,
            });
            const bobOrderCell = await filterSpecCellByTxHash(bobTxHash, bobOrderCells);

            const [dealmakerCell] = await indexer.collectCells({
                lock: dealmakerDefaultLock,
            });

            let inputs = [
                dealmakerCell,
                aliceOrderCell,
                bobOrderCell,
            ];

            return inputs;
        };
        
        const filterSpecCellByTxHash = async (txHash, inputs) => {
            for (let i = 0; i < inputs.length; i++) {
                if(inputs[i].outPoint.txHash === txHash) {
                    return inputs[i];
                }
            }
        }

        const generateCreateOrderTx = async ({
            publicKeyHash,
            sudtCurrentAmount,
            orderAmount,
            price,
            isBid,
            ckbAmount,
        }, index) => {
            const cells = await indexer.collectCells({
                lock: { ...defaultLockScript, args: publicKeyHash },
            });

            const inputLock = {
                codeHash: deps.secp256k1Dep.codeHash,
                hashType: 'type',
                args: publicKeyHash,
            };

            const orderLock = {
                codeHash: orderLockCodeHash,
                hashType: 'data',
                args: ckb.utils.scriptToHash(inputLock),
            };

            let uuid;
            uuid = ckb.utils.scriptToHash(defaultLockScript);
            const sudtType = {
                args: uuid,
                hashType: 'type',
                codeHash: ckb.utils.scriptToHash(typeIdScript),
            };

            const inputs = [cells[index]];
            const changeOutput = {
                ckbAmount: BigInt(cells[index].capacity) - ckbAmount - 10n ** 8n,
                type: sudtType,
                lock: { ...defaultLockScript, args: publicKeyHash },
                data: BufferParser.writeBigUInt128LE(BufferParser.parseAmountFromSUDTData(cells[index].data) - sudtCurrentAmount),
            };
            const outputs = [
                {
                    ckbAmount,
                    type: sudtType,
                    lock: orderLock,
                    data: formatOrderData(sudtCurrentAmount, orderAmount, price, isBid),
                },
                changeOutput,
            ];

            const rawTx = await generateRawTx(inputs, outputs, [sudtCellDep]);
            return rawTx;
        };

        // deploy contracts
        before(async () => {
            const cells = await indexer.collectCells({ lock: defaultLockScript });

            const udtBinaryPath = path.join(__dirname, './simple_udt');
            const udtBinaryData = fs.readFileSync(udtBinaryPath);
            udtScriptDataHex = ckb.utils.bytesToHex(udtBinaryData);

            const orderLockBinaryPath = path.join(__dirname, './order-book-contract');
            const orderLockBinaryData = fs.readFileSync(orderLockBinaryPath);
            orderLockScriptDataHex = ckb.utils.bytesToHex(orderLockBinaryData);

            const b = ckb.utils.blake2b(32, null, null, ckb.utils.PERSONAL);
            b.update(orderLockBinaryData);
            orderLockCodeHash = `0x${b.digest('hex')}`;

            const input = cells.find((cell) => cell.data === '0x');
            const typeIdHash = calculateTypeIdHash(input.outPoint);

            typeIdScript = {
                hashType: 'type',
                codeHash: '0x00000000000000000000000000000000000000000000000000545950455f4944',
                args: typeIdHash,
            };

            const inputs = [input];
            const outputs = [
                {
                    ckb: 200000n,
                    lock: input.lock,
                    type: typeIdScript,
                    data: udtScriptDataHex,
                },
                {
                    ckb: 200000n,
                    lock: input.lock,
                    data: orderLockScriptDataHex,
                },
                // {
                //     ckb: 200000n,
                //     lock: input.lock,
                //     data: secp256k1SignAllScriptDataHex,
                // },
                {
                    ckb: 2000000n,
                    lock: input.lock,
                },
            ];

            const rawTx = await generateRawTx(inputs, outputs);
            const signedTx = ckb.signTransaction(privateKey)(rawTx);

            const txHash = await sendTransaction(signedTx);

            sudtCellDep.outPoint.txHash = txHash;
            sudtCellDep.outPoint.index = '0x0';

            orderCellDep.outPoint.txHash = txHash;
            orderCellDep.outPoint.index = '0x1';
        });
        
        // issue sUDT and transfer udt
        before(async() => {
            let uuid;
            uuid = ckb.utils.scriptToHash(defaultLockScript);
            const sudtType = {
                args: uuid,
                hashType: 'type',
                codeHash: ckb.utils.scriptToHash(typeIdScript),
            };

            const issuanceAmount = BigInt('10000000000000000000000000000');
            const normalCells = await indexer.collectCells({ lock: defaultLockScript });
                const normalInput = normalCells.find((normalCells) => normalCells.data === '0x');
                const normalInputs = [normalInput];
                const issueUdtOutputs = [{
                    ckb: 200000n,
                    lock: normalInput.lock,
                    type: {
                        args: uuid,
                        hashType: 'type',
                        codeHash: ckb.utils.scriptToHash(typeIdScript),
                    },
                    data: BufferParser.writeBigUInt128LE(issuanceAmount),
                }];

                const issueUdtRawTx = await generateRawTx(normalInputs, issueUdtOutputs, [sudtCellDep]);
                const issueUdtSignedTx = ckb.signTransaction(privateKey)(issueUdtRawTx);
                await sendTransaction(issueUdtSignedTx);

                // transfer 2 cells of sudt to Alice and Bob:
                const udtCell = (
                    await indexer.collectCells({ lock: defaultLockScript, type: sudtType })
                )[0];

                const udtInputs = [udtCell];
                const udtOutputs = [{
                    ckb: 40000n,
                    type: udtCell.type,
                    lock: {
                        ...udtCell.lock,
                        args: alicePublicKeyHash,
                    },
                    data: BufferParser.writeBigUInt128LE(issuanceAmount / 4n),
                }, {
                    ckb: 40000n,
                    type: udtCell.type,
                    lock: {
                        ...udtCell.lock,
                        args: alicePublicKeyHash,
                    },
                    data: BufferParser.writeBigUInt128LE(issuanceAmount / 4n),
                }, {
                    ckb: 20000n,
                    type: udtCell.type,
                    lock: {
                        ...udtCell.lock,
                        args: bobPublicKeyHash,
                    },
                    data: BufferParser.writeBigUInt128LE(issuanceAmount / 4n),
                }, {
                    ckb: 20000n,
                    type: udtCell.type,
                    lock: {
                        ...udtCell.lock,
                        args: bobPublicKeyHash,
                    },
                    data: BufferParser.writeBigUInt128LE(issuanceAmount / 4n),
                }, {
                    ckb: 20000n,
                    lock: {
                        ...udtCell.lock,
                        args: dealmakerPublicKeyHash,
                    },
                }];

                const udtRawTx = await generateRawTx(udtInputs, udtOutputs, [sudtCellDep]);
                const udtSignedTx = ckb.signTransaction(privateKey)(udtRawTx);

                await sendTransaction(udtSignedTx);
        });

        const createPendingOrderInSameBlock = async (aliceOrder, bobOrder) => {
            const ckb = getCKBSDK();
            const aliceTxHashList = [];
            const bobTxHashList = [];
            const size = aliceOrder.length;

            for (let i = 0; i < size; i++) {
                let aliceRawTx;
                let bobRawTx;
                let aliceTxHash;
                let bobTxHash;
                
                if (aliceOrder) {
                    aliceRawTx = await generateCreateOrderTx(aliceOrder[i], i);
                    aliceTxHash = await ckb.rpc.sendTransaction(ckb.signTransaction(alicePrivateKey)(aliceRawTx));
                }
                if (bobOrder) {
                    bobRawTx = await generateCreateOrderTx(bobOrder[i], i);
                    bobTxHash = await ckb.rpc.sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx));
                } 
                aliceTxHashList.push(aliceTxHash);
                bobTxHashList.push(bobTxHash);
            }
            await commitTxs();

            console.log("aliceTxHashList is: ", aliceTxHashList);
            console.log("bobTxHashList is: ", bobTxHashList);

            for (let i = 0; i < aliceTxHashList.length; i++) {
                console.log("aliceTxHashList[%d], blockNum: %d", i, await getTxBlockNum(aliceTxHashList[i]));
                console.log("bobTxHashList[%d], blockNum: %d", i, await getTxBlockNum(bobTxHashList[i]));
                await logCellsInfo(aliceTxHashList[i], bobTxHashList[i]);
            }

            return {
                aliceTxHashList,
                bobTxHashList,
            };
        };

        const getTxBlockNum = async (txHash) => {
            if (txHash) {
                const getTx = await ckb.rpc.getTransaction(txHash);
                const blockHash = getTx.txStatus.blockHash;
                const getBlockInfo = await ckb.rpc.getBlock(blockHash);
                const blockNum = getBlockInfo.header.number;
                return parseInt(blockNum, 16);                
            } else {
                return "txHash is null!"
            }
        }

        const createPendingOrder = async (aliceOrder, bobOrder, isAliceEarlier) => {
            let aliceRawTx = await generateCreateOrderTx(aliceOrder, 0);
            let bobRawTx = await generateCreateOrderTx(bobOrder, 0);
            let aliceTxHash;
            let bobTxHash;
            if (!isAliceEarlier) {
                bobTxHash = await sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx));
                aliceTxHash = await sendTransaction(ckb.signTransaction(alicePrivateKey)(aliceRawTx));
            } else if (isAliceEarlier) {
                aliceTxHash = await sendTransaction(ckb.signTransaction(alicePrivateKey)(aliceRawTx));
                bobTxHash = await sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx));
            }

            await logCellsInfo(aliceTxHash, bobTxHash);
        };

        const logCellsInfo = async (aliceTxHash, bobTxHash) => {
            const inputs = await collectOrderInputs(aliceTxHash, bobTxHash);
            const [dealmakerCell, aliceOrderCell, bobOrderCell] = inputs;

            console.log("dealmakerCell.capacity: ", formatCKB(BigInt(dealmakerCell.capacity))); 
            console.log("dealmakerCell.data is: ", dealmakerCell.data);
            console.log("OrderData(dealmakerCell.data).sUDTAmount: %d, orderAmount: %d, price: %d, isBid: %d", 
                formatCKB(parseOrderData(dealmakerCell.data).sUDTAmount), formatCKB(parseOrderData(dealmakerCell.data).orderAmount),
                Number(parseOrderData(dealmakerCell.data).price)/10**10, Number(parseOrderData(dealmakerCell.data).isBid)); 

            if (aliceTxHash) {
                console.log("log aliceTxHash %s, blockNumber: ", aliceTxHash, await getTxBlockNum(aliceTxHash));
                console.log("aliceOrderCell.capacity: ", formatCKB(BigInt(aliceOrderCell.capacity))); 
                console.log("aliceOrderCell.data is: ", aliceOrderCell.data);
                console.log("OrderData(aliceOrderCell.data).sUDTAmount: %d, orderAmount: %d, price: %d, isBid: %d", 
                    formatCKB(parseOrderData(aliceOrderCell.data).sUDTAmount), formatCKB(parseOrderData(aliceOrderCell.data).orderAmount),
                    Number(parseOrderData(aliceOrderCell.data).price)/10**10, Number(parseOrderData(aliceOrderCell.data).isBid));
            }
            
            if (bobTxHash) {
                console.log("log bobTxHash %s, blockNumber: ", bobTxHash, await getTxBlockNum(bobTxHash));
                console.log("bobOrderCell.capacity: ", formatCKB(BigInt(bobOrderCell.capacity)));
                console.log("bobOrderCell.data is: ", bobOrderCell.data); 
                console.log("OrderData(bobOrderCell.data).sUDTAmount: %d, orderAmount: %d, price: %d, isBid: %d", 
                    formatCKB(parseOrderData(bobOrderCell.data).sUDTAmount), formatCKB(parseOrderData(bobOrderCell.data).orderAmount),
                    Number(parseOrderData(bobOrderCell.data).price)/10**10, Number(parseOrderData(bobOrderCell.data).isBid)); 
            }
        };

        it('case 0.1: create order cells with exact match price', async() => {
            let bidPrice = 50000000000n;
            let askPrice = bidPrice;

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 5000000000n,
                orderAmount: 15000000000n,
                price: bidPrice,
                isBid: true,
                ckbAmount: 2000n * 10n ** 8n,
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 50000000000n,
                orderAmount: 100000000000n,
                price: askPrice,
                isBid: false,
                ckbAmount: 800n * 10n ** 8n,
            };

            console.log("~~ case 0.1: exact ~~");
            await createPendingOrder(aliceOrder,bobOrder, true);
        });

        it('case 0.2: create order cells with gap price', async() => {
            let bidPrice = 50000000000n;
            let askPrice = 60000000000n;

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 5000000000n,
                orderAmount: 15000000000n,
                price: bidPrice,
                isBid: true,
                ckbAmount: 2000n * 10n ** 8n,
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 50000000000n,
                orderAmount: 100000000000n,
                price: askPrice,
                isBid: false,
                ckbAmount: 800n * 10n ** 8n,
            };

            console.log("~~ case 0.2: gap ~~");
            await createPendingOrder(aliceOrder,bobOrder);
        });

        it('case 0.3: create order cells with overlap price', async() => {
            let bidPrice = 60000000000n;
            let askPrice = 50000000000n;

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 5000000000n,
                orderAmount: 15000000000n,
                price: bidPrice,
                isBid: true,
                ckbAmount: 2000n * 10n ** 8n,
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 50000000000n,
                orderAmount: 100000000000n,
                price: askPrice,
                isBid: false,
                ckbAmount: 800n * 10n ** 8n,
            };

            console.log("~~ case 0.3: overlap1 ~~");
            await createPendingOrder(aliceOrder,bobOrder);
        });

        // orderAmount is the amount of Receive token's
        it('case1.1: same block - bid 1 - ask 1 - order amount all matched', async() => {
            let bidPrice = 10n * 10n ** 10n;
            let askPrice = 9n * 10n ** 10n;

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 100n * 10n ** 8n ,
                price: bidPrice,
                isBid: true,
                ckbAmount: 100300000000n + occupiedCKBAmnt, //1003
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 100n * 10n ** 8n * includFeeInPay, //the Pay udt should include fee
                orderAmount: 100n * 10n ** 8n * askPrice/10n**10n, //the Receive ckb amount for ask order
                price: askPrice,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 1.1: ~~");
            await createPendingOrderInSameBlock([aliceOrder],[bobOrder]);
        });

        it('case1.2: diff block - ask earlier - bid 1 - ask 1 - order amount all matched', async() => {
            let bidPrice = 10n * 10n ** 10n;
            let askPrice = 9n * 10n ** 10n;

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 100n * 10n ** 8n ,
                price: bidPrice,
                isBid: true,
                ckbAmount: 100300000000n + occupiedCKBAmnt, //1003
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 100n * 10n ** 8n * includFeeInPay, //the Pay udt should include fee
                orderAmount: 100n * 10n ** 8n * askPrice / 10n**10n, //the Receive ckb amount for ask order
                price: askPrice,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 1.2: ~~");
            await createPendingOrder(aliceOrder, bobOrder, false);
        });

        it('case2.1: same block - bid 1 - ask 1 - order amount partial dealt & bid remaining', async() => {
            let bidPrice = 10n * 10n ** 10n; //10
            let askPrice = 9n * 10n ** 10n; //9

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 120n * 10n ** 8n,
                price: bidPrice,
                isBid: true,
                ckbAmount: 120360000000n + occupiedCKBAmnt, //1203.6
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 100n * 10n ** 8n * includFeeInPay,
                orderAmount: 100n * 10n ** 8n * askPrice / 10n**10n, 
                price: askPrice,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 2.1: ~~");
            await createPendingOrderInSameBlock([aliceOrder],[bobOrder]);
        });

        it('case2.2: diff block - ask earlier - bid 1 - ask 1 - order amount partial dealt & bid remaining', async() => {
            let bidPrice = 10n * 10n ** 10n;
            let askPrice = 9n * 10n ** 10n;

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 120n * 10n ** 8n,
                price: bidPrice,
                isBid: true,
                ckbAmount: 120360000000n + occupiedCKBAmnt, //1203.6
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 100n * 10n ** 8n * includFeeInPay,
                orderAmount: 100n * 10n ** 8n * askPrice / 10n**10n, 
                price: askPrice,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 2.2: ~~");
            await createPendingOrder(aliceOrder, bobOrder, false);
        });

        it('case3.1: same block - bid 1 - ask 1 - order amount partial dealt & ask remaining', async() => {
            let bidPrice = 10n * 10n ** 10n;
            let askPrice = 9n * 10n ** 10n;

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 50n * 10n ** 8n,
                price: bidPrice,
                isBid: true,
                ckbAmount: 50150000000n + occupiedCKBAmnt, //501.5
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 130n * 10n ** 8n * includFeeInPay,
                orderAmount: 130n * 10n ** 8n * askPrice / 10n**10n, 
                price: askPrice,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 3.1: ~~");
            await createPendingOrderInSameBlock([aliceOrder],[bobOrder]);
        });

        it('case3.2: diff block - ask earlier - bid 1 - ask 1 - order amount partial dealt & ask remaining', async() => {
            let bidPrice = 10n * 10n ** 10n;
            let askPrice = 9n * 10n ** 10n;

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 100n * 10n ** 8n,
                price: bidPrice,
                isBid: true,
                ckbAmount: 100300000000n + occupiedCKBAmnt, //1003
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 130n * 10n ** 8n * includFeeInPay,
                orderAmount: 130n * 10n ** 8n * askPrice / 10n**10n, 
                price: askPrice,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 3.2: ~~");
            await createPendingOrder(aliceOrder, bobOrder, false);
        });

        it('case4.1: same block - bid 1 - ask 2 - order amount all matched', async() => {
            let bidPrice1 = 10n * 10n ** 10n;
            let askPrice1 = 10n * 10n ** 10n;

            const aliceOrder1 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 220n * 10n ** 8n,
                price: bidPrice1,
                isBid: true,
                ckbAmount: 220660000000n + occupiedCKBAmnt, //2206.6
            };
            const bobOrder1 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 120n * 10n ** 8n * includFeeInPay,
                orderAmount: 120n * 10n ** 8n * askPrice1 / 10n**10n, 
                price: askPrice1,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            let bidPrice2 = 9n * 10n ** 10n;
            let askPrice2 = 100000000000n; // 10

            const aliceOrder2 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 66n * 10n ** 8n,
                price: bidPrice2,
                isBid: true,
                ckbAmount: 66n * 10n ** 8n * bidPrice2 / 10n ** 10n + occupiedCKBAmnt,
            };
            const bobOrder2 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 100n * 10n ** 8n * includFeeInPay,
                orderAmount: 100n * 10n ** 8n * askPrice2 / 10n ** 10n, 
                price: askPrice2,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 4.1: ~~");
            await createPendingOrderInSameBlock([aliceOrder1, aliceOrder2],[bobOrder1, bobOrder2]);
        });
        
        it('case4.2: diff block - ask earlier - bid 1 - ask 2 - order amount all matched', async() => {
            let bidPrice1 = 10n * 10n ** 10n;
            let askPrice1 = 9n * 10n ** 10n;

            const aliceOrder1 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 220n * 10n ** 8n,
                price: bidPrice1,
                isBid: true,
                ckbAmount: 220660000000n + occupiedCKBAmnt, //2206.6
            };
            const bobOrder1 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 120n * 10n ** 8n * includFeeInPay,
                orderAmount: 120n * 10n ** 8n * askPrice1 / 10n ** 10n, 
                price: askPrice1,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            let bidPrice2 = 9n * 10n ** 10n;
            let askPrice2 = 95000000000n; // 9.5

            const aliceOrder2 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 66n * 10n ** 8n,
                price: bidPrice2,
                isBid: true,
                ckbAmount: 66n * 10n ** 8n * includFeeInPay * bidPrice2 / 10n ** 10n + occupiedCKBAmnt,
            };
            const bobOrder2 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 100n * 10n ** 8n * includFeeInPay,
                orderAmount: 100n * 10n ** 8n * askPrice2 / 10n ** 10n, 
                price: askPrice2,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 4.2: ~~");
            bobRawTx1 = await generateCreateOrderTx(bobOrder1, 0);
            const bobTxHash1 = await sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx1));

            bobRawTx2 = await generateCreateOrderTx(bobOrder2, 0);
            const bobTxHash2 = await sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx2));

            const sameBlockAliceTxHashList = await createPendingOrderInSameBlock([aliceOrder1, aliceOrder2]);
            logCellsInfo(sameBlockAliceTxHashList.aliceTxHashList[0], bobTxHash1);
            logCellsInfo(sameBlockAliceTxHashList.aliceTxHashList[0], bobTxHash2);
        });

        it('case5.1: same block - bid 1 - ask 2 - order amount partial dealt & bid remaining', async() => {
            let bidPrice1 = 10n * 10n ** 10n;
            let askPrice1 = 9n * 10n ** 10n;

            const aliceOrder1 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 230n * 10n ** 8n,
                price: bidPrice1,
                isBid: true,
                ckbAmount: 230n * 10n ** 8n * bidPrice1/10n**10n * includFeeInPay + occupiedCKBAmnt,
            };
            const bobOrder1 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 120n * 10n ** 8n * includFeeInPay,
                orderAmount: 120n * 10n ** 8n * askPrice1 / 10n**10n, 
                price: askPrice1,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            let bidPrice2 = 9n * 10n ** 10n;
            let askPrice2 = 95000000000n; // 9.5

            const aliceOrder2 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 66n * 10n ** 8n,
                price: bidPrice2,
                isBid: true,
                ckbAmount: 66n * 10n ** 8n * includFeeInPay * bidPrice2 / 10n ** 10n + occupiedCKBAmnt,
            };
            const bobOrder2 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 100n * 10n ** 8n * includFeeInPay,
                orderAmount: 100n * 10n ** 8n * askPrice2 / 10n ** 10n, 
                price: askPrice2,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 5.1: ~~");
            await createPendingOrderInSameBlock([aliceOrder1, aliceOrder2],[bobOrder1, bobOrder2]);
        });

        it('case5.2: diff block - ask earlier - bid 1 - ask 2 - order amount partial dealt & bid remaining', async() => {
            let bidPrice1 = 10n * 10n ** 10n;
            let askPrice1 = 9n * 10n ** 10n;

            const aliceOrder1 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 230n * 10n ** 8n,
                price: bidPrice1,
                isBid: true,
                ckbAmount: 230n * 10n ** 8n * bidPrice1/10n**10n * includFeeInPay + occupiedCKBAmnt,
            };
            const bobOrder1 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 120n * 10n ** 8n * includFeeInPay,
                orderAmount: 120n * 10n ** 8n * askPrice1 / 10n**10n, 
                price: askPrice1,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            let bidPrice2 = 9n * 10n ** 10n;
            let askPrice2 = 95000000000n; // 9.5

            const aliceOrder2 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 66n * 10n ** 8n,
                price: bidPrice2,
                isBid: true,
                ckbAmount: 66n * 10n ** 8n * includFeeInPay * bidPrice2 / 10n ** 10n + occupiedCKBAmnt,
            };
            const bobOrder2 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 100n * 10n ** 8n * includFeeInPay,
                orderAmount: 100n * 10n ** 8n * askPrice2 / 10n ** 10n, 
                price: askPrice2,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 5.2: ~~");
            bobRawTx1 = await generateCreateOrderTx(bobOrder1, 0);
            const bobTxHash1 = await sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx1));

            bobRawTx2 = await generateCreateOrderTx(bobOrder2, 0);
            const bobTxHash2 = await sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx2));

            const sameBlockAliceTxHashList = await createPendingOrderInSameBlock([aliceOrder1, aliceOrder2]);
            logCellsInfo(sameBlockAliceTxHashList.aliceTxHashList[0], bobTxHash1);
            logCellsInfo(sameBlockAliceTxHashList.aliceTxHashList[0], bobTxHash2);
        });

        it('case6.1: same block - bid 1 - ask 2 - order amount partial dealt & ask remaining', async() => {
            let bidPrice1 = 10n * 10n ** 10n;
            let askPrice1 = 9n * 10n ** 10n;

            const aliceOrder1 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 220n * 10n ** 8n,
                price: bidPrice1,
                isBid: true,
                ckbAmount: 220n * 10n ** 8n * includFeeInPay * bidPrice1/10n**10n + occupiedCKBAmnt,
            };
            const bobOrder1 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 120n * 10n ** 8n * includFeeInPay,
                orderAmount: 120n * 10n ** 8n * askPrice1 / 10n**10n, 
                price: askPrice1,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            let bidPrice2 = 9n * 10n ** 10n;
            let askPrice2 = 95000000000n; // 9.5

            const aliceOrder2 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 66n * 10n ** 8n,
                price: bidPrice2,
                isBid: true,
                ckbAmount: 66n * 10n ** 8n * includFeeInPay * bidPrice2 / 10n ** 10n + occupiedCKBAmnt,
            };
            const bobOrder2 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 130n * 10n ** 8n * includFeeInPay,
                orderAmount: 130n * 10n ** 8n * askPrice2 / 10n ** 10n, 
                price: askPrice2,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 6.1: ~~");
            await createPendingOrderInSameBlock([aliceOrder1, aliceOrder2],[bobOrder1, bobOrder2]);
        });

        it('case6.2: diff block - ask earlier - bid 1 - ask 2 - order amount partial dealt & ask remaining', async() => {
            let bidPrice1 = 10n * 10n ** 10n;
            let askPrice1 = 9n * 10n ** 10n;

            const aliceOrder1 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 220n * 10n ** 8n,
                price: bidPrice1,
                isBid: true,
                ckbAmount: 220n * 10n ** 8n * includFeeInPay * bidPrice1/10n**10n + occupiedCKBAmnt,
            };
            const bobOrder1 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 120n * 10n ** 8n * includFeeInPay,
                orderAmount: 120n * 10n ** 8n * askPrice1 / 10n**10n, 
                price: askPrice1,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            let bidPrice2 = 9n * 10n ** 10n;
            let askPrice2 = 95000000000n; // 9.5

            const aliceOrder2 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 66n * 10n ** 8n,
                price: bidPrice2,
                isBid: true,
                ckbAmount: 66n * 10n ** 8n * includFeeInPay * bidPrice2 / 10n ** 10n + occupiedCKBAmnt,
            };
            const bobOrder2 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 130n * 10n ** 8n * includFeeInPay,
                orderAmount: 130n * 10n ** 8n * askPrice2 / 10n ** 10n, 
                price: askPrice2,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 6.2: ~~");
            bobRawTx1 = await generateCreateOrderTx(bobOrder1, 0);
            const bobTxHash1 = await sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx1));

            bobRawTx2 = await generateCreateOrderTx(bobOrder2, 0);
            const bobTxHash2 = await sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx2));

            const sameBlockAliceTxHashList = await createPendingOrderInSameBlock([aliceOrder1, aliceOrder2]);
            logCellsInfo(sameBlockAliceTxHashList.aliceTxHashList[0], bobTxHash1);
            logCellsInfo(sameBlockAliceTxHashList.aliceTxHashList[0], bobTxHash2);
        });

        it('case7.1: same block - bid 2 - ask 1 - order amount all matched', async() => {
            let bidPrice1 = 10n * 10n ** 10n;
            let askPrice1 = 9n * 10n ** 10n;

            const aliceOrder1 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 220n * 10n ** 8n,
                price: bidPrice1,
                isBid: true,
                ckbAmount: 220n * 10n ** 8n * includFeeInPay * bidPrice1/10n**10n + occupiedCKBAmnt,
            };
            const bobOrder1 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 286n * 10n ** 8n * includFeeInPay,
                orderAmount: 286n * 10n ** 8n * askPrice1 / 10n**10n, 
                price: askPrice1,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            let bidPrice2 = 97000000000n; // 9.7
            let askPrice2 = 95000000000n; // 9.5

            const aliceOrder2 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 66n * 10n ** 8n,
                price: bidPrice2,
                isBid: true,
                ckbAmount: 66n * 10n ** 8n * includFeeInPay * bidPrice2 / 10n ** 10n + occupiedCKBAmnt,
            };
            const bobOrder2 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 130n * 10n ** 8n * includFeeInPay,
                orderAmount: 130n * 10n ** 8n * askPrice2 / 10n ** 10n, 
                price: askPrice2,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 7.1: ~~");
            await createPendingOrderInSameBlock([aliceOrder1, aliceOrder2],[bobOrder1, bobOrder2]);
        });

        it('case7.2: diff block - bid&ask earlier in turn - bid 2 - ask 1 - order amount all matched', async() => {
            let bidPrice1 = 10n * 10n ** 10n;
            let askPrice1 = 9n * 10n ** 10n;

            const aliceOrder1 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 220n * 10n ** 8n,
                price: bidPrice1,
                isBid: true,
                ckbAmount: 220n * 10n ** 8n * includFeeInPay * bidPrice1/10n**10n + occupiedCKBAmnt,
            };
            const bobOrder1 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 286n * 10n ** 8n * includFeeInPay,
                orderAmount: 286n * 10n ** 8n * askPrice1 / 10n**10n, 
                price: askPrice1,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            let bidPrice2 = 97000000000n; // 9.7
            let askPrice2 = 95000000000n; // 9.5

            const aliceOrder2 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 66n * 10n ** 8n,
                price: bidPrice2,
                isBid: true,
                ckbAmount: 66n * 10n ** 8n * includFeeInPay * bidPrice2 / 10n ** 10n + occupiedCKBAmnt,
            };
            const bobOrder2 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 130n * 10n ** 8n * includFeeInPay,
                orderAmount: 130n * 10n ** 8n * askPrice2 / 10n ** 10n, 
                price: askPrice2,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 7.2: ~~");
            aliceRawTx2 = await generateCreateOrderTx(aliceOrder2, 0);
            const aliceTxHash2 = await sendTransaction(ckb.signTransaction(alicePrivateKey)(aliceRawTx2));

            bobRawTx1 = await generateCreateOrderTx(bobOrder1, 0);
            const bobTxHash1 = await sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx1));

            const sameBlockAliceTxHashList = await createPendingOrderInSameBlock([aliceOrder1],[bobOrder2]);
            logCellsInfo(sameBlockAliceTxHashList.aliceTxHashList[0], bobTxHash1);
            logCellsInfo(aliceTxHash2, sameBlockAliceTxHashList.bobTxHashList[0]);
        });

        it('case8.1: same block - bid 2 - ask 1 - order amount partial dealt & bid remaining', async() => {
            let bidPrice1 = 10n * 10n ** 10n;
            let askPrice1 = 9n * 10n ** 10n;

            const aliceOrder1 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 230n * 10n ** 8n,
                price: bidPrice1,
                isBid: true,
                ckbAmount: 230n * 10n ** 8n * includFeeInPay * bidPrice1/10n**10n + occupiedCKBAmnt,
            };
            const bobOrder1 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 286n * 10n ** 8n * includFeeInPay,
                orderAmount: 286n * 10n ** 8n * askPrice1 / 10n**10n, 
                price: askPrice1,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            let bidPrice2 = 97000000000n; // 9.7
            let askPrice2 = 95000000000n; // 9.5

            const aliceOrder2 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 66n * 10n ** 8n,
                price: bidPrice2,
                isBid: true,
                ckbAmount: 66n * 10n ** 8n * includFeeInPay * bidPrice2 / 10n ** 10n + occupiedCKBAmnt,
            };
            const bobOrder2 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 130n * 10n ** 8n * includFeeInPay,
                orderAmount: 130n * 10n ** 8n * askPrice2 / 10n ** 10n, 
                price: askPrice2,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 8.1: ~~");
            await createPendingOrderInSameBlock([aliceOrder1, aliceOrder2],[bobOrder1, bobOrder2]);
        });

        it('case8.2: diff block - bid&ask earlier in turn - bid 2 - ask 1 - order amount partial dealt & bid remaining', async() => {
            let bidPrice1 = 10n * 10n ** 10n;
            let askPrice1 = 9n * 10n ** 10n;

            const aliceOrder1 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 230n * 10n ** 8n,
                price: bidPrice1,
                isBid: true,
                ckbAmount: 230n * 10n ** 8n * includFeeInPay * bidPrice1/10n**10n + occupiedCKBAmnt,
            };
            const bobOrder1 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 286n * 10n ** 8n * includFeeInPay,
                orderAmount: 286n * 10n ** 8n * askPrice1 / 10n**10n, 
                price: askPrice1,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            let bidPrice2 = 97000000000n; // 9.7
            let askPrice2 = 95000000000n; // 9.5

            const aliceOrder2 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 66n * 10n ** 8n,
                price: bidPrice2,
                isBid: true,
                ckbAmount: 66n * 10n ** 8n * includFeeInPay * bidPrice2 / 10n ** 10n + occupiedCKBAmnt,
            };
            const bobOrder2 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 130n * 10n ** 8n * includFeeInPay,
                orderAmount: 130n * 10n ** 8n * askPrice2 / 10n ** 10n, 
                price: askPrice2,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 8.2: ~~");
            aliceRawTx2 = await generateCreateOrderTx(aliceOrder2, 0);
            const aliceTxHash2 = await sendTransaction(ckb.signTransaction(alicePrivateKey)(aliceRawTx2));

            bobRawTx1 = await generateCreateOrderTx(bobOrder1, 0);
            const bobTxHash1 = await sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx1));

            const sameBlockAliceTxHashList = await createPendingOrderInSameBlock([aliceOrder1],[bobOrder2]);
            logCellsInfo(sameBlockAliceTxHashList.aliceTxHashList[0], bobTxHash1);
            logCellsInfo(aliceTxHash2, sameBlockAliceTxHashList.bobTxHashList[0]);
        });

        it('case9.1: same block - bid 2 - ask 1 - order amount partial dealt & ask remaining', async() => {
            let bidPrice1 = 10n * 10n ** 10n;
            let askPrice1 = 9n * 10n ** 10n;

            const aliceOrder1 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 120n * 10n ** 8n,
                price: bidPrice1,
                isBid: true,
                ckbAmount: 120n * 10n ** 8n * includFeeInPay * bidPrice1/10n**10n + occupiedCKBAmnt,
            };
            const bobOrder1 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 286n * 10n ** 8n * includFeeInPay,
                orderAmount: 286n * 10n ** 8n * askPrice1 / 10n**10n, 
                price: askPrice1,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            let bidPrice2 = 97000000000n; // 9.7
            let askPrice2 = 95000000000n; // 9.5

            const aliceOrder2 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 10n * 10n ** 8n,
                price: bidPrice2,
                isBid: true,
                ckbAmount: 10n * 10n ** 8n * includFeeInPay * bidPrice2 / 10n ** 10n + occupiedCKBAmnt,
            };
            const bobOrder2 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 130n * 10n ** 8n * includFeeInPay,
                orderAmount: 130n * 10n ** 8n * askPrice2 / 10n ** 10n, 
                price: askPrice2,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 9.1: ~~");
            await createPendingOrderInSameBlock([aliceOrder1, aliceOrder2],[bobOrder1, bobOrder2]);
        });

        it('case9.2: diff block - bid&ask earlier in turn - bid 2 - ask 1 - order amount partial dealt & ask remaining', async() => {
            let bidPrice1 = 10n * 10n ** 10n;
            let askPrice1 = 9n * 10n ** 10n;

            const aliceOrder1 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 120n * 10n ** 8n,
                price: bidPrice1,
                isBid: true,
                ckbAmount: 120n * 10n ** 8n * includFeeInPay * bidPrice1/10n**10n + occupiedCKBAmnt,
            };
            const bobOrder1 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 286n * 10n ** 8n * includFeeInPay,
                orderAmount: 286n * 10n ** 8n * askPrice1 / 10n**10n, 
                price: askPrice1,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            let bidPrice2 = 97000000000n; // 9.7
            let askPrice2 = 95000000000n; // 9.5

            const aliceOrder2 = {
                publicKeyHash: alicePublicKeyHash,
                sudtCurrentAmount: 0n,
                orderAmount: 10n * 10n ** 8n,
                price: bidPrice2,
                isBid: true,
                ckbAmount: 10n * 10n ** 8n * includFeeInPay * bidPrice2 / 10n ** 10n + occupiedCKBAmnt,
            };
            const bobOrder2 = {
                publicKeyHash: bobPublicKeyHash,
                sudtCurrentAmount: 130n * 10n ** 8n * includFeeInPay,
                orderAmount: 130n * 10n ** 8n * askPrice2 / 10n ** 10n, 
                price: askPrice2,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 9.2: ~~");
            aliceRawTx2 = await generateCreateOrderTx(aliceOrder2, 0);
            const aliceTxHash2 = await sendTransaction(ckb.signTransaction(alicePrivateKey)(aliceRawTx2));

            bobRawTx1 = await generateCreateOrderTx(bobOrder1, 0);
            const bobTxHash1 = await sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx1));

            const sameBlockAliceTxHashList = await createPendingOrderInSameBlock([aliceOrder1],[bobOrder2]);
            logCellsInfo(sameBlockAliceTxHashList.aliceTxHashList[0], bobTxHash1);
            logCellsInfo(aliceTxHash2, sameBlockAliceTxHashList.bobTxHashList[0]);
        });

    });
});