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
    const occupiedCKBAmnt = 168n * 10n ** 8n; // occupied 167, plus 1 more

    const ckb = getCKBSDK();
    const privateKey = '0x01829817e4dead9ec93822574313c74eab20e308e4c9af476f28515aea4f8a2f';
    const publicKey = ckb.utils.privateKeyToPublicKey(privateKey);
    const rootPublicKeyHash = `0x${ckb.utils.blake160(publicKey, 'hex')}`;

    const alicePrivateKey = '0x650f2b74920bc2a3e5e33e5909cac206e38fc5fe8cb8b1596bf631a60057ff0e';
    const alicePublicKey = ckb.utils.privateKeyToPublicKey(alicePrivateKey);
    const alicePublicKeyHash = `0x${ckb.utils.blake160(alicePublicKey, 'hex')}`;

    const bobPrivateKey = '0x41f44f049b66b2d095d2c66a04b11b518feb6947b999e2b3d2fc2725e891e273';
    const bobPublicKey = ckb.utils.privateKeyToPublicKey(bobPrivateKey);
    const bobPublicKeyHash = `0x${ckb.utils.blake160(bobPublicKey, 'hex')}`;

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
    });

    describe('deploy sudt and order lock', () => {
        let typeIdScript;
        let udtScriptDataHex;
        let orderLockScriptDataHex;
        let orderLockCodeHash;
        // let secp256k1SignAllScriptDataHex;

        let sudtType;

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
                args: alicePublicKeyHash,
            };
            const bobOrderLock = {
                codeHash: orderLockCodeHash,
                hashType: 'data',
                args: bobPublicKeyHash,
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
            currentAmount,
            orderAmount,
            price,
            isBid,
            ckbAmount,
        }, index) => {
            const cells = await indexer.collectCells({
                lock: { ...defaultLockScript, args: publicKeyHash },
            });

            const orderLock = {
                codeHash: orderLockCodeHash,
                hashType: 'data',
                args: publicKeyHash,
            };

            const inputs = [cells[index]];

            const changeOutput = {
                ckbAmount: BigInt(cells[index].capacity) - ckbAmount - 10n ** 8n,
                type: sudtType,
                lock: { ...defaultLockScript, args: publicKeyHash },
                data: BufferParser.writeBigUInt128LE(BufferParser.parseAmountFromSUDTData(cells[index].data) - currentAmount),
            };
            const outputs = [
                {
                    ckbAmount,
                    type: sudtType,
                    lock: orderLock,
                    data: formatOrderData(currentAmount, orderAmount, price, isBid),
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
            let sudtType;
            uuid = ckb.utils.scriptToHash(defaultLockScript);
            sudtType = {
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
                    ckb: 20000n,
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
                const aliceRawTx = await generateCreateOrderTx(aliceOrder[i], i);
                const bobRawTx = await generateCreateOrderTx(bobOrder[i], i);   
                
                const aliceTxHash = await ckb.rpc.sendTransaction(ckb.signTransaction(alicePrivateKey)(aliceRawTx));
                const bobTxHash = await ckb.rpc.sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx));

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
            const getTx = await ckb.rpc.getTransaction(txHash);
            const blockHash = getTx.txStatus.blockHash;
            const getBlockInfo = await ckb.rpc.getBlock(blockHash);
            const blockNum = getBlockInfo.header.number;
            return parseInt(blockNum, 16);
        }

        const createPendingOrder = async (aliceOrder, bobOrder) => {
            const aliceRawTx = await generateCreateOrderTx(aliceOrder, 0);
            const aliceTxHash = await sendTransaction(ckb.signTransaction(alicePrivateKey)(aliceRawTx));

            const bobRawTx = await generateCreateOrderTx(bobOrder, 0);
            const bobTxHash = await sendTransaction(ckb.signTransaction(bobPrivateKey)(bobRawTx));

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
            
            console.log("aliceOrderCell.capacity: ", formatCKB(BigInt(aliceOrderCell.capacity))); 
            console.log("aliceOrderCell.data is: ", aliceOrderCell.data);
            console.log("OrderData(aliceOrderCell.data).sUDTAmount: %d, orderAmount: %d, price: %d, isBid: %d", 
            formatCKB(parseOrderData(aliceOrderCell.data).sUDTAmount), formatCKB(parseOrderData(aliceOrderCell.data).orderAmount),
                Number(parseOrderData(aliceOrderCell.data).price)/10**10, Number(parseOrderData(aliceOrderCell.data).isBid)); 
            
            console.log("bobOrderCell.capacity: ", formatCKB(BigInt(bobOrderCell.capacity)));
            console.log("bobOrderCell.data is: ", bobOrderCell.data); 
            console.log("OrderData(bobOrderCell.data).sUDTAmount: %d, orderAmount: %d, price: %d, isBid: %d", 
            formatCKB(parseOrderData(bobOrderCell.data).sUDTAmount), formatCKB(parseOrderData(bobOrderCell.data).orderAmount),
                Number(parseOrderData(bobOrderCell.data).price)/10**10, Number(parseOrderData(bobOrderCell.data).isBid)); 
        };

        it('case 0.1: create order cells with exact match price', async() => {
            let bidPrice = 50000000000n;
            let askPrice = bidPrice;

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                currentAmount: 5000000000n,
                orderAmount: 15000000000n,
                price: bidPrice,
                isBid: true,
                ckbAmount: 2000n * 10n ** 8n,
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                currentAmount: 50000000000n,
                orderAmount: 100000000000n,
                price: askPrice,
                isBid: false,
                ckbAmount: 800n * 10n ** 8n,
            };

            console.log("~~ case 0.1: exact ~~");
            await createPendingOrder(aliceOrder,bobOrder);
        });

        it('case 0.2: create order cells with gap price', async() => {
            let bidPrice = 50000000000n;
            let askPrice = 60000000000n;

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                currentAmount: 5000000000n,
                orderAmount: 15000000000n,
                price: bidPrice,
                isBid: true,
                ckbAmount: 2000n * 10n ** 8n,
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                currentAmount: 50000000000n,
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
                currentAmount: 5000000000n,
                orderAmount: 15000000000n,
                price: bidPrice,
                isBid: true,
                ckbAmount: 2000n * 10n ** 8n,
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                currentAmount: 50000000000n,
                orderAmount: 100000000000n,
                price: askPrice,
                isBid: false,
                ckbAmount: 800n * 10n ** 8n,
            };

            console.log("~~ case 0.3: overlap1 ~~");
            await createPendingOrder(aliceOrder,bobOrder);
        });

        it('case1.1: same block - bid 1 - ask 1 - order amount all matched', async() => {
            let bidPrice = 10n * 10n ** 10n;
            let askPrice = 9n * 10n ** 10n;

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                currentAmount: 0n,
                orderAmount: 100n * 10n ** 8n,
                price: bidPrice,
                isBid: true,
                ckbAmount: 100300000000n + occupiedCKBAmnt, //1003
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                currentAmount: 100n * 10n ** 8n,
                orderAmount: 100n * 10n ** 8n,
                price: askPrice,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 1.1: ~~");
            await createPendingOrderInSameBlock([aliceOrder],[bobOrder]);
        });

        it('case1.2: diff block - bid 1 - ask 1 - order amount all matched', async() => {
            let bidPrice = 10n * 10n ** 10n;
            let askPrice = 9n * 10n ** 10n;

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                currentAmount: 0n,
                orderAmount: 100n * 10n ** 8n,
                price: bidPrice,
                isBid: true,
                ckbAmount: 100300000000n + occupiedCKBAmnt, //1003
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                currentAmount: 100n * 10n ** 8n,
                orderAmount: 100n * 10n ** 8n,
                price: askPrice,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 1.2: ~~");
            await createPendingOrder(aliceOrder,bobOrder);
        });

        it('case2.2: diff block - bid 1 - ask 1 - order amount partial dealt & bid remaining', async() => {
            let bidPrice = 10n * 10n ** 10n; //10
            let askPrice = 9n * 10n ** 10n; //9

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                currentAmount: 0n,
                orderAmount: 120n * 10n ** 8n,
                price: bidPrice,
                isBid: true,
                ckbAmount: 120360000000n + occupiedCKBAmnt, //1203.6
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                currentAmount: 100n * 10n ** 8n,
                orderAmount: 100n * 10n ** 8n,
                price: askPrice,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 2.2: ~~");
            await createPendingOrder(aliceOrder,bobOrder);
        });

        it('case3.2: diff block - bid 1 - ask 1 - order amount partial dealt & bid remaining', async() => {
            let bidPrice = 10n * 10n ** 10n;
            let askPrice = 9n * 10n ** 10n;

            const aliceOrder = {
                publicKeyHash: alicePublicKeyHash,
                currentAmount: 0n,
                orderAmount: 100n * 10n ** 8n, 
                price: bidPrice,
                isBid: true,
                ckbAmount: 100300000000n + occupiedCKBAmnt, //1003
            };
            const bobOrder = {
                publicKeyHash: bobPublicKeyHash,
                currentAmount: 13039000000n, //130.39
                orderAmount: 130n * 10n ** 8n, 
                price: askPrice,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 3.2: ~~");
            await createPendingOrder(aliceOrder,bobOrder);
        });

        it('case4.1: same block - bid 1 - ask 2 - order amount all matched', async() => {
            let bidPrice1 = 10n * 10n ** 10n;
            let askPrice1 = 9n * 10n ** 10n;

            const aliceOrder1 = {
                publicKeyHash: alicePublicKeyHash,
                currentAmount: 0n,
                orderAmount: 220n * 10n ** 8n,
                price: bidPrice1,
                isBid: true,
                ckbAmount: 220660000000n + occupiedCKBAmnt, //2206.6
            };
            const bobOrder1 = {
                publicKeyHash: bobPublicKeyHash,
                currentAmount: 120n * 10n ** 8n,
                orderAmount: 120n * 10n ** 8n,
                price: askPrice1,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            let bidPrice2 = 9n * 10n ** 10n;
            let askPrice2 = 95000000000n; // 9.5

            const aliceOrder2 = {
                publicKeyHash: alicePublicKeyHash,
                currentAmount: 0n,
                orderAmount: 66n * 10n ** 8n,
                price: bidPrice2,
                isBid: true,
                ckbAmount: 66n * 9n + occupiedCKBAmnt,
            };
            const bobOrder2 = {
                publicKeyHash: bobPublicKeyHash,
                currentAmount: 100n * 10n ** 8n,
                orderAmount: 100n * 10n ** 8n,
                price: askPrice2,
                isBid: false,
                ckbAmount: occupiedCKBAmnt,
            };

            console.log("~~ case 4.1: ~~");
            await createPendingOrderInSameBlock([aliceOrder1, aliceOrder2],[bobOrder1, bobOrder2]);
        });
        
    });
});