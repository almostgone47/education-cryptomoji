'use strict';

const { createHash } = require('crypto');
const signing = require('./signing');
const sha256 = require('sha256');
/**
 * A simple validation function for transactions. Accepts a transaction
 * and returns true or false. It should reject transactions that:
 *   - have negative amounts
 *   - were improperly signed
 *   - have been modified since signing
 */
const isValidTransaction = transaction => {
  if (transaction.amount < 0) {
    return false;
  }

  const data = transaction.source + transaction.recipient + transaction.amount;

  return signing.verify(transaction.source, data, transaction.signature);
};

/**
 * Validation function for blocks. Accepts a block and returns true or false.
 * It should reject blocks if:
 *   - their hash or any other properties were altered
 *   - they contain any invalid transactions
 */
const isValidBlock = block => {
  const transactionString = block.transactions.map(tx => tx.signature).join('');
  const data = transactionString + block.previousHash + block.nonce;

  if (block.hash !== sha256(data)) {
    return false;
  }
  return block.transactions.every(isValidTransaction);
};

/**
 * One more validation function. Accepts a blockchain, and returns true
 * or false. It should reject any blockchain that:
 *   - is a missing genesis block
 *   - has any block besides genesis with a null hash
 *   - has any block besides genesis with a previousHash that does not match
 *     the previous hash
 *   - contains any invalid blocks
 *   - contains any invalid transactions
 */
const isValidChain = blockchain => {
  const { blocks } = blockchain;

  if (blocks[0].previousHash !== null) {
    return false;
  }

  for (let i = 0; i < blocks.length; i++) {
    if (!isValidBlock(blocks[i])) {
      return false;
    }

    if (i !== 0 && blocks[i].previousHash !== blocks[i - 1].hash) {
      return false;
    }

    blocks[i].transactions.map(block => {
      if (isValidTransaction(block)) {
        return false;
      }
    });
  }
  return true;
};

/**
 * This last one is just for fun. Become a hacker and tamper with the passed in
 * blockchain, mutating it for your own nefarious purposes. This should
 * (in theory) make the blockchain fail later validation checks;
 */
const randomNum = maxNum => {
  return Math.floor(Math.random() * maxNum);
};

const breakChain = blockchain => {
  const maxBlocksNum = blockchain.blocks.length;
  const maxTxNum =
    blockchain.blocks[randomNum(maxBlocksNum)].transactions.length;

  blockchain.blocks[randomNum(maxBlocksNum)].transactions[
    randomNum(maxTxNum)
  ] = randomNum(100);
};

module.exports = {
  isValidTransaction,
  isValidBlock,
  isValidChain,
  breakChain,
};
