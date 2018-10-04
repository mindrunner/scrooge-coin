import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TxHandler {

    private UTXOPool utxoPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    private Transaction.Output getOutputForInput(Transaction.Input input) {
        return utxoPool.getTxOutput(new UTXO(input.prevTxHash, input.outputIndex));
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     * values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        if (!checkAllOutputsClaimed(tx)) return false;
        if (!checkValidInputOutputSum(tx)) return false;
        if (!checkValidInputSignatures(tx)) return false;
        if (checkNegativeOutput(tx)) return false;
        if (isDoubleSpending(tx)) return false;
        return true;
    }

    private boolean isDoubleSpending(Transaction tx) {
        List<UTXO> utxos = new ArrayList<>();

        for(Transaction.Input input : tx.getInputs()) {
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            if(utxos.contains(utxo)) return true;
            utxos.add(utxo);
        }
        return false;
    }

    private boolean checkNegativeOutput(Transaction tx) {
        for (Transaction.Output o : tx.getOutputs()) {
            if (o.value < 0.0) return true;
        }
        return false;
    }

    private boolean checkValidInputSignatures(Transaction tx) {
        for (int i = 0; i < tx.getInputs().size(); ++i) {
            Transaction.Input input = tx.getInput(i);
            Transaction.Output output = getOutputForInput(input);
            if (null == output) return false;
            PublicKey pubKey = output.address;
            byte[] rawData = tx.getRawDataToSign(i);
            byte[] signature = input.signature;
            if (!Crypto.verifySignature(pubKey, rawData, signature)) {
                return false;
            }
        }
        return true;
    }

    private boolean checkValidInputOutputSum(Transaction tx) {
        double sumInput = 0.0;
        double sumOutput = 0.0;
        for (Transaction.Input i : tx.getInputs()) {
            Transaction.Output output = getOutputForInput(i);
            if(null == output) return false;
            sumInput += output.value;
        }
        for (Transaction.Output o : tx.getOutputs()) {
            sumOutput += o.value;
        }
        return (sumInput >= sumOutput);
    }

    private boolean checkAllOutputsClaimed(Transaction tx) {
        for (UTXO utxo : utxoPool.getAllUTXO()) {
            if (null == utxoPool.getTxOutput(utxo)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        List<Transaction> validTxs = new ArrayList<>();
        for (Transaction t : possibleTxs) {
            if (isValidTx(t)) {
                validTxs.add(t);
                int index = 0;
                for (Transaction.Output o : t.getOutputs()) {
                    utxoPool.addUTXO(new UTXO(t.getHash(), index), o);
                    ++index;
                }
                for (Transaction.Input i : t.getInputs()) {
                    utxoPool.removeUTXO(new UTXO(i.prevTxHash, i.outputIndex));
                }
            }
        }
        return validTxs.toArray(new Transaction[0]);
    }
}
