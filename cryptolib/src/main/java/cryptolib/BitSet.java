//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package cryptolib;

public class BitSet extends java.util.BitSet {
    public static final int DEFAULT_SIZE = 8;
    private static final long serialVersionUID = 1L;
    private final int size;

    public BitSet() {
        super(8);
        this.size = 8;
    }

    public BitSet(int nbits) {
        super(nbits);
        this.size = nbits;
    }

    public BitSet get(int low, int high) {
        BitSet n = new BitSet(high - low);

        for(int i = 0; i < high - low; ++i) {
            n.set(i, this.get(low + i));
        }

        return n;
    }

    public int bitSize() {
        return this.size;
    }
}
