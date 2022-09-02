package datastructures;

import org.javatuples.Quartet;

public class AllocOffset implements Comparable<Object> {
    public Long allocBaseAddress;
    public Long allocSize;
    public Long locOffset;
    public Long locSize;

    public AllocOffset(Long allocBaseAddress, Long allocSize, Long locOffset, Long locSize) {
        this.allocBaseAddress = allocBaseAddress;
        this.allocSize = allocSize;
        this.locOffset = locOffset;
        this.locSize = locSize;
    }

    @Override
    public int hashCode() {
        return (new Quartet<>(this.allocBaseAddress, this.allocSize, this.locOffset, this.locSize)).hashCode();
    }

    @Override
    public boolean equals(Object that) {
        if (this == that) return true;
        if (!(that instanceof AllocOffset)) return false;

        AllocOffset other = (AllocOffset)that;
        return (new Quartet<>(this.allocBaseAddress, this.allocSize, this.locOffset, this.locSize))
            .equals(new Quartet<>(other.allocBaseAddress, other.allocSize, other.locOffset, other.locSize));
    }

    @Override
    public int compareTo(Object that) throws NullPointerException, ClassCastException {
        if (that == null) throw new NullPointerException();
        if (!(that instanceof AllocOffset)) throw new ClassCastException();

        AllocOffset other = (AllocOffset)that;
        return (new Quartet<>(this.allocBaseAddress, this.allocSize, this.locOffset, this.locSize))
            .compareTo(new Quartet<>(other.allocBaseAddress, other.allocSize, other.locOffset, other.locSize));
    }

    @Override
    public String toString() {
        return "{" + Long.toHexString(allocBaseAddress) + ", " + Long.toHexString(allocSize) + ", " + Long.toHexString(locOffset) + "}";
    }
}
