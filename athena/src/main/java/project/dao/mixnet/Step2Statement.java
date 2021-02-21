package project.dao.mixnet;

import java.util.List;

public class Step2Statement  {
    private final List<Integer> permutation;
    private final List<MixBallot> permutedBallots;

    public Step2Statement(List<Integer> permutation, List<MixBallot> permutedBallots) {
        this.permutation = permutation;
        this.permutedBallots = permutedBallots;
    }

    public List<Integer> getPermutation() {
        return permutation;
    }

    public List<MixBallot> getPermutedBallots() {
        return permutedBallots;
    }
    
}
