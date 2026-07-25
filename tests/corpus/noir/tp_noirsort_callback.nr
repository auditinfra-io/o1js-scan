// @recall-rule NOIR_UNCONSTRAINED_WITNESS
// @recall-min-severity high
//
// MUTATION of fp_noirsort_callback.nr: the ONLY change is deleting the
// `sortfn_assert(...)` loop. Nothing then constrains the ordering of `sorted`,
// so a prover may return any permutation (or any array at all).
pub fn sort_advanced<T, let N: u32>(
    input: [T; N],
    sortfn: unconstrained fn(T, T) -> bool,
    sortfn_assert: fn(T, T) -> (),
) -> SortResult<T, N>
where
    T: std::cmp::Eq,
{
    // Safety: validated using check_shuffle. See its documentation for more info.
    let sorted = unsafe { quicksort_explicit(input, sortfn) };

    let sort_indices = get_shuffle_indices(input, sorted);

    SortResult { sorted, sort_indices }
}
